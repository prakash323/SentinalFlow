package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreateReplayRunRequest;
import com.anomaly.platform.dto.ReplayRunResponse;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.ReplayRun;
import com.anomaly.platform.entity.ReplayStatus;
import com.anomaly.platform.kafka.KafkaEvent;
import com.anomaly.platform.ml.MlServiceUnavailableException;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.ReplayRunRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Outcome accounting for admin replay. The transactional behaviour (one
 * event's database failure no longer rolls back the whole run) needs real
 * transactions and was verified on an isolated PostgreSQL stack; this test
 * pins the accounting and guards against the run-wide @Transactional
 * coming back.
 */
@ExtendWith(MockitoExtension.class)
class ReplayRunServiceTest {

    @Mock private ReplayRunRepository replayRunRepository;
    @Mock private EventRepository eventRepository;
    @Mock private EventProcessingService eventProcessingService;
    @Mock private AuditLogService auditLogService;

    private ReplayRunService service;

    /* Snapshot of every run state actually persisted ("STATUS processed=x failed=y [completed]"). */
    private final List<String> persisted = new java.util.ArrayList<>();
    /* Which save() calls (1-based) fail with a database error. */
    private java.util.function.IntPredicate failingSave = n -> false;
    private int saveCalls;

    @BeforeEach
    void setUp() {
        service = new ReplayRunService(replayRunRepository, eventRepository, eventProcessingService, auditLogService);
        // lenient: create_isNotOneRunWideTransaction never calls the service
        org.mockito.Mockito.lenient().when(replayRunRepository.findByRunKey(any())).thenReturn(Optional.empty());
        org.mockito.Mockito.lenient().when(replayRunRepository.save(any())).thenAnswer(inv -> {
            if (failingSave.test(++saveCalls)) {
                throw new org.springframework.dao.DataAccessResourceFailureException("database unavailable");
            }
            ReplayRun run = inv.getArgument(0);
            if (run.getId() == null) {
                run.setId(UUID.randomUUID());
            }
            persisted.add(run.getStatus() + " processed=" + run.getProcessedEvents() + " failed=" + run.getFailedEvents()
                    + (run.getCompletedAt() != null ? " completed" : ""));
            return run;
        });
    }

    private void stored(String... eventIds) {
        EntityProfile entity = new EntityProfile();
        entity.setEntityId("HOST-1");
        for (String id : eventIds) {
            Event e = new Event();
            e.setId(UUID.randomUUID());
            e.setEventId(id);
            e.setEntity(entity);
            e.setEventType("LOGIN");
            e.setEventVersion("v1");
            e.setOccurredAt(OffsetDateTime.parse("2026-10-02T10:00:00Z"));
            e.setSource("rest");
            e.setPayload(Map.of());
            // lenient: a run stopped by a persistence failure never loads the remaining events
            org.mockito.Mockito.lenient().when(eventRepository.findByEventIdWithEntity(id)).thenReturn(Optional.of(e));
        }
    }

    private static org.mockito.ArgumentMatcher<KafkaEvent> event(String id) {
        return e -> e != null && id.equals(e.eventId());
    }

    @Test
    void create_isNotOneRunWideTransaction() throws Exception {

        // A run-wide transaction let one event's database error roll back every
        // other event's results and the run itself (reproduced on PostgreSQL).
        assertThat(ReplayRunService.class
                .getMethod("create", CreateReplayRunRequest.class)
                .isAnnotationPresent(Transactional.class)).isFalse();
    }

    @Test
    void partialFailure_isReportedAccurately_andProgressIsSavedAfterEveryEvent() {

        stored("EV-1", "EV-2", "EV-3");
        when(eventProcessingService.process(argThat(event("EV-1")))).thenReturn(EventProcessingService.Outcome.PROCESSED);
        when(eventProcessingService.process(argThat(event("EV-2")))).thenThrow(new MlServiceUnavailableException("ML down", false, null));
        when(eventProcessingService.process(argThat(event("EV-3")))).thenReturn(EventProcessingService.Outcome.PROCESSED);

        ReplayRunResponse result = service.create(new CreateReplayRunRequest("RUN-1", "test", List.of("EV-1", "EV-2", "EV-3")));

        assertThat(result.status()).isEqualTo(ReplayStatus.FAILED);
        assertThat(result.totalEvents()).isEqualTo(3);
        assertThat(result.processedEvents()).isEqualTo(2);
        assertThat(result.failedEvents()).isEqualTo(1);
        // created + running + one save per event + completed
        verify(replayRunRepository, times(6)).save(any());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditLogService).log(eq("system"), eq("REPLAY_EVENT_FAILED"), eq("REPLAY_RUN"), any(), any(), details.capture());
        assertThat(details.getValue())
                .containsEntry("eventId", "EV-2")
                .containsEntry("errorType", "MlServiceUnavailableException")
                .containsKey("recoveryAction");
        assertThat((String) details.getValue().get("recoveryAction")).contains("FAILED").contains("replay");
    }

    @Test
    void anAlreadyProcessedEvent_countsAsCompleted_andIsAuditedAsSkipped() {

        stored("EV-DONE");
        when(eventProcessingService.process(any())).thenReturn(EventProcessingService.Outcome.ALREADY_PROCESSED);

        ReplayRunResponse result = service.create(new CreateReplayRunRequest("RUN-2", "test", List.of("EV-DONE")));

        assertThat(result.status()).isEqualTo(ReplayStatus.COMPLETED);
        assertThat(result.processedEvents()).isEqualTo(1);
        verify(auditLogService).log(eq("system"), eq("REPLAY_EVENT_SKIPPED"), eq("REPLAY_RUN"), any(), any(),
                argThat(d -> "EV-DONE".equals(d.get("eventId"))));
        verify(auditLogService, never()).log(any(), eq("REPLAY_EVENT_FAILED"), any(), any(), any(), any());
    }

    @Test
    void anEventWithNoStoredRow_isAFailureWhoseRecoveryPointsAtTheDeadLetterTopic() {

        when(eventRepository.findByEventIdWithEntity("EV-KAFKA-ONLY")).thenReturn(Optional.empty());

        ReplayRunResponse result = service.create(new CreateReplayRunRequest("RUN-3", "test", List.of("EV-KAFKA-ONLY")));

        assertThat(result.failedEvents()).isEqualTo(1);
        verify(eventProcessingService, never()).process(any());
        verify(auditLogService).log(eq("system"), eq("REPLAY_EVENT_FAILED"), eq("REPLAY_RUN"), any(), any(),
                argThat(d -> String.valueOf(d.get("recoveryAction")).contains("raw.events.v1.DLT")));
    }

    // ---------------------------------------------------------------
    // Persistence failures mid-run: each event counted once, run closed
    // ---------------------------------------------------------------

    private String lastPersisted() {
        return persisted.get(persisted.size() - 1);
    }

    @Test
    void skipAuditFailure_stopsTheRun_withoutCountingThatEventAsProcessedOrFailed() {

        stored("EV-1", "EV-2", "EV-3");
        when(eventProcessingService.process(argThat(event("EV-1")))).thenReturn(EventProcessingService.Outcome.PROCESSED);
        when(eventProcessingService.process(argThat(event("EV-2")))).thenReturn(EventProcessingService.Outcome.ALREADY_PROCESSED);
        when(auditLogService.log(any(), eq("REPLAY_EVENT_SKIPPED"), any(), any(), any(), any()))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("audit write failed"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        service.create(new CreateReplayRunRequest("RUN-A", "test", List.of("EV-1", "EV-2", "EV-3"))))
                .isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class)
                .hasMessageContaining("audit write failed");

        // closed as FAILED; EV-1 counted, EV-2 (skip not recorded) counted neither way
        assertThat(lastPersisted()).isEqualTo("FAILED processed=1 failed=0 completed");
        verify(eventProcessingService, never()).process(argThat(event("EV-3")));
        verify(auditLogService, never()).log(any(), eq("REPLAY_EVENT_FAILED"), any(), any(), any(), any());
    }

    @Test
    void progressSaveFailure_closesTheRunAsFailed_withTheCompletedEventCountedOnce() {

        stored("EV-1", "EV-2");
        when(eventProcessingService.process(any())).thenReturn(EventProcessingService.Outcome.PROCESSED);
        failingSave = n -> n == 3;   // 1 created, 2 running, 3 progress after EV-1

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        service.create(new CreateReplayRunRequest("RUN-B", "test", List.of("EV-1", "EV-2"))))
                .isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);

        // EV-1 completed (its commit is untouched) and is counted once; the run is not left RUNNING
        assertThat(lastPersisted()).isEqualTo("FAILED processed=1 failed=0 completed");
        verify(eventProcessingService, times(1)).process(any());
        verify(auditLogService, never()).log(any(), eq("REPLAY_EVENT_FAILED"), any(), any(), any(), any());
    }

    @Test
    void failureAuditFailure_countsTheFailedEventOnce_andClosesTheRun() {

        stored("EV-1", "EV-2");
        when(eventProcessingService.process(argThat(event("EV-1"))))
                .thenThrow(new MlServiceUnavailableException("ML down", false, null));
        when(auditLogService.log(any(), eq("REPLAY_EVENT_FAILED"), any(), any(), any(), any()))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("audit write failed"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        service.create(new CreateReplayRunRequest("RUN-C", "test", List.of("EV-1", "EV-2"))))
                .isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);

        assertThat(lastPersisted()).isEqualTo("FAILED processed=0 failed=1 completed");
        verify(eventProcessingService, never()).process(argThat(event("EV-2")));
    }

    @Test
    void finalSaveFailure_isPropagated_andTheRunIsNeverReportedAsCompleted() {

        stored("EV-1");
        when(eventProcessingService.process(any())).thenReturn(EventProcessingService.Outcome.PROCESSED);
        failingSave = n -> n == 4;   // created, running, progress, FINAL

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        service.create(new CreateReplayRunRequest("RUN-D", "test", List.of("EV-1"))))
                .isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);

        // the last state that reached the database is still in progress; COMPLETED was never persisted
        assertThat(lastPersisted()).isEqualTo("RUNNING processed=1 failed=0");
        assertThat(persisted).noneMatch(state -> state.startsWith("COMPLETED"));
    }

    @Test
    void whenClosingTheRunAlsoFails_theOriginalErrorIsPropagated_withTheCloseFailureAttached() {

        stored("EV-1");
        when(eventProcessingService.process(any())).thenReturn(EventProcessingService.Outcome.PROCESSED);
        failingSave = n -> n >= 3;   // the database stays down

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        service.create(new CreateReplayRunRequest("RUN-E", "test", List.of("EV-1"))))
                .isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class)
                .satisfies(e -> assertThat(e.getSuppressed()).hasSize(1));

        assertThat(lastPersisted()).isEqualTo("RUNNING processed=0 failed=0");   // nothing newer could be written
    }
}
