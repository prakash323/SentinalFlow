package com.anomaly.platform.service;

import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.EventProcessingStatus;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.KafkaEvent;
import com.anomaly.platform.repository.EntityProfileRepository;
import com.anomaly.platform.repository.EventRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Focused Phase 1 tests for EventProcessingLedgerService: the component
 * responsible for durable idempotent persistence and observable
 * success/failure recording, independent of the detection pipeline.
 */
@ExtendWith(MockitoExtension.class)
class EventProcessingLedgerServiceTest {

    @Mock
    private EventRepository eventRepository;

    @Mock
    private EntityProfileRepository entityProfileRepository;

    @Mock
    private AuditLogService auditLogService;

    private EventProcessingLedgerService ledger;

    @BeforeEach
    void setUp() {
        ledger = new EventProcessingLedgerService(eventRepository, entityProfileRepository, auditLogService);
    }

    private KafkaEvent kafkaEvent() {
        return new KafkaEvent(
                "EV-1", "USER-1", "LOGIN", "v1",
                OffsetDateTime.now(), "test-source",
                Map.of("ip", "10.10.10.50", "loginSuccess", false)
        );
    }

    @Test
    void persistOrLoad_whenEventAlreadyExists_returnsExisting_andNeverInserts() {

        Event existing = new Event();
        existing.setId(UUID.randomUUID());
        existing.setEventId("EV-1");

        when(eventRepository.findByEventIdWithEntity("EV-1")).thenReturn(Optional.of(existing));

        Event result = ledger.persistOrLoad(kafkaEvent());

        assertThat(result).isSameAs(existing);
        verify(eventRepository, never()).save(any());
        verify(entityProfileRepository, never()).findByEntityId(any());
    }

    @Test
    void persistOrLoad_whenEventIsNew_createsAndSavesIt() {

        when(eventRepository.findByEventIdWithEntity("EV-1")).thenReturn(Optional.empty());

        EntityProfile entity = new EntityProfile();
        entity.setId(UUID.randomUUID());
        entity.setEntityId("USER-1");
        when(entityProfileRepository.findByEntityId("USER-1")).thenReturn(Optional.of(entity));

        ArgumentCaptor<Event> savedCaptor = ArgumentCaptor.forClass(Event.class);
        when(eventRepository.save(any())).thenAnswer(invocation -> {
            Event toSave = invocation.getArgument(0);
            toSave.setId(UUID.randomUUID());
            return toSave;
        });

        Event result = ledger.persistOrLoad(kafkaEvent());

        verify(eventRepository).save(savedCaptor.capture());
        assertThat(savedCaptor.getValue().getEventId()).isEqualTo("EV-1");
        assertThat(savedCaptor.getValue().getEntity()).isSameAs(entity);
        assertThat(result.getId()).isNotNull();
    }

    @Test
    void persistOrLoad_whenEntityMissing_throwsNotFound_andNeverSaves() {

        when(eventRepository.findByEventIdWithEntity("EV-1")).thenReturn(Optional.empty());
        when(entityProfileRepository.findByEntityId("USER-1")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> ledger.persistOrLoad(kafkaEvent()))
                .isInstanceOf(NotFoundException.class);

        verify(eventRepository, never()).save(any());
    }

    @Test
    void markProcessed_setsStatusAndTimestamp() {

        Event event = new Event();
        UUID id = UUID.randomUUID();
        event.setId(id);
        event.setProcessingStatus(EventProcessingStatus.PENDING);

        when(eventRepository.findById(id)).thenReturn(Optional.of(event));
        when(eventRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ledger.markProcessed(id);

        assertThat(event.getProcessingStatus()).isEqualTo(EventProcessingStatus.PROCESSED);
        assertThat(event.getProcessedAt()).isNotNull();
    }

    /*
     * State-transition edge case: FAILED -> PROCESSED via a successful retry.
     *
     * An earlier attempt failed and left an error message + attempt count
     * on the event. Once a later attempt (e.g. a Kafka-level retry, or a
     * manual replay) succeeds, the event must not still look broken: the
     * stale error has to be cleared. The attempt count is intentionally
     * preserved as a historical fact (this event needed 2 tries).
     */
    @Test
    void markProcessed_afterPriorFailure_clearsStaleError_butKeepsAttemptHistory() {

        Event event = new Event();
        UUID id = UUID.randomUUID();
        event.setId(id);
        event.setProcessingStatus(EventProcessingStatus.FAILED);
        event.setProcessingAttempts(2);
        event.setLastProcessingError("simulated transient DB failure");

        when(eventRepository.findById(id)).thenReturn(Optional.of(event));
        when(eventRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ledger.markProcessed(id);

        assertThat(event.getProcessingStatus()).isEqualTo(EventProcessingStatus.PROCESSED);
        assertThat(event.getLastProcessingError()).isNull();
        assertThat(event.getProcessingAttempts()).isEqualTo(2);
        assertThat(event.getProcessedAt()).isNotNull();
    }

    @Test
    void markFailed_incrementsAttempts_recordsError_andWritesAuditLog() {

        Event event = new Event();
        UUID id = UUID.randomUUID();
        event.setId(id);
        event.setProcessingStatus(EventProcessingStatus.PENDING);
        event.setProcessingAttempts(1);

        when(eventRepository.findById(id)).thenReturn(Optional.of(event));
        when(eventRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ledger.markFailed(id, "EV-1", new RuntimeException("boom"));

        assertThat(event.getProcessingStatus()).isEqualTo(EventProcessingStatus.FAILED);
        assertThat(event.getProcessingAttempts()).isEqualTo(2);
        assertThat(event.getLastProcessingError()).isEqualTo("boom");

        verify(auditLogService).log(
                eq("system"),
                eq("EVENT_PROCESSING_FAILED"),
                eq("EVENT"),
                eq(id),
                any(),
                anyMap()
        );
    }

    @Test
    void markFailed_truncatesVeryLongErrorMessages() {

        Event event = new Event();
        UUID id = UUID.randomUUID();
        event.setId(id);

        when(eventRepository.findById(id)).thenReturn(Optional.of(event));
        when(eventRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        String longMessage = "x".repeat(2000);

        ledger.markFailed(id, "EV-1", new RuntimeException(longMessage));

        assertThat(event.getLastProcessingError()).hasSize(1000);
    }

    @Test
    void recordUnresolvableFailure_writesAuditLogWithNullResourceId() {

        ledger.recordUnresolvableFailure("EV-1", "USER-1", new RuntimeException("entity missing"));

        verify(auditLogService).log(
                eq("system"),
                eq("EVENT_PERSIST_FAILED"),
                eq("EVENT"),
                isNull(),
                any(),
                anyMap()
        );
    }
}
