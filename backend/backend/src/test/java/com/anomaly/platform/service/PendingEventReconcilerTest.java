package com.anomaly.platform.service;

import com.anomaly.platform.config.ReconcilerProperties;
import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.exception.PayloadTooLargeException;
import com.anomaly.platform.kafka.EventKafkaProducer;
import com.anomaly.platform.repository.AuditLogRepository;
import com.anomaly.platform.repository.EventRepository;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/*
 * Eligibility itself (which rows claimNextUnpublished returns, and the row
 * locking between concurrent runs) is SQL and was verified against an
 * isolated PostgreSQL - this test covers what the job does with a claim.
 */
@ExtendWith(MockitoExtension.class)
class PendingEventReconcilerTest {

    @Mock private EventRepository eventRepository;
    @Mock private AuditLogRepository auditLogRepository;
    @Mock private AuditLogService auditLogService;
    @Mock private EventKafkaProducer kafkaProducer;
    @Mock private PlatformTransactionManager transactionManager;

    private final ReconcilerProperties props = new ReconcilerProperties();
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");

    private PendingEventReconciler reconciler;

    @BeforeEach
    void setUp() {
        reconciler = new PendingEventReconciler(eventRepository, auditLogRepository, auditLogService, kafkaProducer,
                transactionManager, props, meters, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void transactionsWork() {
        when(transactionManager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
    }

    private Event storedEvent(String eventId) {
        EntityProfile entity = new EntityProfile();
        entity.setEntityId("HOST-1");
        Event e = new Event();
        e.setId(UUID.randomUUID());
        e.setEventId(eventId);
        e.setEntity(entity);
        e.setEventType("LOGIN");
        e.setEventVersion("v1");
        e.setOccurredAt(OffsetDateTime.parse("2026-10-02T11:40:00Z"));
        e.setSource("rest");
        e.setPayload(Map.of("loginSuccess", false));
        return e;
    }

    /** Each claim returns the next event in order, then nothing. */
    private void claimable(Event... events) {
        java.util.Deque<UUID> queue = new java.util.ArrayDeque<>();
        for (Event e : events) {
            // lenient: a run that stops early never loads the remaining events
            org.mockito.Mockito.lenient().when(eventRepository.findById(e.getId())).thenReturn(Optional.of(e));
            queue.add(e.getId());
        }
        when(eventRepository.claimNextUnpublished(any(), any(), any(), anyLong()))
                .thenAnswer(inv -> Optional.ofNullable(queue.poll()));
    }

    private double count(String outcome) {
        return meters.get("sentinelflow.reconciler.events").tag("outcome", outcome).counter().count();
    }

    @Test
    void eventLeftPendingByAFailedPublish_isRepublishedAsStored_andTheAttemptIsAudited() {

        transactionsWork();
        Event stored = storedEvent("EV-1");
        claimable(stored);

        PendingEventReconciler.Result result = reconciler.reconcile();

        assertThat(result).isEqualTo(new PendingEventReconciler.Result(1, 0, 0));
        ArgumentCaptor<CreateEventRequest> sent = ArgumentCaptor.forClass(CreateEventRequest.class);
        verify(kafkaProducer).publishNow(sent.capture(), eq(props.getSendTimeout()));
        assertThat(sent.getValue()).isEqualTo(new CreateEventRequest(
                "EV-1", "HOST-1", "LOGIN", "v1", stored.getOccurredAt(), "rest", stored.getPayload()));
        verify(auditLogService).log(eq("system"), eq("EVENT_REPUBLISH_ATTEMPT"), eq("EVENT"), eq(stored.getId()), any(),
                eq(Map.of("eventId", "EV-1", "attempt", 1L, "maxAttempts", 6)));
        assertThat(count("republished")).isEqualTo(1);
    }

    @Test
    void crashBetweenCommitAndPublish_leavesAnEventThatIsRecoveredTheSameWay_withTheConfiguredAgeWindow() {

        // A crash after commit leaves exactly the state a failed send leaves:
        // PENDING, 0 attempts, no prediction. Only age decides when it is due.
        transactionsWork();
        claimable(storedEvent("EV-CRASH"));

        reconciler.reconcile();

        OffsetDateTime now = NOW.atOffset(ZoneOffset.UTC);
        // the claim that returned the event, then the one that found nothing more
        verify(eventRepository, times(2)).claimNextUnpublished(
                now.minus(Duration.ofMinutes(10)),   // staleAfter: normal publish/processing long over
                now.minus(Duration.ofHours(24)),     // maxAge
                now.minus(Duration.ofMinutes(10)),   // retryInterval
                6L);
        verify(kafkaProducer).publishNow(any(), any());
    }

    @Test
    void sendFailureBelowTheLimit_isCounted_stopsTheRun_andDoesNotGiveUp() {

        transactionsWork();
        claimable(storedEvent("EV-1"), storedEvent("EV-2"));
        doThrow(new IllegalStateException("broker down")).when(kafkaProducer).publishNow(any(), any());

        PendingEventReconciler.Result result = reconciler.reconcile();

        assertThat(result).isEqualTo(new PendingEventReconciler.Result(0, 1, 0));
        // EV-2 is not claimed in this run, so it does not lose an attempt to the same outage
        verify(eventRepository, times(1)).claimNextUnpublished(any(), any(), any(), anyLong());
        verify(auditLogService, never()).log(any(), eq("EVENT_REPUBLISH_EXHAUSTED"), any(), any(), any(), any());
        assertThat(count("failed")).isEqualTo(1);
    }

    @Test
    void sendFailureOnTheFinalAttempt_givesUp_soTheEventIsNotRetriedForever() {

        transactionsWork();
        Event stored = storedEvent("EV-1");
        claimable(stored);
        when(auditLogRepository.countByResourceTypeAndResourceIdAndAction("EVENT", stored.getId(), "EVENT_REPUBLISH_ATTEMPT"))
                .thenReturn(5L);   // this is attempt 6 of 6
        doThrow(new IllegalStateException("broker down")).when(kafkaProducer).publishNow(any(), any());

        PendingEventReconciler.Result result = reconciler.reconcile();

        assertThat(result).isEqualTo(new PendingEventReconciler.Result(0, 1, 1));
        verify(auditLogService).log(eq("system"), eq("EVENT_REPUBLISH_EXHAUSTED"), eq("EVENT"), eq(stored.getId()), any(), any());
        assertThat(count("exhausted")).isEqualTo(1);
    }

    @Test
    void anEventKafkaCanNeverCarry_isGivenUpOnImmediately_withoutSending_andTheRunContinues() {

        transactionsWork();
        Event huge = storedEvent("EV-HUGE");
        Event normal = storedEvent("EV-OK");
        claimable(huge, normal);
        doThrow(new PayloadTooLargeException("too large")).when(kafkaProducer)
                .ensurePublishable(org.mockito.ArgumentMatchers.argThat(r -> r != null && "EV-HUGE".equals(r.eventId())));

        PendingEventReconciler.Result result = reconciler.reconcile();

        assertThat(result).isEqualTo(new PendingEventReconciler.Result(1, 0, 1));
        verify(kafkaProducer, never()).publishNow(org.mockito.ArgumentMatchers.argThat(r -> "EV-HUGE".equals(r.eventId())), any());
        verify(auditLogService).log(eq("system"), eq("EVENT_REPUBLISH_EXHAUSTED"), eq("EVENT"), eq(huge.getId()), any(), any());
    }

    @Test
    void oneRunHandlesAtMostBatchSizeEvents() {

        transactionsWork();
        props.setBatchSize(2);
        claimable(storedEvent("EV-1"), storedEvent("EV-2"), storedEvent("EV-3"));

        PendingEventReconciler.Result result = reconciler.reconcile();

        assertThat(result.republished()).isEqualTo(2);
        verify(kafkaProducer, times(2)).publishNow(any(), any());
    }

    @Test
    void nothingEligible_sendsNothing() {

        transactionsWork();
        when(eventRepository.claimNextUnpublished(any(), any(), any(), anyLong())).thenReturn(Optional.empty());

        assertThat(reconciler.reconcile()).isEqualTo(new PendingEventReconciler.Result(0, 0, 0));
        verify(kafkaProducer, never()).publishNow(any(), any());
        verifyNoInteractions(auditLogService);
    }

    @Test
    void eachClaimRunsInItsOwnTransaction_soTheRowLockIsReleasedBeforeTheSend() {

        transactionsWork();
        claimable(storedEvent("EV-1"), storedEvent("EV-2"));

        reconciler.reconcile();

        // two claims + the final empty claim, each begun and committed
        verify(transactionManager, times(3)).getTransaction(any());
        verify(transactionManager, times(3)).commit(any());
    }

    @Test
    void disabled_doesNothing() {

        props.setEnabled(false);

        reconciler.scheduledRun();

        verifyNoInteractions(eventRepository, kafkaProducer, auditLogService, transactionManager);
    }

    @Test
    void aFailingRun_isLoggedAndDoesNotPropagate_soTheScheduleKeepsRunning() {

        when(transactionManager.getTransaction(any())).thenThrow(new IllegalStateException("database unavailable"));

        assertThatCode(() -> reconciler.scheduledRun()).doesNotThrowAnyException();
        verifyNoInteractions(kafkaProducer);
    }
}
