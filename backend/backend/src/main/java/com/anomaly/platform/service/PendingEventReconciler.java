package com.anomaly.platform.service;

import com.anomaly.platform.config.ReconcilerProperties;
import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.exception.PayloadTooLargeException;
import com.anomaly.platform.kafka.EventKafkaProducer;
import com.anomaly.platform.repository.AuditLogRepository;
import com.anomaly.platform.repository.EventRepository;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/*
 * Recovers events that the REST API stored but that never reached Kafka.
 *
 * EventService commits the event first and publishes it after commit
 * (EventKafkaProducer.publish). If that send fails, or the process dies in
 * between, the row stays PENDING and nothing would ever process it. This job
 * finds such rows and publishes them again.
 *
 * Which rows: see EventRepository.claimNextUnpublished - PENDING, never
 * attempted, no prediction, older than staleAfter but within maxAge, and
 * under the attempt limit. There is no "published" flag, so an event that
 * WAS published but is still waiting in the consumer backlog after
 * staleAfter can be sent twice; that is safe because the consumer is
 * idempotent: it reuses the stored row and skips any event already
 * PROCESSED with a prediction (EventProcessingService), so the duplicate is
 * a no-op.
 *
 * Every attempt is recorded as an EVENT_REPUBLISH_ATTEMPT audit row before
 * the send (attempt count and spacing survive restarts and are visible in
 * the audit log); after maxAttempts, or for an event Kafka can never carry,
 * an EVENT_REPUBLISH_EXHAUSTED row stops further tries and the event needs
 * an operator (POST /api/v1/replay-runs). FAILED and PROCESSED events are
 * never touched.
 */
@Service
public class PendingEventReconciler {

    static final String ATTEMPT = "EVENT_REPUBLISH_ATTEMPT";
    static final String EXHAUSTED = "EVENT_REPUBLISH_EXHAUSTED";
    private static final String RESOURCE = "EVENT";

    private static final Logger log = LoggerFactory.getLogger(PendingEventReconciler.class);

    private final EventRepository eventRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;
    private final EventKafkaProducer kafkaProducer;
    private final TransactionTemplate claimTransaction;
    private final ReconcilerProperties props;
    private final Clock clock;

    private final Counter republished;
    private final Counter failed;
    private final Counter exhausted;

    @Autowired
    public PendingEventReconciler(
            EventRepository eventRepository,
            AuditLogRepository auditLogRepository,
            AuditLogService auditLogService,
            EventKafkaProducer kafkaProducer,
            PlatformTransactionManager transactionManager,
            ReconcilerProperties props,
            MeterRegistry meterRegistry
    ) {
        this(eventRepository, auditLogRepository, auditLogService, kafkaProducer,
                transactionManager, props, meterRegistry, Clock.systemUTC());
    }

    PendingEventReconciler(
            EventRepository eventRepository,
            AuditLogRepository auditLogRepository,
            AuditLogService auditLogService,
            EventKafkaProducer kafkaProducer,
            PlatformTransactionManager transactionManager,
            ReconcilerProperties props,
            MeterRegistry meterRegistry,
            Clock clock
    ) {
        this.eventRepository = eventRepository;
        this.auditLogRepository = auditLogRepository;
        this.auditLogService = auditLogService;
        this.kafkaProducer = kafkaProducer;
        this.claimTransaction = new TransactionTemplate(transactionManager);
        this.props = props;
        this.clock = clock;
        this.republished = counter(meterRegistry, "republished");
        this.failed = counter(meterRegistry, "failed");
        this.exhausted = counter(meterRegistry, "exhausted");
    }

    private static Counter counter(MeterRegistry registry, String outcome) {
        return Counter.builder("sentinelflow.reconciler.events")
                .description("Unpublished PENDING events handled by the reconciler, by outcome")
                .tag("outcome", outcome)
                .register(registry);
    }

    public record Result(int republished, int failed, int exhausted) {
    }

    private record Claim(UUID id, CreateEventRequest request, long attempt) {
    }

    @Scheduled(
            initialDelayString = "${anomaly.reconciler.interval:PT1M}",
            fixedDelayString = "${anomaly.reconciler.interval:PT1M}"
    )
    public void scheduledRun() {
        if (!props.isEnabled()) {
            return;
        }
        try {
            reconcile();
        } catch (Exception e) {
            // e.g. database unavailable: try again on the next run
            log.error("Pending-event reconciliation run failed", e);
        }
    }

    public Result reconcile() {

        OffsetDateTime now = OffsetDateTime.now(clock);
        int sent = 0;
        int sendFailures = 0;
        int givenUp = 0;

        for (int i = 0; i < props.getBatchSize(); i++) {

            // Claim one event per short transaction: the row lock is held only
            // while the attempt is recorded, and that fresh attempt row is what
            // keeps other runs away from the event for retryInterval.
            Claim claim = claimTransaction.execute(status -> claimNext(now));
            if (claim == null) {
                break;
            }

            try {
                kafkaProducer.ensurePublishable(claim.request());
            } catch (PayloadTooLargeException tooLarge) {
                giveUp(claim, "payload too large for Kafka: " + tooLarge.getMessage());
                givenUp++;
                continue;
            }

            try {
                kafkaProducer.publishNow(claim.request(), props.getSendTimeout());
                republished.increment();
                sent++;
                log.warn(
                        "Recovered unpublished event: re-published eventId={} dbEventId={} attempt={}/{}",
                        claim.request().eventId(), claim.id(), claim.attempt(), props.getMaxAttempts()
                );
            } catch (RuntimeException sendFailure) {
                failed.increment();
                sendFailures++;
                log.warn(
                        "Re-publish failed eventId={} dbEventId={} attempt={}/{} reason={}",
                        claim.request().eventId(), claim.id(), claim.attempt(), props.getMaxAttempts(),
                        sendFailure.getMessage()
                );
                if (claim.attempt() >= props.getMaxAttempts()) {
                    giveUp(claim, "re-publish failed " + claim.attempt() + " times; last error: " + sendFailure.getMessage());
                    givenUp++;
                }
                // The broker is most likely unavailable: stop this run instead of
                // spending the remaining events' attempts on the same outage.
                break;
            }
        }

        if (sent + sendFailures + givenUp > 0) {
            log.info("Pending-event reconciliation: republished={} failed={} gaveUp={}", sent, sendFailures, givenUp);
        }
        return new Result(sent, sendFailures, givenUp);
    }

    private Claim claimNext(OffsetDateTime now) {

        UUID id = eventRepository.claimNextUnpublished(
                now.minus(props.getStaleAfter()),
                now.minus(props.getMaxAge()),
                now.minus(props.getRetryInterval()),
                props.getMaxAttempts()
        ).orElse(null);

        if (id == null) {
            return null;
        }

        Event event = eventRepository.findById(id).orElseThrow();
        long attempt = auditLogRepository.countByResourceTypeAndResourceIdAndAction(RESOURCE, id, ATTEMPT) + 1;

        CreateEventRequest request = new CreateEventRequest(
                event.getEventId(),
                event.getEntity().getEntityId(),
                event.getEventType(),
                event.getEventVersion(),
                event.getOccurredAt(),
                event.getSource(),
                event.getPayload()
        );

        auditLogService.log("system", ATTEMPT, RESOURCE, id, null, Map.of(
                "eventId", event.getEventId(),
                "attempt", attempt,
                "maxAttempts", props.getMaxAttempts()
        ));

        return new Claim(id, request, attempt);
    }

    private void giveUp(Claim claim, String reason) {
        exhausted.increment();
        auditLogService.log("system", EXHAUSTED, RESOURCE, claim.id(), null, Map.of(
                "eventId", claim.request().eventId(),
                "attempts", claim.attempt(),
                "reason", reason
        ));
        log.error(
                "Giving up on unpublished event eventId={} dbEventId={} after attempt {}: {} - it stays PENDING; "
                        + "recover it with POST /api/v1/replay-runs",
                claim.request().eventId(), claim.id(), claim.attempt(), reason
        );
    }
}
