package com.anomaly.platform.service;

import com.anomaly.platform.config.CorrelationIdFilter;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.EventProcessingStatus;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.KafkaEvent;
import com.anomaly.platform.repository.EntityProfileRepository;
import com.anomaly.platform.repository.EventRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/*
 * ================================================================
 * WHY THIS CLASS EXISTS
 * ================================================================
 *
 * EventProcessingService used to be a single @Transactional method that
 * persisted the event AND ran feature extraction/scoring/prediction/alert/
 * incident creation in one atomic unit. That meant a failure anywhere in
 * scoring or prediction rolled back the event insert itself (when the event
 * did not already exist), and there was no durable record that processing
 * had even been attempted - only a caught exception that got printed to
 * stderr and discarded by the Kafka consumer.
 *
 * This service is a separate Spring bean specifically so that every method
 * here runs in its OWN transaction (calls from EventProcessingService always
 * cross this bean's transactional proxy - no self-invocation problem).
 * That gives us three independently-durable facts, regardless of whether
 * the detection pipeline itself succeeds or throws:
 *
 *   1. The event was received (persistOrLoad) - idempotent on eventId.
 *   2. Processing succeeded (markProcessed).
 *   3. Processing failed, with a recorded reason (markFailed), or the event
 *      could not even be persisted (recordUnresolvableFailure).
 *
 * This is what makes "an accepted event must never silently disappear" true:
 * every event either ends up PROCESSED, or FAILED with a reason attached
 * and an audit log entry, and it is always still readable via EventRepository.
 */
@Service
public class EventProcessingLedgerService {

    private static final Logger log = LoggerFactory.getLogger(EventProcessingLedgerService.class);

    private static final int MAX_ERROR_MESSAGE_LENGTH = 1000;

    private final EventRepository eventRepository;
    private final EntityProfileRepository entityProfileRepository;
    private final AuditLogService auditLogService;

    public EventProcessingLedgerService(
            EventRepository eventRepository,
            EntityProfileRepository entityProfileRepository,
            AuditLogService auditLogService
    ) {
        this.eventRepository = eventRepository;
        this.entityProfileRepository = entityProfileRepository;
        this.auditLogService = auditLogService;
    }

    /*
     * ============================================================
     * PERSIST OR LOAD (IDEMPOTENT ON eventId)
     * ============================================================
     *
     * The REST API already stores the event before publishing it to Kafka,
     * so in the current architecture this almost always hits the
     * "already exists" branch. It also defends against a future producer
     * (e.g. the planned Python simulator) publishing directly to Kafka
     * without going through the REST API first.
     *
     * Runs in its own transaction so the event row commits independently
     * of whatever happens afterward in the detection pipeline.
     */
    @Transactional
    public Event persistOrLoad(KafkaEvent kafkaEvent) {

        Event existing = eventRepository
                .findByEventIdWithEntity(kafkaEvent.eventId())
                .orElse(null);

        if (existing != null) {
            return existing;
        }

        EntityProfile entity =
                entityProfileRepository
                        .findByEntityId(kafkaEvent.entityId())
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Entity not found: " + kafkaEvent.entityId()
                                )
                        );

        Event event = new Event();

        event.setEventId(kafkaEvent.eventId());
        event.setEntity(entity);
        event.setEventType(kafkaEvent.eventType());
        event.setEventVersion(kafkaEvent.eventVersion());
        event.setOccurredAt(kafkaEvent.occurredAt());
        event.setSource(kafkaEvent.source());
        event.setPayload(kafkaEvent.payload());

        Event saved = eventRepository.save(event);

        log.info(
                "Event persisted from Kafka eventId={} entityId={} dbEventId={}",
                kafkaEvent.eventId(),
                kafkaEvent.entityId(),
                saved.getId()
        );

        return saved;
    }

    /*
     * ============================================================
     * MARK PROCESSED
     * ============================================================
     */
    @Transactional
    public void markProcessed(UUID eventDbId) {

        Event event =
                eventRepository.findById(eventDbId)
                        .orElseThrow(() ->
                                new NotFoundException("Event not found: " + eventDbId)
                        );

        event.setProcessingStatus(EventProcessingStatus.PROCESSED);
        event.setProcessedAt(OffsetDateTime.now());

        /*
         * A prior attempt may have failed and left an error message behind.
         * Once processing succeeds (e.g. on a Kafka-level retry), that error
         * is no longer current and would otherwise sit on an event that
         * looks PROCESSED, misleading anyone reading it later. attemptCount
         * is deliberately left untouched - it is a legitimate historical
         * count of how many attempts this event needed.
         */
        event.setLastProcessingError(null);

        eventRepository.save(event);
    }

    /*
     * ============================================================
     * MARK FAILED
     * ============================================================
     *
     * Records the failure on the event itself (status, attempt count,
     * truncated error message) AND writes an audit log entry, mirroring
     * the pattern ReplayRunService already uses for replay failures.
     *
     * Called once per processing attempt, so a message that is retried
     * by the Kafka error handler accumulates one audit entry per attempt -
     * that is deliberate: it gives a visible retry history.
     */
    @Transactional
    public void markFailed(UUID eventDbId, String businessEventId, Throwable error) {

        Event event =
                eventRepository.findById(eventDbId)
                        .orElseThrow(() ->
                                new NotFoundException("Event not found: " + eventDbId)
                        );

        int attempt = event.getProcessingAttempts() + 1;

        event.setProcessingStatus(EventProcessingStatus.FAILED);
        event.setProcessingAttempts(attempt);
        event.setLastProcessingError(safeMessage(error));

        eventRepository.save(event);

        Map<String, Object> details = new HashMap<>();
        details.put("eventId", businessEventId);
        details.put("attempt", attempt);
        details.put("errorType", error.getClass().getSimpleName());
        details.put("errorMessage", safeMessage(error));

        auditLogService.log(
                "system",
                "EVENT_PROCESSING_FAILED",
                "EVENT",
                event.getId(),
                MDC.get(CorrelationIdFilter.HEADER),
                details
        );
    }

    /*
     * ============================================================
     * RECORD UNRESOLVABLE FAILURE (NO EVENT ROW EXISTS)
     * ============================================================
     *
     * Covers the case where the event could not even be persisted (e.g.
     * the referenced entity does not exist). There is no Event row to
     * attach a status to, so this is recorded purely as an audit log entry
     * plus a structured error log, so the failure is still discoverable.
     */
    @Transactional
    public void recordUnresolvableFailure(String businessEventId, String entityId, Throwable error) {

        log.error(
                "Event could not be persisted before processing; no event row exists. eventId={} entityId={} reason={}",
                businessEventId,
                entityId,
                error.getMessage(),
                error
        );

        Map<String, Object> details = new HashMap<>();
        details.put("eventId", businessEventId == null ? "" : businessEventId);
        details.put("entityId", entityId == null ? "" : entityId);
        details.put("errorType", error.getClass().getSimpleName());
        details.put("errorMessage", safeMessage(error));

        auditLogService.log(
                "system",
                "EVENT_PERSIST_FAILED",
                "EVENT",
                null,
                MDC.get(CorrelationIdFilter.HEADER),
                details
        );
    }

    private String safeMessage(Throwable error) {

        String message = error.getMessage();

        if (message == null || message.isBlank()) {
            return "No error message available";
        }

        if (message.length() > MAX_ERROR_MESSAGE_LENGTH) {
            return message.substring(0, MAX_ERROR_MESSAGE_LENGTH);
        }

        return message;
    }
}
