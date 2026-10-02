package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreateReplayRunRequest;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.dto.ReplayRunResponse;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.ReplayRun;
import com.anomaly.platform.entity.ReplayStatus;
import com.anomaly.platform.exception.DuplicateResourceException;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.KafkaEvent;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.ReplayRunRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Map;

@Service
public class ReplayRunService {

    private static final Logger log =
            LoggerFactory.getLogger(ReplayRunService.class);

    private final ReplayRunRepository replayRunRepository;
    private final EventRepository eventRepository;
    private final EventProcessingService eventProcessingService;
    private final AuditLogService auditLogService;

    public ReplayRunService(
            ReplayRunRepository replayRunRepository,
            EventRepository eventRepository,
            EventProcessingService eventProcessingService,
            AuditLogService auditLogService
    ) {
        this.replayRunRepository = replayRunRepository;
        this.eventRepository = eventRepository;
        this.eventProcessingService = eventProcessingService;
        this.auditLogService = auditLogService;
    }

    /*
     * ============================================================
     * CREATE AND EXECUTE REPLAY
     * ============================================================
     */

    /*
     * Deliberately NOT @Transactional. Each event is processed exactly as the
     * Kafka consumer processes it - its own transactions, committed as it
     * goes - and the run's progress is saved after every event. One run-wide
     * transaction meant a failure inside any participating @Transactional
     * method (e.g. a database error saving one event's prediction) marked the
     * whole run rollback-only: every other event's results, the run record
     * and its failure audit were rolled back and the caller got a 500,
     * sometimes with the error blamed on a later event (the failing insert
     * was only flushed then). Reproduced on an isolated stack.
     */
    public ReplayRunResponse create(
            CreateReplayRunRequest request
    ) {

        /*
         * Request validation is handled by @Valid.
         */

        /*
         * ========================================================
         * CHECK DUPLICATE RUN
         * ========================================================
         */

        if (replayRunRepository
                .findByRunKey(request.runKey())
                .isPresent()) {

            throw new DuplicateResourceException(
                    "Replay run already exists: "
                            + request.runKey()
            );
        }

        /*
         * ========================================================
         * CREATE REPLAY RUN
         * ========================================================
         */

        ReplayRun replayRun =
                new ReplayRun();

        replayRun.setRunKey(
                request.runKey()
        );

        replayRun.setSourceName(
                request.sourceName()
        );

        replayRun.setStatus(
                ReplayStatus.CREATED
        );

        replayRun.setTotalEvents(
                request.eventIds().size()
        );

        replayRun.setProcessedEvents(0);

        replayRun.setFailedEvents(0);

        /*
         * Save initial replay state.
         */

        ReplayRun saved =
                replayRunRepository.save(
                        replayRun
                );

        /*
         * ========================================================
         * START REPLAY
         * ========================================================
         */

        saved.setStatus(
                ReplayStatus.RUNNING
        );

        saved.setStartedAt(
                OffsetDateTime.now()
        );

        saved =
                replayRunRepository.save(
                        saved
                );

        /*
         * ========================================================
         * PROCESS EVENTS
         * ========================================================
         */

        /*
         * Each event is counted exactly once: as failed if replaying it threw,
         * otherwise as processed - and only after its skip audit (if any) was
         * written. Progress is saved after every event. If an audit or
         * progress write itself fails (typically the database), the run is
         * stopped and closed as FAILED with the counts known so far (abortRun)
         * and the error is propagated; events already processed stay
         * committed.
         */
        try {

            for (String eventId : request.eventIds()) {

                EventProcessingService.Outcome outcome;

                try {
                    outcome = replayOne(eventId);
                } catch (Exception processingFailure) {
                    // Replay is a batch: one failed event does not stop the others.
                    log.error(
                            "Replay failed for event {} in run {}",
                            eventId,
                            saved.getRunKey(),
                            processingFailure
                    );
                    saved.setFailedEvents(saved.getFailedEvents() + 1);
                    auditReplayFailure(saved, eventId, processingFailure);
                    saved = replayRunRepository.save(saved);
                    continue;
                }

                // An already-processed event is a no-op, recorded in the audit
                // log before it is counted.
                if (outcome == EventProcessingService.Outcome.ALREADY_PROCESSED) {
                    auditReplaySkipped(saved, eventId);
                }
                saved.setProcessedEvents(saved.getProcessedEvents() + 1);

                // progress is durable after every event (no run-wide transaction)
                saved = replayRunRepository.save(saved);
            }

        } catch (RuntimeException runFailure) {
            abortRun(saved, runFailure);
            throw runFailure;
        }

        /*
         * ========================================================
         * COMPLETE REPLAY
         * ========================================================
         */

        saved.setStatus(
                saved.getFailedEvents() == 0
                        ? ReplayStatus.COMPLETED
                        : ReplayStatus.FAILED
        );
        saved.setCompletedAt(
                OffsetDateTime.now()
        );

        try {
            saved = replayRunRepository.save(saved);
        } catch (RuntimeException finalSaveFailure) {
            // Never report a run whose final state was not recorded.
            log.error(
                    "Replay run {} finished (processed={} failed={} of {}) but its final status could not be saved",
                    saved.getRunKey(),
                    saved.getProcessedEvents(),
                    saved.getFailedEvents(),
                    saved.getTotalEvents(),
                    finalSaveFailure
            );
            throw finalSaveFailure;
        }

        return toResponse(
                saved
        );
    }

    /*
     * Replays one stored event through the normal pipeline. JOIN FETCH in
     * EventRepository loads the EntityProfile with it (no lazy loading).
     */
    private EventProcessingService.Outcome replayOne(String eventId) {

        Event event =
                eventRepository
                        .findByEventIdWithEntity(eventId)
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Event not found: " + eventId
                                )
                        );

        KafkaEvent kafkaEvent =
                new KafkaEvent(
                        event.getEventId(),
                        event.getEntity().getEntityId(),
                        event.getEventType(),
                        event.getEventVersion(),
                        event.getOccurredAt(),
                        event.getSource(),
                        event.getPayload()
                );

        return eventProcessingService.process(kafkaEvent);
    }

    /*
     * An audit or progress write failed mid-run. Close the run as FAILED with
     * the counts accumulated so far rather than leaving it RUNNING; a run
     * whose processed + failed is below totalEvents was stopped early. This
     * save is best effort - if the database is still unavailable the run may
     * stay RUNNING, which is logged - and the caller always gets the
     * original error.
     */
    private void abortRun(ReplayRun run, RuntimeException cause) {

        run.setStatus(ReplayStatus.FAILED);
        run.setCompletedAt(OffsetDateTime.now());

        log.error(
                "Replay run {} stopped early by a persistence failure after processed={} failed={} of {} events",
                run.getRunKey(),
                run.getProcessedEvents(),
                run.getFailedEvents(),
                run.getTotalEvents(),
                cause
        );

        try {
            replayRunRepository.save(run);
        } catch (RuntimeException saveFailure) {
            cause.addSuppressed(saveFailure);
            log.error(
                    "Could not record replay run {} as FAILED - it may still show RUNNING",
                    run.getRunKey(),
                    saveFailure
            );
        }
    }

    /*
     * ============================================================
     * AUDIT REPLAY FAILURE
     * ============================================================
     */

    private void auditReplayFailure(
            ReplayRun replayRun,
            String eventId,
            Exception exception
    ) {

        String correlationId =
                MDC.get("X-Correlation-Id");

        auditLogService.log(
                "system",
                "REPLAY_EVENT_FAILED",
                "REPLAY_RUN",
                replayRun.getId(),
                correlationId,
                Map.of(
                        "runKey",
                        replayRun.getRunKey(),

                        "eventId",
                        eventId,

                        "errorType",
                        exception.getClass()
                                .getSimpleName(),

                        "errorMessage",
                        safeMessage(exception),

                        "recoveryAction",
                        recoveryAction(exception)
                )
        );
    }

    /* What the operator can do about one event that failed in a replay run. */
    static String recoveryAction(Exception exception) {

        if (exception instanceof NotFoundException
                && String.valueOf(exception.getMessage()).startsWith("Event not found")) {
            return "No event row exists for this eventId, so replay cannot recover it. If the record is on "
                    + "raw.events.v1.DLT (an event that arrived only via Kafka), fix the cause and re-publish "
                    + "that record's value to raw.events.v1.";
        }
        return "The event is FAILED with this error recorded (GET /api/v1/events/{eventId}/trail). "
                + "Fix the cause, then replay it again in a new run.";
    }

    private void auditReplaySkipped(ReplayRun replayRun, String eventId) {

        auditLogService.log(
                "system",
                "REPLAY_EVENT_SKIPPED",
                "REPLAY_RUN",
                replayRun.getId(),
                MDC.get("X-Correlation-Id"),
                Map.of(
                        "runKey", replayRun.getRunKey(),
                        "eventId", eventId,
                        "reason", "already PROCESSED with a prediction on record - nothing was re-run"
                )
        );
    }

    /*
     * ============================================================
     * SAFE EXCEPTION MESSAGE
     * ============================================================
     */

    private String safeMessage(
            Exception exception
    ) {

        String message =
                exception.getMessage();

        if (message == null || message.isBlank()) {

            return "No error message available";
        }

        /*
         * Prevent very large exception messages from
         * bloating the audit log.
         */

        if (message.length() > 1000) {

            return message.substring(0, 1000);
        }

        return message;
    }

    /*
     * ============================================================
     * GET REPLAY RUN
     * ============================================================
     */

    @Transactional(readOnly = true)
    public ReplayRunResponse get(
            String runKey
    ) {

        ReplayRun replayRun =
                replayRunRepository
                        .findByRunKey(runKey)
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Replay run not found: "
                                                + runKey
                                )
                        );

        return toResponse(
                replayRun
        );
    }

    /*
     * ============================================================
     * LIST REPLAY RUNS (newest first)
     * ============================================================
     */

    @Transactional(readOnly = true)
    public PageResponse<ReplayRunResponse> list(
            int page,
            int size
    ) {

        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(Sort.Direction.DESC, "createdAt")
        );

        return PageResponse.from(
                replayRunRepository
                        .findAll(pageable)
                        .map(this::toResponse)
        );
    }

    /*
     * ============================================================
     * ENTITY → RESPONSE
     * ============================================================
     */

    private ReplayRunResponse toResponse(
            ReplayRun replayRun
    ) {

        return new ReplayRunResponse(
                replayRun.getId(),
                replayRun.getRunKey(),
                replayRun.getSourceName(),
                replayRun.getStatus(),
                replayRun.getTotalEvents(),
                replayRun.getProcessedEvents(),
                replayRun.getFailedEvents(),
                replayRun.getStartedAt(),
                replayRun.getCompletedAt(),
                replayRun.getCreatedAt()
        );
    }
}