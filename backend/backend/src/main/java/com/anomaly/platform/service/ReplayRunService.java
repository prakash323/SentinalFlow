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

    @Transactional
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

        for (String eventId :
                request.eventIds()) {

            try {

                /*
                 * Load event together with EntityProfile.
                 *
                 * JOIN FETCH in EventRepository prevents
                 * LazyInitializationException.
                 */

                Event event =
                        eventRepository
                                .findByEventIdWithEntity(
                                        eventId
                                )
                                .orElseThrow(() ->
                                        new NotFoundException(
                                                "Event not found: "
                                                        + eventId
                                        )
                                );

                /*
                 * =================================================
                 * CONVERT DATABASE EVENT → KAFKA EVENT
                 * =================================================
                 */

                KafkaEvent kafkaEvent =
                        new KafkaEvent(
                                event.getEventId(),

                                event.getEntity()
                                        .getEntityId(),

                                event.getEventType(),

                                event.getEventVersion(),

                                event.getOccurredAt(),

                                event.getSource(),

                                event.getPayload()
                        );

                /*
                 * =================================================
                 * PROCESS EVENT THROUGH NORMAL PIPELINE
                 * =================================================
                 */

                eventProcessingService.process(
                        kafkaEvent
                );

                /*
                 * Event processed successfully.
                 */

                saved.setProcessedEvents(
                        saved.getProcessedEvents() + 1
                );

            } catch (Exception exception) {

                /*
                 * =================================================
                 * EVENT FAILURE
                 * =================================================
                 *
                 * Replay is a batch operation.
                 *
                 * One failed event should NOT stop the
                 * remaining events.
                 */

                saved.setFailedEvents(
                        saved.getFailedEvents() + 1
                );

                /*
                 * =================================================
                 * APPLICATION LOG
                 * =================================================
                 *
                 * Use SLF4J instead of System.err and
                 * exception.printStackTrace().
                 */

                log.error(
                        "Replay failed for event {} in run {}",
                        eventId,
                        saved.getRunKey(),
                        exception
                );

                /*
                 * =================================================
                 * AUDIT LOG
                 * =================================================
                 */

                auditReplayFailure(
                        saved,
                        eventId,
                        exception
                );
            }

            /*
             * ====================================================
             * SAVE PROGRESS AFTER EVERY EVENT
             * ====================================================
             */

            replayRunRepository.save(
                    saved
            );
        }

        /*
         * ========================================================
         * COMPLETE REPLAY
         * ========================================================
         */

        if (saved.getFailedEvents() == 0) {

            saved.setStatus(
                    ReplayStatus.COMPLETED
            );

        } else {

            saved.setStatus(
                    ReplayStatus.FAILED
            );
        }

        saved.setCompletedAt(
                OffsetDateTime.now()
        );

        saved =
                replayRunRepository.save(
                        saved
                );

        return toResponse(
                saved
        );
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
                        safeMessage(exception)
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