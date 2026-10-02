package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.dto.AlertResponse;
import com.anomaly.platform.dto.EventResponse;
import com.anomaly.platform.dto.EventTrailResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.dto.PredictionResponse;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.EventKafkaProducer;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EntityProfileRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class EventService {

    private final EventRepository repo;
    private final EntityProfileRepository entityRepository;
    private final EventKafkaProducer kafkaProducer;
    private final PredictionRepository predictionRepository;
    private final AlertRepository alertRepository;
    private final PredictionService predictionService;
    private final AlertService alertService;

    public EventService(
            EventRepository repo,
            EntityProfileRepository entityRepository,
            EventKafkaProducer kafkaProducer,
            PredictionRepository predictionRepository,
            AlertRepository alertRepository,
            PredictionService predictionService,
            AlertService alertService
    ) {
        this.repo = repo;
        this.entityRepository = entityRepository;
        this.kafkaProducer = kafkaProducer;
        this.predictionRepository = predictionRepository;
        this.alertRepository = alertRepository;
        this.predictionService = predictionService;
        this.alertService = alertService;
    }

    @Transactional
    public EventResponse create(CreateEventRequest request) {

        /*
         * 1. Find the entity.
         */
        EntityProfile entity = entityRepository
                .findByEntityId(request.entityId())
                .orElseThrow(() ->
                        new NotFoundException(
                                "Entity not found: " + request.entityId()
                        )
                );

        /*
         * Reject an event Kafka cannot carry BEFORE persisting it, so it can
         * never be stored without being processable.
         */
        kafkaProducer.ensurePublishable(request);

        /*
         * 2. Create the Event entity.
         */
        Event event = new Event();

        event.setEventId(request.eventId());
        event.setEntity(entity);
        event.setEventType(request.eventType());
        event.setEventVersion(request.eventVersion());
        event.setOccurredAt(request.occurredAt());
        event.setSource(request.source());
        event.setPayload(request.payload());

        /*
         * 3. Persist the event in PostgreSQL.
         */
        Event saved = repo.save(event);

        /*
         * 4. Publish the raw event to Kafka.
         */
        kafkaProducer.publish(request);

        /*
         * 5. Return the normal REST response.
         */
        return EventResponse.from(saved);
    }

    @Transactional(readOnly = true)
    public EventResponse get(String id) {

        return repo.findByEventId(id)
                .map(EventResponse::from)
                .orElseThrow(() ->
                        new NotFoundException(
                                "Event not found: " + id
                        )
                );
    }

    /*
     * What the detection pipeline did with one event: processing outcome,
     * prediction and (if raised) alert.
     */
    @Transactional(readOnly = true)
    public EventTrailResponse trail(String id) {

        Event event = repo.findByEventId(id)
                .orElseThrow(() ->
                        new NotFoundException(
                                "Event not found: " + id
                        )
                );

        PredictionResponse prediction =
                predictionRepository
                        .findTopByEvent_IdOrderByCreatedAtDesc(event.getId())
                        .map(p -> predictionService.get(p.getId()))
                        .orElse(null);

        // Newest first. A rule alert and an ML alert can both exist for one
        // event; returning only the newest hid the other one entirely.
        List<AlertResponse> alerts =
                alertRepository
                        .findByEvent_IdOrderByCreatedAtDesc(event.getId())
                        .stream()
                        .map(a -> alertService.get(a.getId()))
                        .toList();

        return new EventTrailResponse(
                event.getEventId(),
                event.getProcessingStatus(),
                event.getProcessingAttempts(),
                event.getLastProcessingError(),
                event.getProcessedAt(),
                prediction,
                alerts.isEmpty() ? null : alerts.get(0),
                alerts
        );
    }

    /*
     * Specification-based (Source-Aware SOC phase): entityId/eventType
     * previously drove a hand-branched if/else chain over four discrete
     * repository finder methods, which does not extend to a third filter
     * (source) without an exponential number of branches. Every supplied
     * filter is applied together (AND), matching AlertService/
     * IncidentService's existing Specification pattern exactly - same
     * "no filter combination is silently ignored" property those already
     * have.
     */
    @Transactional(readOnly = true)
    public PageResponse<EventResponse> list(
            String entityId,
            String eventType,
            String source,
            int page,
            int size
    ) {

        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(
                        Sort.Direction.DESC,
                        "occurredAt"
                )
        );

        Specification<Event> spec = Specification.where(null);

        if (entityId != null) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("entity").get("entityId"), entityId));
        }

        if (eventType != null) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("eventType"), eventType));
        }

        if (source != null) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("source"), source));
        }

        Page<Event> events = repo.findAll(spec, pageable);

        return PageResponse.from(
                events.map(EventResponse::from)
        );
    }

}