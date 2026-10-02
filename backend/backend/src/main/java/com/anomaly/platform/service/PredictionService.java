package com.anomaly.platform.service;

import com.anomaly.platform.config.AlertPolicyProperties;
import com.anomaly.platform.dto.CreatePredictionRequest;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.dto.PredictionResponse;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.Prediction;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class PredictionService {

    private final PredictionRepository predictionRepository;
    private final AlertRepository alertRepository;
    private final AlertFactorRepository alertFactorRepository;
    private final EventRepository eventRepository;
    private final AlertPolicyProperties alertPolicy;
    private final IncidentService incidentService;

    public PredictionService(
            PredictionRepository predictionRepository,
            AlertRepository alertRepository,
            AlertFactorRepository alertFactorRepository,
            EventRepository eventRepository,
            AlertPolicyProperties alertPolicy,
            IncidentService incidentService
    ) {
        this.predictionRepository = predictionRepository;
        this.alertRepository = alertRepository;
        this.alertFactorRepository = alertFactorRepository;
        this.eventRepository = eventRepository;
        this.alertPolicy = alertPolicy;
        this.incidentService = incidentService;
    }

    /*
     * ============================================================
     * LIST PREDICTIONS (newest first)
     * ============================================================
     */
    @Transactional(readOnly = true)
    public PageResponse<PredictionResponse> list(
            String entityId,
            DecisionState decision,
            int page,
            int size
    ) {

        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(Sort.Direction.DESC, "createdAt")
        );

        Specification<Prediction> spec = Specification.where(null);

        if (entityId != null && !entityId.isBlank()) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("entity").get("entityId"), entityId.trim()));
        }

        if (decision != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("decision"), decision));
        }

        Page<Prediction> predictions = predictionRepository.findAll(spec, pageable);

        return PageResponse.from(predictions.map(this::toResponse));
    }

    /*
     * ============================================================
     * GET SINGLE PREDICTION
     * ============================================================
     */
    @Transactional(readOnly = true)
    public PredictionResponse get(
            UUID id
    ) {

        Prediction prediction =
                predictionRepository.findById(id)
                        .orElseThrow(() ->
                                new NotFoundException("Prediction not found: " + id)
                        );

        return toResponse(prediction);
    }

    /*
     * Whether any prediction is on record for this event. Used before the ML
     * call, when the model name/version (the create() idempotency key) is not
     * known yet - it only arrives in the ML response.
     */
    @Transactional(readOnly = true)
    public boolean hasPrediction(UUID eventDbId) {
        return predictionRepository.findTopByEvent_IdOrderByCreatedAtDesc(eventDbId).isPresent();
    }

    @Transactional
    public PredictionResponse create(
            CreatePredictionRequest request
    ) {

        /*
         * Serialize concurrent creates for the same event (Kafka consumer and
         * an admin replay racing): the second waits here, then finds the
         * first one's prediction below and returns it - instead of both
         * inserting, the loser hitting uk_predictions_event_model_version at
         * commit and its caller marking a fully processed event FAILED.
         */
        eventRepository.lockForProcessing(request.eventId());

        /*
         * STEP 1
         * Idempotency check.
         *
         * The same event + model + model version
         * should not create another prediction.
         */
        Prediction existing =
                predictionRepository
                        .findTopByEvent_IdAndModelNameAndModelVersionOrderByCreatedAtDesc(
                                request.eventId(),
                                request.modelName(),
                                request.modelVersion()
                        )
                        .orElse(null);

        if (existing != null) {
            return toResponse(existing);
        }

        /*
         * STEP 2
         * Find the database event.
         */
        Event event =
                eventRepository.findById(request.eventId())
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Event not found: "
                                                + request.eventId()
                                )
                        );

        EntityProfile entity = event.getEntity();

        /*
         * STEP 3
         * Create prediction.
         */
        Prediction prediction = new Prediction();

        prediction.setEvent(event);
        prediction.setEntity(entity);
        prediction.setModelName(request.modelName());
        prediction.setModelVersion(request.modelVersion());
        prediction.setAnomalyScore(request.anomalyScore());
        prediction.setConfidence(request.confidence());
        prediction.setFusedScore(request.fusedScore());
        prediction.setDecision(request.decision());
        prediction.setFeatures(
                request.features() == null
                        ? java.util.Map.of()
                        : request.features()
        );

        /*
         * STEP 4
         * Save prediction.
         */
        Prediction savedPrediction =
                predictionRepository.save(prediction);

        /*
         * STEP 5
         * Create alert when fused score crosses
         * the configured threshold.
         */
        if (shouldCreateAlert(request)) {

            /*
             * Create alert.
             */
            Alert alert =
                    createAlert(
                            event,
                            entity,
                            savedPrediction,
                            request
                    );

            /*
             * Save alert first so that it has an ID.
             */
            Alert savedAlert =
                    alertRepository.save(alert);

            /*
             * STEP 6
             * Find an existing active incident or
             * create a new incident.
             */
            Incident incident =
                    incidentService.findOrCreateIncident(
                            savedAlert
                    );

            /*
             * Link alert to incident.
             */
            savedAlert.setIncident(incident);

            /*
             * STEP 7
             * Create alert factors.
             */
            createAlertFactors(
                    savedAlert,
                    request
            );
        }

        /*
         * STEP 8
         * Return prediction response.
         */
        return toResponse(savedPrediction);
    }

    /*
     * Determines whether an alert should be created.
     */
    private boolean shouldCreateAlert(
            CreatePredictionRequest request
    ) {

        if (request.fusedScore() == null) {
            return false;
        }

        return request.fusedScore()
                .compareTo(
                        BigDecimal.valueOf(
                                alertPolicy.getAlertThreshold()
                        )
                ) >= 0;
    }

    /*
     * Creates an Alert entity.
     */
    private Alert createAlert(
            Event event,
            EntityProfile entity,
            Prediction prediction,
            CreatePredictionRequest request
    ) {

        Alert alert = new Alert();

        /*
         * Relationships.
         */
        alert.setEvent(event);
        alert.setEntity(entity);
        alert.setPrediction(prediction);

        /*
         * Decision.
         */
        alert.setDecision(
                request.decision()
        );

        /*
         * Severity.
         */
        alert.setSeverity(
                determineSeverity(
                        request.fusedScore()
                )
        );

        /*
         * New alerts start as OPEN.
         */
        alert.setStatus(
                AlertStatus.OPEN
        );

        /*
         * Scores.
         */
        alert.setAnomalyScore(
                request.anomalyScore()
        );

        alert.setConfidence(
                request.confidence()
        );

        alert.setFusedScore(
                request.fusedScore()
        );

        /*
         * Store the policy version used
         * for this alert.
         */
        alert.setPolicyVersion(
                alertPolicy.getPolicyVersion()
        );

        return alert;
    }

    /*
     * Creates alert factors explaining why
     * the event was considered anomalous.
     */
    private void createAlertFactors(
            Alert alert,
            CreatePredictionRequest request
    ) {

        List<String> factors =
                determineFactors(request);

        int rank = 1;

        for (String factor : factors) {

            AlertFactor alertFactor =
                    new AlertFactor();

            alertFactor.setAlert(alert);

            alertFactor.setFactor(
                    factor
            );

            alertFactor.setRank(
                    rank++
            );

            alertFactor.setCreatedAt(
                    OffsetDateTime.now()
            );

            alertFactorRepository.save(
                    alertFactor
            );
        }
    }

    /*
     * Determines the individual factors
     * responsible for the anomaly.
     *
     * Prefers the real ML service's own "factors" list (already
     * human-readable strings - see
     * ml-service/anomaly-detection/src/explain.py Explainer.build_alert,
     * "top_factors") when present, since it already did the work of
     * deciding what mattered for this specific event. Falls back to the
     * old heuristic (login/IP/location risk keys) only when that key is
     * absent, so a direct/manual POST /api/v1/predictions call using the
     * older feature shape still produces factors.
     */
    private List<String> determineFactors(
            CreatePredictionRequest request
    ) {

        List<String> factors =
                new ArrayList<>();

        if (request.features() == null) {
            return factors;
        }

        Object mlFactors =
                request.features()
                        .get("factors");

        if (mlFactors instanceof List<?> list && !list.isEmpty()) {

            for (Object factor : list) {

                if (factor != null) {
                    // alert_factors.factor is VARCHAR(128): an over-long ML factor
                    // must not roll back the prediction and dead-letter the event.
                    String text = String.valueOf(factor);
                    factors.add(text.length() <= 128 ? text : text.substring(0, 125) + "...");
                }
            }

            return factors;
        }

        Object loginSuccess =
                request.features()
                        .get("loginSuccess");

        Object location =
                request.features()
                        .get("location");

        Object ipRisk =
                request.features()
                        .get("ipRisk");

        Object locationRisk =
                request.features()
                        .get("locationRisk");

        Object failureRisk =
                request.features()
                        .get("failureRisk");

        /*
         * Login failure.
         */
        if (Boolean.FALSE.equals(loginSuccess)) {

            factors.add(
                    "Login failure"
            );
        }

        /*
         * Unknown location.
         */
        if (location != null
                && "Unknown".equalsIgnoreCase(
                String.valueOf(location)
        )) {

            factors.add(
                    "Unknown location"
            );
        }

        /*
         * High IP risk.
         */
        if (ipRisk instanceof Number
                && ((Number) ipRisk).doubleValue() >= 0.70) {

            factors.add(
                    "High IP risk"
            );
        }

        /*
         * High location risk.
         */
        if (locationRisk instanceof Number
                && ((Number) locationRisk).doubleValue() >= 0.70) {

            factors.add(
                    "High location risk"
            );
        }

        /*
         * High failure risk.
         */
        if (failureRisk instanceof Number
                && ((Number) failureRisk).doubleValue() >= 0.70) {

            factors.add(
                    "High failure risk"
            );
        }

        return factors;
    }

    /*
     * Determines severity from fused score.
     */
    private Severity determineSeverity(
            BigDecimal fusedScore
    ) {

        double score =
                fusedScore.doubleValue();

        /*
         * Critical.
         */
        if (score >=
                alertPolicy
                        .getSeverity()
                        .getCritical()) {

            return Severity.CRITICAL;
        }

        /*
         * High.
         */
        if (score >=
                alertPolicy
                        .getSeverity()
                        .getHigh()) {

            return Severity.HIGH;
        }

        /*
         * Medium.
         */
        if (score >=
                alertPolicy
                        .getSeverity()
                        .getMedium()) {

            return Severity.MEDIUM;
        }

        /*
         * Low.
         */
        return Severity.LOW;
    }

    /*
     * Converts Prediction entity to API response.
     */
    private PredictionResponse toResponse(
            Prediction prediction
    ) {

        return new PredictionResponse(
                prediction.getId(),
                prediction.getEvent().getEventId(),
                prediction.getEntity().getEntityId(),
                prediction.getModelName(),
                prediction.getModelVersion(),
                prediction.getAnomalyScore(),
                prediction.getConfidence(),
                prediction.getFusedScore(),
                prediction.getDecision(),
                prediction.getFeatures(),
                prediction.getCreatedAt()
        );
    }
}