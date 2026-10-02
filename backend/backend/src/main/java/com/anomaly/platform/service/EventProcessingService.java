package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreatePredictionRequest;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.EventProcessingStatus;
import com.anomaly.platform.kafka.KafkaEvent;
import com.anomaly.platform.ml.MlPredictionClient;
import com.anomaly.platform.ml.MlPredictionRequest;
import com.anomaly.platform.ml.MlPredictionResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class EventProcessingService {

    private static final Logger log = LoggerFactory.getLogger(EventProcessingService.class);

    /*
     * The ML service's own decision is strictly binary (see api.py /predict
     * and src/realtime.py StreamingScorer.process: an alert dict is built
     * only when risk >= threshold, otherwise decision is "NORMAL"). There is
     * no third state to invent here.
     */
    private static final String ML_DECISION_ANOMALOUS = "ANOMALOUS";
    private static final String ML_ATTACK_TYPE_UNCLASSIFIED = "unclassified";

    private final MlPredictionClient mlPredictionClient;
    private final PredictionService predictionService;
    private final EventProcessingLedgerService ledger;
    private final DeterministicRuleService deterministicRuleService;

    public EventProcessingService(
            MlPredictionClient mlPredictionClient,
            PredictionService predictionService,
            EventProcessingLedgerService ledger,
            DeterministicRuleService deterministicRuleService
    ) {
        this.mlPredictionClient = mlPredictionClient;
        this.predictionService = predictionService;
        this.ledger = ledger;
        this.deterministicRuleService = deterministicRuleService;
    }

    /*
     * ============================================================
     * MAIN EVENT PROCESSING PIPELINE
     * ============================================================
     *
     * Deliberately NOT @Transactional at this level.
     *
     * Persisting the event and recording the processing outcome (both via
     * `ledger`, a separate bean with its own @Transactional methods) must
     * each commit independently of whether the ML call and
     * prediction/alert/incident creation (which PredictionService runs
     * atomically on its own) succeed.
     *
     * If this whole method were @Transactional, a failure late in the
     * pipeline (including an ML service outage) would roll back the event
     * insert itself and the failure record we are trying to write - which is
     * exactly how events used to disappear with no trace (Phase 1).
     *
     * If the ML call throws (timeout, connection refused, non-2xx), that
     * exception propagates from this method exactly like any other
     * processing failure: no Prediction row is ever created (nothing is
     * fabricated), the event is marked FAILED with the real error via
     * `ledger`, and the exception continues to propagate so the Kafka
     * consumer's retry/dead-letter handling (KafkaErrorHandlingConfig) can
     * act on it.
     */
    /* What process() did with an event that did not fail. */
    public enum Outcome {
        /** Rules and ML ran; the prediction (and any alert/incident) is persisted. */
        PROCESSED,
        /** Already PROCESSED with a prediction on record - nothing was run again. */
        ALREADY_PROCESSED
    }

    public Outcome process(KafkaEvent event) {

        validate(event);

        Event databaseEvent;

        try {

            databaseEvent = ledger.persistOrLoad(event);

        } catch (Exception persistFailure) {

            ledger.recordUnresolvableFailure(
                    event.eventId(),
                    event.entityId(),
                    persistFailure
            );

            throw persistFailure;
        }

        // Idempotency guard for duplicate delivery and admin replay. PROCESSED
        // is only set after the prediction (and any alert/incident) committed,
        // so such an event is complete. Running it again would feed the
        // stateful ML scorer the same event twice (skewing that entity's
        // history) and re-run the rules (repeat DETECTION_SUPPRESSED audit
        // entries, or a fresh rule alert once the original was resolved).
        // PENDING/FAILED events - and a PROCESSED event with no prediction on
        // record - are incomplete and still take the normal recovery path.
        if (databaseEvent.getProcessingStatus() == EventProcessingStatus.PROCESSED
                && predictionService.hasPrediction(databaseEvent.getId())) {

            log.info(
                    "Event already processed - skipping duplicate delivery/replay eventId={} dbEventId={}",
                    event.eventId(),
                    databaseEvent.getId()
            );
            return Outcome.ALREADY_PROCESSED;
        }

        /*
         * Independent deterministic detection (P1): runs unconditionally,
         * before the ML call and regardless of its outcome. evaluate()
         * never throws (see DeterministicRuleService), so this can neither
         * be skipped by an ML outage nor cause one - the two detection
         * paths are fully independent, as required.
         */
        // evaluate() catches its own failures, but it is @Transactional: a
        // failed repository call inside it marks the transaction
        // rollback-only, so its commit still throws (UnexpectedRollbackException)
        // after the internal catch. Without this second guard that would skip
        // the ML call entirely and leave the event PENDING.
        try {
            deterministicRuleService.evaluate(databaseEvent);
        } catch (Exception ruleFailure) {
            log.error(
                    "Deterministic rule evaluation failed eventId={} dbEventId={} - continuing with ML scoring",
                    event.eventId(),
                    databaseEvent.getId(),
                    ruleFailure
            );
        }

        try {

            MlPredictionResponse mlResponse =
                    mlPredictionClient.predict(toMlRequest(event));

            log.info(
                    "ML prediction received eventId={} entityId={} dbEventId={} riskScore={} decision={} attackType={}",
                    event.eventId(),
                    event.entityId(),
                    databaseEvent.getId(),
                    mlResponse.riskScore(),
                    mlResponse.decision(),
                    mlResponse.attackType()
            );

            createPrediction(
                    databaseEvent,
                    mlResponse
            );

            ledger.markProcessed(databaseEvent.getId());

            log.info(
                    "Event processing succeeded eventId={} entityId={} dbEventId={}",
                    event.eventId(),
                    event.entityId(),
                    databaseEvent.getId()
            );

            return Outcome.PROCESSED;

        } catch (Exception processingFailure) {

            ledger.markFailed(
                    databaseEvent.getId(),
                    event.eventId(),
                    processingFailure
            );

            log.error(
                    "Event processing failed eventId={} entityId={} dbEventId={} reason={}",
                    event.eventId(),
                    event.entityId(),
                    databaseEvent.getId(),
                    processingFailure.getMessage(),
                    processingFailure
            );

            throw processingFailure;
        }
    }

    /*
     * ============================================================
     * BUILD ML REQUEST
     * ============================================================
     *
     * Field-for-field the same envelope EventController/EventService
     * already persist - api.py adapts this into its own canonical schema
     * (api.py:_canonical_event), so nothing SentinelFlow-specific needs to
     * change here when the ML side evolves.
     */
    private MlPredictionRequest toMlRequest(KafkaEvent event) {

        return new MlPredictionRequest(
                event.eventId(),
                event.entityId(),
                event.eventType(),
                event.eventVersion(),
                event.occurredAt(),
                event.source(),
                event.payload()
        );
    }

    /*
     * ============================================================
     * CREATE PREDICTION
     * ============================================================
     *
     * Delegates to PredictionService.create, which is @Transactional and
     * idempotent on (eventId, modelName, modelVersion) - a duplicate
     * delivery of the same Kafka message will not create a duplicate
     * prediction or a duplicate alert. If this throws, no prediction row
     * is committed (nothing is fabricated) and process() records the
     * failure via the ledger.
     *
     * The ML model determines anomalyScore/confidence/decision/attackType;
     * severity and whether an alert is actually raised remain entirely
     * PredictionService's job (fusedScore vs. anomaly.alert-policy config) -
     * ML detection and Spring Boot operational policy stay separate, as
     * before.
     */
    private void createPrediction(
            Event databaseEvent,
            MlPredictionResponse mlResponse
    ) {

        CreatePredictionRequest request =
                new CreatePredictionRequest(
                        databaseEvent.getId(),

                        mlResponse.modelName(),

                        mlResponse.modelVersion(),

                        mlResponse.anomalyScore(),

                        mlResponse.confidence(),

                        /*
                         * fusedScore: the ML ensemble (baseline + isolation
                         * forest + sequence autoencoder) already fuses its
                         * three internal signals into one anomalyScore
                         * (src/detect.py Detector.fuse_single). Spring Boot
                         * does not combine multiple independent model
                         * outputs today, so the single ML score is the
                         * fused score - same convention the placeholder
                         * scorer used.
                         */
                        mlResponse.anomalyScore(),

                        mapDecision(mlResponse),

                        buildFeatures(mlResponse)
                );

        predictionService.create(
                request
        );
    }

    /*
     * ============================================================
     * ML -> SPRING DecisionState MAPPING (documented explicitly)
     * ============================================================
     *
     *   ML decision "NORMAL"                                  -> NORMAL
     *   ML decision "ANOMALOUS", attackType is a real class    -> KNOWN_ANOMALY
     *   ML decision "ANOMALOUS", attackType null/"unclassified" -> UNKNOWN_ANOMALY
     *
     * DecisionState.SUSPICIOUS and DecisionState.ERROR are never produced
     * here: the ML model's own output is strictly binary (see
     * ML_DECISION_ANOMALOUS above), and a call failure never reaches this
     * method at all - process() records it via the ledger and rethrows
     * before createPrediction() is ever called, so no Prediction row (and
     * therefore no ERROR-decision row) is ever fabricated for a failed
     * call.
     */
    private DecisionState mapDecision(MlPredictionResponse mlResponse) {

        if (!ML_DECISION_ANOMALOUS.equalsIgnoreCase(mlResponse.decision())) {
            return DecisionState.NORMAL;
        }

        String attackType = mlResponse.attackType();

        if (attackType == null
                || attackType.isBlank()
                || ML_ATTACK_TYPE_UNCLASSIFIED.equalsIgnoreCase(attackType)) {

            return DecisionState.UNKNOWN_ANOMALY;
        }

        return DecisionState.KNOWN_ANOMALY;
    }

    /*
     * ============================================================
     * BUILD FEATURE MAP
     * ============================================================
     *
     * Prediction.features is a generic JSONB map - the real ML
     * explainability output (attack type, human-readable reason, top
     * factors, raw 0-100 risk score) is stored here rather than requiring
     * a schema migration for fields the existing column can already hold.
     */
    private Map<String, Object> buildFeatures(
            MlPredictionResponse mlResponse
    ) {

        Map<String, Object> result =
                new HashMap<>();

        result.put(
                "mlDecision",
                mlResponse.decision()
        );

        result.put(
                "riskScore",
                mlResponse.riskScore()
        );

        result.put(
                "attackType",
                mlResponse.attackType()
        );

        result.put(
                "reason",
                mlResponse.reason()
        );

        result.put(
                "factors",
                mlResponse.factors() == null
                        ? List.of()
                        : mlResponse.factors()
        );

        return result;
    }

    /*
     * ============================================================
     * VALIDATION
     * ============================================================
     */

    private void validate(
            KafkaEvent event
    ) {

        if (event.eventId() == null
                || event.eventId().isBlank()) {

            throw new IllegalArgumentException(
                    "Event ID is required"
            );
        }

        if (event.entityId() == null
                || event.entityId().isBlank()) {

            throw new IllegalArgumentException(
                    "Entity ID is required"
            );
        }

        if (event.eventType() == null
                || event.eventType().isBlank()) {

            throw new IllegalArgumentException(
                    "Event type is required"
            );
        }

        if (event.occurredAt() == null) {

            throw new IllegalArgumentException(
                    "Occurred time is required"
            );
        }
    }
}
