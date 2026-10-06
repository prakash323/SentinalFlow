package com.anomaly.platform.service;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.RuleRegistry;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.detection.rules.AuthBurstRule;
import com.anomaly.platform.detection.rules.NewProcessExternalConnectionRule;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;

import org.springframework.stereotype.Service;

import java.util.List;

/*
 * ============================================================
 * INDEPENDENT DETERMINISTIC DETECTION - ENTRY POINT
 * ============================================================
 *
 * SentinelFlow's ML path is EventProcessingService -> MlPredictionClient ->
 * PredictionService. If the ML service is down, times out or returns an error,
 * no alert is possible on that path for that event, however obviously suspicious
 * the raw telemetry is. This is the second, independent detection path: it never
 * calls the ML client and is unaffected by its availability.
 *
 * ------------------------------------------------------------
 * WHAT THIS CLASS IS NOW
 * ------------------------------------------------------------
 * A seam, and nothing else. All detection logic lives in
 * com.anomaly.platform.detection:
 *
 *     DetectionRule  ->  RuleContext  ->  DetectionMatch  ->  DetectionEngine
 *                                                              -> AlertService machinery
 *                                                              -> IncidentService
 *
 * This class holds no rule, no threshold and no suppression logic. It exists so
 * that EventProcessingService's collaborator, and the contract that
 * `evaluate(Event)` never throws, are unchanged by the detection rewrite - the
 * pipeline did not have to be touched to gain eight new rules.
 *
 * ------------------------------------------------------------
 * TWO CONSTRUCTORS, DELIBERATELY
 * ------------------------------------------------------------
 * The Spring constructor takes the fully wired DetectionEngine: in production
 * this runs the complete rule set from DetectionConfig.
 *
 * The second constructor builds an engine over ONLY the two original rules
 * (AUTH_BURST and NEW_PROCESS_EXTERNAL_CONNECTION) from bare repositories. It is
 * the backward-compatibility harness: DeterministicRuleServiceTest constructs
 * this service exactly as it did before the rewrite and asserts exactly what it
 * asserted before, so those tests are direct evidence that the re-implemented
 * R001/R002 behave as the originals did - same thresholds, same windows, same
 * suppression, same locking, same audit actions.
 *
 * It is a test seam, not a second production path: nothing in the application
 * calls it, and it contains no logic of its own beyond choosing which two rules
 * to register.
 */
@Service
public class DeterministicRuleService {

    private final DetectionEngine engine;

    /** Production: the fully wired engine with every rule from DetectionConfig. */
    public DeterministicRuleService(DetectionEngine engine) {
        this.engine = engine;
    }

    /**
     * Backward-compatibility seam (see the class comment): an engine over the two
     * original rules only, built from bare repositories with the historical
     * default thresholds.
     */
    public DeterministicRuleService(
            EventRepository eventRepository,
            AlertRepository alertRepository,
            AlertFactorRepository alertFactorRepository,
            IncidentService incidentService,
            AuditLogService auditLogService
    ) {
        DetectionProperties properties = DetectionProperties.defaults();
        this.engine = new DetectionEngine(
                new RuleRegistry(List.of(new AuthBurstRule(), new NewProcessExternalConnectionRule())),
                new CorrelationWindowService(eventRepository),
                properties,
                eventRepository,
                alertRepository,
                alertFactorRepository,
                incidentService,
                auditLogService
        );
    }

    /*
     * ============================================================
     * ENTRY POINT
     * ============================================================
     * Called once per persisted event, independently of the ML call.
     *
     * NEVER THROWS. A rule bug must not affect event processing outcome - the
     * engine catches per rule and again around the whole evaluation, and
     * EventProcessingService wraps this call as a third layer because the
     * engine's method is @Transactional and a failed repository call inside it
     * can still throw at commit.
     */
    public void evaluate(Event databaseEvent) {
        engine.evaluate(databaseEvent);
    }
}
