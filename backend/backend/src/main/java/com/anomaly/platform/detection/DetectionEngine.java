package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.service.AuditLogService;
import com.anomaly.platform.service.IncidentService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/*
 * ============================================================
 * THE DETERMINISTIC DETECTION ENGINE
 * ============================================================
 *
 * The one place that decides what happens to a rule's match. Every rule goes
 * through exactly this path, so deduplication, suppression, cooldown,
 * escalation, incident attachment and audit behave identically for all of them -
 * a new rule inherits all of it and can get none of it wrong.
 *
 * Relationship to the ML path: NONE. This never reads a prediction, a score or a
 * model decision, and PredictionService never reads a rule. The two detection
 * paths share only the Alert/Incident/AlertFactor/AuditLog machinery, and a rule
 * alert is distinguishable by `ruleId` being non-null (AlertResponse derives
 * detectionType from exactly that). An ML outage cannot stop a rule firing, and a
 * rule cannot change a score.
 *
 * ------------------------------------------------------------
 * CONCURRENCY
 * ------------------------------------------------------------
 * Preserved from the original implementation, unchanged:
 *
 *   1. The triggering event row is LOCKED FOR UPDATE once per evaluation, before
 *      any rule looks for an existing alert. Two threads processing the same
 *      event (Kafka consumer and an admin replay) therefore serialise here
 *      rather than both deciding "no alert yet" and both inserting one.
 *   2. existsByEvent_IdAndRuleId is the application-level duplicate check.
 *   3. uk_alerts_event_rule (V15) is the DATABASE guarantee behind both: a
 *      unique index on (event_id, rule_id) where rule_id is not null. Even if
 *      the lock were somehow bypassed, the second insert fails rather than
 *      creating a duplicate alert.
 *   4. Incident attachment goes through IncidentService.findOrCreateIncident,
 *      which relies on the incident_key unique constraint for the same reason.
 *
 * None of this depends on a synchronized block or any in-JVM state, so it holds
 * across multiple application instances.
 *
 * ------------------------------------------------------------
 * FAILURE CONTAINMENT
 * ------------------------------------------------------------
 * evaluate() never throws. A bug in one rule must never fail event processing or
 * stop the other rules - each rule is evaluated in its own try/catch, and the
 * whole method has an outer one. EventProcessingService wraps the call as well,
 * because this method is @Transactional and a failed repository call inside it
 * marks the transaction rollback-only, so its commit can still throw after the
 * internal catch.
 */
@Service
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    /** Unchanged from the original implementation: rule alerts carry this policy version. */
    public static final String RULE_POLICY_VERSION = "rules-v1";

    /** alert_factors.factor is VARCHAR(128) (V8__create_alert_factors.sql). */
    public static final int MAX_FACTOR_LENGTH = 128;

    /** Evidence lines kept per alert. The first is always the generated summary. */
    public static final int MAX_FACTORS_PER_ALERT = 6;

    private static final List<AlertStatus> ACTIVE_ALERT_STATUSES =
            List.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING);

    public static final String AUDIT_DETECTION_CREATED = "DETECTION_CREATED";
    public static final String AUDIT_DETECTION_SUPPRESSED = "DETECTION_SUPPRESSED";
    public static final String AUDIT_DETECTION_ESCALATED = "DETECTION_ESCALATED";

    private final RuleRegistry registry;
    private final CorrelationWindowService correlation;
    private final DetectionProperties properties;
    private final EventRepository eventRepository;
    private final AlertRepository alertRepository;
    private final AlertFactorRepository alertFactorRepository;
    private final IncidentService incidentService;
    private final AuditLogService auditLogService;

    public DetectionEngine(
            RuleRegistry registry,
            CorrelationWindowService correlation,
            DetectionProperties properties,
            EventRepository eventRepository,
            AlertRepository alertRepository,
            AlertFactorRepository alertFactorRepository,
            IncidentService incidentService,
            AuditLogService auditLogService
    ) {
        this.registry = registry;
        this.correlation = correlation;
        this.properties = properties;
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.alertFactorRepository = alertFactorRepository;
        this.incidentService = incidentService;
        this.auditLogService = auditLogService;
    }

    public RuleRegistry registry() {
        return registry;
    }

    public DetectionProperties properties() {
        return properties;
    }

    /** What one rule did with one event. Returned for tests and logging; nothing branches on it. */
    public record RuleEvaluation(String ruleId, DetectionOutcome outcome, Severity severity) {
    }

    /*
     * ============================================================
     * ENTRY POINT
     * ============================================================
     * Called once per persisted event, independently of the ML call.
     */
    @Transactional
    public List<RuleEvaluation> evaluate(Event databaseEvent) {

        List<RuleEvaluation> results = new ArrayList<>();

        try {
            if (databaseEvent == null || databaseEvent.getEntity() == null) {
                return results;
            }

            List<DetectionRule> candidates = registry.forEventType(databaseEvent.getEventType());
            if (candidates.isEmpty()) {
                // No rule consumes this event type: no query, no row lock, no cost.
                return results;
            }

            // Disabled rules are reported, not run - and crucially they are decided
            // BEFORE the lock, so turning detection off costs nothing at all rather
            // than still serialising every event on a row lock.
            List<DetectionRule> active = new ArrayList<>(candidates.size());
            for (DetectionRule rule : candidates) {
                if (rule.isEnabled(properties)) {
                    active.add(rule);
                } else {
                    results.add(new RuleEvaluation(rule.id(), DetectionOutcome.NOT_APPLICABLE, null));
                }
            }
            if (active.isEmpty()) {
                return results;
            }

            // One lock for the whole evaluation, taken before any rule checks for
            // an existing alert - see the CONCURRENCY note above.
            lockEvent(databaseEvent);

            for (DetectionRule rule : active) {
                results.add(evaluateOne(rule, databaseEvent));
            }

        } catch (Exception engineFailure) {
            log.error(
                    "Detection engine failed eventId={} entityId={} dbEventId={} - event processing itself is unaffected",
                    databaseEvent == null ? null : databaseEvent.getEventId(),
                    databaseEvent == null || databaseEvent.getEntity() == null
                            ? null : databaseEvent.getEntity().getEntityId(),
                    databaseEvent == null ? null : databaseEvent.getId(),
                    engineFailure
            );
        }

        return results;
    }

    private RuleEvaluation evaluateOne(DetectionRule rule, Event databaseEvent) {
        try {
            if (!rule.isEnabled(properties)) {
                return new RuleEvaluation(rule.id(), DetectionOutcome.NOT_APPLICABLE, null);
            }

            DetectionMatch match = rule.evaluate(new RuleContext(databaseEvent, correlation, properties));
            if (match == null || !match.matched()) {
                DetectionOutcome reason = match == null ? DetectionOutcome.NOT_APPLICABLE : match.noMatchReason();
                return new RuleEvaluation(rule.id(), reason, null);
            }

            return decide(rule, databaseEvent, match);

        } catch (Exception ruleFailure) {
            // One rule's bug must never stop the others or fail the event.
            log.error("Detection rule {} failed for eventId={} - other rules are unaffected",
                    rule.id(), databaseEvent.getEventId(), ruleFailure);
            return new RuleEvaluation(rule.id(), DetectionOutcome.NOT_APPLICABLE, null);
        }
    }

    /*
     * ============================================================
     * WHAT HAPPENS TO A MATCH
     * ============================================================
     *
     * In order, and the order matters:
     *
     *   1. DUPLICATE  - this exact event already raised this rule's alert.
     *      Checked first because a redelivery is not new activity and must not
     *      even be recorded as a suppression.
     *   2. ACTIVE ALERT - an alert for this rule and this suppression key is
     *      still open. Either escalate it (worse evidence, and the rule allows
     *      escalation) or suppress.
     *   3. COOLDOWN - the last alert for this rule and key closed too recently.
     *   4. Otherwise raise a new alert.
     */
    private RuleEvaluation decide(DetectionRule rule, Event databaseEvent, DetectionMatch match) {

        if (alertRepository.existsByEvent_IdAndRuleId(databaseEvent.getId(), rule.id())) {
            return new RuleEvaluation(rule.id(), DetectionOutcome.DUPLICATE, null);
        }

        String entityId = databaseEvent.getEntity().getEntityId();
        DetectionProperties.RuleSettings settings = rule.settings(properties);

        Optional<Alert> active = findActive(rule, entityId, match);
        if (active.isPresent()) {
            Alert existing = active.get();

            if (settings.isEscalate() && SeverityModel.isEscalation(existing.getSeverity(), match.severity())) {
                return escalate(rule, databaseEvent, match, existing);
            }

            recordSuppressed(DetectionOutcome.SUPPRESSED_ACTIVE_ALERT, rule, databaseEvent, existing, match);
            return new RuleEvaluation(rule.id(), DetectionOutcome.SUPPRESSED_ACTIVE_ALERT, null);
        }

        Optional<Alert> cooling = findWithinCooldown(rule, entityId, databaseEvent, match, settings);
        if (cooling.isPresent()) {
            recordSuppressed(DetectionOutcome.SUPPRESSED_COOLDOWN, rule, databaseEvent, cooling.get(), match);
            return new RuleEvaluation(rule.id(), DetectionOutcome.SUPPRESSED_COOLDOWN, null);
        }

        raiseAlert(rule, databaseEvent, match);
        return new RuleEvaluation(rule.id(), DetectionOutcome.DETECTED, match.severity());
    }

    /**
     * The newest still-active alert this match would duplicate.
     *
     * A rule with no suppression key suppresses per (rule, entity) - the
     * historical AUTH_BURST behaviour, using the same repository method it always
     * used. A rule WITH a key (NEW_PROCESS_EXTERNAL_CONNECTION, keyed on the
     * process identity) suppresses only against an active alert for that same
     * key, so a different process on the same host still raises its own alert.
     */
    private Optional<Alert> findActive(DetectionRule rule, String entityId, DetectionMatch match) {
        if (match.suppressionKey() == null) {
            return alertRepository.findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                    entityId, rule.id(), ACTIVE_ALERT_STATUSES);
        }
        List<Alert> candidates = entityScoped(rule)
                ? alertRepository.findByEntity_EntityIdAndRuleIdAndStatusIn(entityId, rule.id(), ACTIVE_ALERT_STATUSES)
                : alertRepository.findByRuleIdAndStatusIn(rule.id(), ACTIVE_ALERT_STATUSES, ACTIVE_ALERT_SCAN);

        return candidates.stream()
                .filter(a -> match.suppressionKey().equals(suppressionKeyOf(rule, a)))
                .findFirst();
    }

    private boolean entityScoped(DetectionRule rule) {
        return !(rule instanceof KeyedSuppression keyed) || keyed.entityScoped();
    }

    /**
     * The suppression key of an ALREADY-STORED alert, recovered from its own
     * triggering event so it can be compared with a new match's key. Only rules
     * that use a key need this, and each states how to rebuild it.
     */
    private String suppressionKeyOf(DetectionRule rule, Alert alert) {
        if (!(rule instanceof KeyedSuppression keyed)) {
            return null;
        }
        Event event = alert.getEvent();
        return event == null ? null : keyed.suppressionKeyOf(event);
    }

    /**
     * A rule whose findings are narrower than "something happened on this
     * entity". It must be able to rebuild the key of a stored alert from that
     * alert's own triggering event, so suppression compares like with like.
     */
    public interface KeyedSuppression {
        String suppressionKeyOf(Event triggeringEvent);

        /**
         * Whether the key is scoped WITHIN one entity (the default) or across
         * them. A source-correlated rule says false: its finding is about a
         * source address that touched many entities, and the alert tracking it
         * is filed against whichever entity happened to trigger it first.
         */
        default boolean entityScoped() {
            return true;
        }
    }

    /** Active alerts scanned when a rule's suppression key is not entity-scoped. */
    private static final org.springframework.data.domain.Pageable ACTIVE_ALERT_SCAN =
            org.springframework.data.domain.PageRequest.of(0, 200,
                    org.springframework.data.domain.Sort.by(org.springframework.data.domain.Sort.Direction.DESC, "createdAt"));

    /**
     * The most recent CLOSED alert for this rule and entity, if it closed inside
     * the configured cooldown. Zero cooldown (the default, and the historical
     * behaviour of both original rules) disables this check entirely.
     */
    private Optional<Alert> findWithinCooldown(DetectionRule rule, String entityId, Event databaseEvent,
                                               DetectionMatch match, DetectionProperties.RuleSettings settings) {
        Duration cooldown = settings.getCooldown();
        if (cooldown == null || cooldown.isZero() || cooldown.isNegative()) {
            return Optional.empty();
        }
        OffsetDateTime notBefore = databaseEvent.getOccurredAt().minus(cooldown);
        return alertRepository
                .findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                        entityId, rule.id(), List.of(AlertStatus.RESOLVED, AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE))
                .filter(a -> {
                    OffsetDateTime closedAt = a.getResolvedAt() != null ? a.getResolvedAt() : a.getUpdatedAt();
                    return closedAt != null && !closedAt.isBefore(notBefore);
                })
                .filter(a -> match.suppressionKey() == null
                        || match.suppressionKey().equals(suppressionKeyOf(rule, a)));
    }

    /*
     * ============================================================
     * RAISE
     * ============================================================
     *
     * The same Alert -> Incident -> AlertFactor -> AuditLog sequence
     * PredictionService.create uses for an ML alert. `prediction` is left null by
     * construction and `decision` is SUSPICIOUS, which the ML path never
     * produces - so a rule alert stays trivially distinguishable.
     */
    private void raiseAlert(DetectionRule rule, Event databaseEvent, DetectionMatch match) {

        EntityProfile entity = databaseEvent.getEntity();

        Alert alert = new Alert();
        alert.setEvent(databaseEvent);
        alert.setEntity(entity);
        alert.setDecision(DecisionState.SUSPICIOUS);
        alert.setSeverity(match.severity());
        alert.setStatus(AlertStatus.OPEN);
        alert.setPolicyVersion(RULE_POLICY_VERSION);
        alert.setRuleId(rule.id());
        alert.setRuleName(rule.name());

        Alert savedAlert = alertRepository.save(alert);

        Incident incident = incidentService.findOrCreateIncident(savedAlert);
        savedAlert.setIncident(incident);
        alertRepository.save(savedAlert);

        List<String> factors = factorsOf(match);
        int rank = 1;
        for (String factor : factors) {
            AlertFactor alertFactor = new AlertFactor();
            alertFactor.setAlert(savedAlert);
            alertFactor.setFactor(factor);
            alertFactor.setRank(rank++);
            alertFactor.setCreatedAt(OffsetDateTime.now());
            alertFactorRepository.save(alertFactor);
        }

        Map<String, Object> details = new LinkedHashMap<>(match.evidence().toAuditDetails());
        details.put("severity", match.severity().name());
        details.put("outcome", DetectionOutcome.DETECTED.name());
        details.put("message", match.message());
        details.put("evidence", factors);
        details.put("eventId", databaseEvent.getEventId());
        details.put("entityId", entity.getEntityId());

        auditLogService.log("system", AUDIT_DETECTION_CREATED, "ALERT", savedAlert.getId(), null, details);

        log.info("Deterministic rule fired ruleId={} entityId={} eventId={} alertId={} severity={}",
                rule.id(), entity.getEntityId(), databaseEvent.getEventId(), savedAlert.getId(), match.severity());
    }

    /*
     * ============================================================
     * ESCALATE
     * ============================================================
     *
     * A continuing condition that got materially worse raises the severity of the
     * alert already tracking it, rather than opening a second alert for the same
     * thing. The new evidence is appended as a further factor and the change is
     * audited, so the escalation is as explainable as the original detection.
     *
     * Only for rules that opt in (detection.rules.<rule>.escalate), and only when
     * the new severity is STRICTLY worse. The two original rules have it off, so
     * their behaviour is byte-for-byte what it was.
     */
    private RuleEvaluation escalate(DetectionRule rule, Event databaseEvent, DetectionMatch match, Alert existing) {

        Severity from = existing.getSeverity();
        existing.setSeverity(match.severity());
        Alert saved = alertRepository.save(existing);

        int nextRank = (int) alertFactorRepository.countByAlert_Id(saved.getId()) + 1;
        if (nextRank <= MAX_FACTORS_PER_ALERT * 3) {
            AlertFactor factor = new AlertFactor();
            factor.setAlert(saved);
            factor.setFactor(truncate("Escalated " + from + " -> " + match.severity() + ": " + match.message()));
            factor.setRank(nextRank);
            factor.setCreatedAt(OffsetDateTime.now());
            alertFactorRepository.save(factor);
        }

        Map<String, Object> details = new LinkedHashMap<>(match.evidence().toAuditDetails());
        details.put("outcome", DetectionOutcome.ESCALATED.name());
        details.put("severityFrom", from == null ? null : from.name());
        details.put("severityTo", match.severity().name());
        details.put("message", match.message());
        details.put("triggeringEventId", databaseEvent.getEventId());

        auditLogService.log("system", AUDIT_DETECTION_ESCALATED, "ALERT", saved.getId(), null, details);

        log.info("Deterministic rule escalated ruleId={} alertId={} {} -> {}",
                rule.id(), saved.getId(), from, match.severity());

        return new RuleEvaluation(rule.id(), DetectionOutcome.ESCALATED, match.severity());
    }

    /*
     * ============================================================
     * SUPPRESS
     * ============================================================
     *
     * Rules run on every processing attempt, so a retried event (while the ML
     * service is unavailable, for instance) reaches this repeatedly. The
     * suppression is recorded ONCE per (alert, rule, triggering event), not once
     * per attempt - preserved from the original implementation.
     *
     * Suppression never discards evidence: the triggering event stays persisted
     * and visible, and the audit row says which alert absorbed it and why.
     */
    private void recordSuppressed(DetectionOutcome outcome, DetectionRule rule, Event triggeringEvent,
                                  Alert existingAlert, DetectionMatch match) {

        if (triggeringEvent.getEventId() != null
                && auditLogService.hasSuppressionRecord(existingAlert.getId(), rule.id(), triggeringEvent.getEventId())) {
            return;
        }

        Map<String, Object> details = new LinkedHashMap<>(match.evidence().toAuditDetails());
        details.put("outcome", outcome.name());
        details.put("suppressedBecauseAlertId", existingAlert.getId().toString());
        details.put("suppressionReason", reasonText(outcome, rule, existingAlert));
        details.put("candidateSeverity", match.severity() == null ? null : match.severity().name());
        details.put("activeAlertSeverity", existingAlert.getSeverity() == null ? null : existingAlert.getSeverity().name());
        details.put("evidence", match.message());

        if (triggeringEvent.getEventId() != null) {
            details.put("triggeringEventId", triggeringEvent.getEventId());
        }
        if (triggeringEvent.getEntity() != null) {
            details.put("entityId", triggeringEvent.getEntity().getEntityId());
        }

        auditLogService.log("system", AUDIT_DETECTION_SUPPRESSED, "ALERT", existingAlert.getId(), null, details);
    }

    private String reasonText(DetectionOutcome outcome, DetectionRule rule, Alert existingAlert) {
        if (outcome == DetectionOutcome.SUPPRESSED_COOLDOWN) {
            return rule.id() + " matched again inside its configured cooldown after alert "
                    + existingAlert.getId() + " closed; no new alert was raised.";
        }
        return rule.id() + " matched again while alert " + existingAlert.getId()
                + " (" + existingAlert.getStatus() + ") is still active for this entity; no new alert was raised.";
    }

    /*
     * ============================================================
     * EVIDENCE AS ALERT FACTORS
     * ============================================================
     *
     * The generated summary first, then the structured detail lines. Every line
     * is truncated to the alert_factors.factor column width BY CONSTRUCTION
     * rather than by trusting a rule never to exceed it - an IPv6 address alone
     * is 45 characters.
     */
    private List<String> factorsOf(DetectionMatch match) {
        DetectionEvidence e = match.evidence();
        List<String> out = new ArrayList<>();
        out.add(truncate(match.message()));

        if (e.count() != null && e.threshold() != null) {
            out.add(truncate("Observed " + e.count() + " against a threshold of " + e.threshold()));
        }
        if (e.distinctTargets() != null) {
            out.add(truncate("Distinct targets: " + e.distinctTargets()));
        }
        if (e.processId() != null) {
            out.add(truncate("Process " + (e.processName() == null ? "pid " + e.processId()
                    : e.processName() + " (pid " + e.processId() + ")")
                    + (e.processCreateTime() == null ? "" : " created " + e.processCreateTime())));
        }
        if (!e.destinations().isEmpty()) {
            out.add(truncate("Destinations: " + String.join(", ", e.destinations())));
        }
        if (!e.contributingSignals().isEmpty()) {
            out.add(truncate("Stages: " + String.join(" -> ", e.contributingSignals())));
        }
        if (e.severityReason() != null) {
            out.add(truncate(e.severityReason()));
        }

        return out.size() > MAX_FACTORS_PER_ALERT ? out.subList(0, MAX_FACTORS_PER_ALERT) : out;
    }

    /** alert_factors.factor is VARCHAR(128) NOT NULL - never let evidence violate that. */
    public static String truncate(String factor) {
        if (factor == null) {
            return "";
        }
        return factor.length() <= MAX_FACTOR_LENGTH ? factor : factor.substring(0, MAX_FACTOR_LENGTH - 3) + "...";
    }

    private void lockEvent(Event databaseEvent) {
        eventRepository.lockForProcessing(databaseEvent.getId());
    }
}
