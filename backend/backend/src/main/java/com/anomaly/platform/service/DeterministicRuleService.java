package com.anomaly.platform.service;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/*
 * ============================================================
 * INDEPENDENT DETERMINISTIC DETECTION (P1)
 * ============================================================
 *
 * SentinelFlow's only detection path today is EventProcessingService ->
 * MlPredictionClient -> PredictionService (see those classes) - if the ML
 * service is down, times out, or returns an error, EventProcessingService
 * records the failure and NO alert is possible for that event, regardless
 * of how obviously suspicious the raw telemetry is. This service is a
 * second, independent detection path that never calls the ML client and
 * is unaffected by its availability.
 *
 * Deliberately small: two rules, both directly evidenced by real data this
 * platform already ingests (see the Correlation Consumption v1/v2 phases
 * and the physical-collector's own LOGIN payload). No rules framework, no
 * DSL, no new tables beyond the two nullable columns Alert already gained
 * (rule_id, rule_name - see V13__add_alert_rule_fields.sql). Evaluation
 * happens in EventProcessingService.process(), in its own try/catch, so a
 * bug here can never fail event processing or affect the ML path.
 *
 * A firing rule reuses the exact same Alert/Incident/AlertFactor/AuditLog
 * machinery a ML-driven alert uses (see PredictionService.create) - the
 * only difference is `prediction` stays null and `ruleId`/`ruleName` are
 * set, so every existing alert/incident list, filter, and lifecycle
 * transition already works for a rule-raised alert with no further change.
 * decision uses DecisionState.SUSPICIOUS, which the ML path never produces
 * (see EventProcessingService's own mapping comment) - a rule alert is
 * therefore trivially distinguishable from an ML alert by decision alone,
 * and unambiguously by detectionType (see AlertResponse).
 */
@Service
public class DeterministicRuleService {

    private static final Logger log = LoggerFactory.getLogger(DeterministicRuleService.class);

    private static final String RULE_POLICY_VERSION = "rules-v1";

    // ---- AUTH_BURST -------------------------------------------------
    private static final String RULE_AUTH_BURST = "AUTH_BURST";
    private static final String RULE_AUTH_BURST_NAME = "Repeated failed login attempts";
    private static final int AUTH_BURST_WINDOW_MINUTES = 5;
    private static final int AUTH_BURST_THRESHOLD = 5;
    private static final int AUTH_BURST_HIGH_THRESHOLD = 10;

    // ---- NEW_PROCESS_EXTERNAL_CONNECTION ----------------------------
    private static final String RULE_NEW_PROCESS_CONNECTION = "NEW_PROCESS_EXTERNAL_CONNECTION";
    private static final String RULE_NEW_PROCESS_CONNECTION_NAME =
            "New process established a non-loopback network connection";
    private static final int NEW_PROCESS_CONNECTION_RECENCY_MINUTES = 5;

    private static final List<AlertStatus> ACTIVE_ALERT_STATUSES =
            List.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING);

    private final EventRepository eventRepository;
    private final AlertRepository alertRepository;
    private final AlertFactorRepository alertFactorRepository;
    private final IncidentService incidentService;
    private final AuditLogService auditLogService;

    public DeterministicRuleService(
            EventRepository eventRepository,
            AlertRepository alertRepository,
            AlertFactorRepository alertFactorRepository,
            IncidentService incidentService,
            AuditLogService auditLogService
    ) {
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.alertFactorRepository = alertFactorRepository;
        this.incidentService = incidentService;
        this.auditLogService = auditLogService;
    }

    /*
     * ============================================================
     * ENTRY POINT
     * ============================================================
     * Called once per persisted event, independent of the ML call. Never
     * throws - a rule bug must never affect event processing outcome (see
     * EventProcessingService.process, which wraps this in its own
     * try/catch as a second layer of the same guarantee).
     */
    @Transactional
    public void evaluate(Event databaseEvent) {

        try {

            String eventType = databaseEvent.getEventType();

            if ("LOGIN".equals(eventType)) {
                lockEvent(databaseEvent);
                evaluateAuthBurst(databaseEvent);
            } else if ("NETWORK_CONNECTION".equals(eventType)) {
                lockEvent(databaseEvent);
                evaluateNewProcessExternalConnection(databaseEvent);
            }

        } catch (Exception ruleFailure) {

            log.error(
                    "Deterministic rule evaluation failed eventId={} entityId={} dbEventId={} - "
                            + "event processing itself is unaffected",
                    databaseEvent.getEventId(),
                    databaseEvent.getEntity() == null ? null : databaseEvent.getEntity().getEntityId(),
                    databaseEvent.getId(),
                    ruleFailure
            );
        }
    }

    /*
     * ============================================================
     * RULE 1: AUTH_BURST
     * ============================================================
     * Fires on a LOGIN event whose own payload reports loginSuccess=false,
     * once the count of such failures for this entity within a short
     * window reaches AUTH_BURST_THRESHOLD. Uses only the loginSuccess
     * field the canonical LOGIN payload already carries (see the
     * simulator's and the physical collector's own LOGIN payload
     * vocabulary) - nothing is fabricated, and this never fires for the
     * physical collector today, since its LOGIN payload has no failure
     * concept (psutil.users() can only observe an already-active session -
     * see session_poller.py). Suppressed (not re-fired) while a previous
     * AUTH_BURST alert for this entity is still open/acknowledged/
     * investigating, so a continuing burst raises one alert, not one per
     * failed attempt.
     */
    private void evaluateAuthBurst(Event databaseEvent) {

        Object loginSuccess = databaseEvent.getPayload().get("loginSuccess");

        if (!Boolean.FALSE.equals(loginSuccess)) {
            return;
        }

        EntityProfile entity = databaseEvent.getEntity();
        String entityId = entity.getEntityId();

        OffsetDateTime windowStart =
                databaseEvent.getOccurredAt().minus(Duration.ofMinutes(AUTH_BURST_WINDOW_MINUTES));

        List<Event> recentLogins = eventRepository.findByEntity_EntityIdAndEventType(
                entityId,
                "LOGIN",
                PageRequest.of(0, 200, Sort.by(Sort.Direction.DESC, "occurredAt"))
        ).getContent();

        long failureCount = recentLogins.stream()
                .filter(e -> !e.getOccurredAt().isBefore(windowStart))
                .filter(e -> !e.getOccurredAt().isAfter(databaseEvent.getOccurredAt()))
                .filter(e -> Boolean.FALSE.equals(e.getPayload().get("loginSuccess")))
                .count();

        if (failureCount < AUTH_BURST_THRESHOLD) {
            return;
        }

        if (alertRepository.existsByEvent_IdAndRuleId(databaseEvent.getId(), RULE_AUTH_BURST)) {
            return;
        }

        Optional<Alert> activeExisting = alertRepository
                .findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                        entityId, RULE_AUTH_BURST, ACTIVE_ALERT_STATUSES);

        if (activeExisting.isPresent()) {
            recordSuppressed(RULE_AUTH_BURST, databaseEvent, activeExisting.get(),
                    failureCount + " failed login attempts observed for " + entityId
                            + " within " + AUTH_BURST_WINDOW_MINUTES + " minutes");
            return;
        }

        Severity severity = failureCount >= AUTH_BURST_HIGH_THRESHOLD ? Severity.HIGH : Severity.MEDIUM;

        String reason = truncateFactor(
                failureCount + " failed login attempts for " + entityId
                        + " within " + AUTH_BURST_WINDOW_MINUTES + "m (threshold " + AUTH_BURST_THRESHOLD + ")."
        );

        raiseAlert(
                databaseEvent,
                entity,
                RULE_AUTH_BURST,
                RULE_AUTH_BURST_NAME,
                severity,
                List.of(reason)
        );
    }

    /*
     * ============================================================
     * RULE 2: NEW_PROCESS_EXTERNAL_CONNECTION
     * ============================================================
     * Fires on a NETWORK_CONNECTION event that correlates - by the exact
     * same (pid, processCreateTime == PROCESS_START.occurredAt) identity
     * Correlation Consumption already established, no time tolerance - to
     * a PROCESS_START seen within the last NEW_PROCESS_CONNECTION_RECENCY_
     * MINUTES. "Newly created" is the recency bound: without it, any
     * process's connection would qualify, which is not a meaningful
     * signal. Neutral, evidence-based naming only - this is an observation
     * ("established a network connection shortly after creation"), never
     * a verdict ("malware").
     */
    private void evaluateNewProcessExternalConnection(Event databaseEvent) {

        Map<String, Object> payload = databaseEvent.getPayload();

        Object pidRaw = payload.get("pid");
        Object processCreateTimeRaw = payload.get("processCreateTime");
        Object remoteAddress = payload.get("remoteAddress");

        if (!(pidRaw instanceof Number) || !(processCreateTimeRaw instanceof String) || remoteAddress == null) {
            return;
        }

        String remoteAddressStr = String.valueOf(remoteAddress);
        if (isLoopback(remoteAddressStr)) {
            return;
        }

        long pid = ((Number) pidRaw).longValue();
        String processCreateTime = (String) processCreateTimeRaw;

        EntityProfile entity = databaseEvent.getEntity();
        String entityId = entity.getEntityId();

        List<Event> recentProcessStarts = eventRepository.findByEntity_EntityIdAndEventType(
                entityId,
                "PROCESS_START",
                PageRequest.of(0, 200, Sort.by(Sort.Direction.DESC, "occurredAt"))
        ).getContent();

        Event correlatedProcessStart = recentProcessStarts.stream()
                .filter(e -> {
                    Object p = e.getPayload().get("pid");
                    return (p instanceof Number) && ((Number) p).longValue() == pid;
                })
                .filter(e -> processCreateTime.equals(formatOccurredAt(e)))
                .findFirst()
                .orElse(null);

        if (correlatedProcessStart == null) {
            return;
        }

        Duration sinceCreation = Duration.between(
                correlatedProcessStart.getOccurredAt(),
                databaseEvent.getOccurredAt()
        );

        if (sinceCreation.isNegative()
                || sinceCreation.compareTo(Duration.ofMinutes(NEW_PROCESS_CONNECTION_RECENCY_MINUTES)) > 0) {
            return;
        }

        if (alertRepository.existsByEvent_IdAndRuleId(databaseEvent.getId(), RULE_NEW_PROCESS_CONNECTION)) {
            return;
        }

        Object processName = correlatedProcessStart.getPayload().get("processName");

        // One alert per new process, not one per connection: a freshly
        // started browser or updater routinely opens dozens of connections
        // in its first minutes, and each used to raise its own alert (27
        // OPEN alerts for a single pid were observed on the physical host).
        // Same suppression semantics as AUTH_BURST, scoped to this exact
        // process identity (pid + processCreateTime) - a different new
        // process still raises its own alert.
        Optional<Alert> activeForSameProcess = alertRepository
                .findByEntity_EntityIdAndRuleIdAndStatusIn(
                        entityId, RULE_NEW_PROCESS_CONNECTION, ACTIVE_ALERT_STATUSES)
                .stream()
                .filter(a -> isSameProcess(a.getEvent(), pid, processCreateTime))
                .findFirst();

        if (activeForSameProcess.isPresent()) {
            recordSuppressed(RULE_NEW_PROCESS_CONNECTION, databaseEvent, activeForSameProcess.get(),
                    "Process " + (processName != null ? processName : "pid " + pid)
                            + " connected to " + remoteAddressStr
                            + " while an earlier alert for the same process is still active");
            return;
        }

        // alert_factors.factor is VARCHAR(128) (see V8__create_alert_factors.sql)
        // - kept short by construction rather than relying on the caller to
        // never exceed it (an IPv6 remoteAddress alone can be 45 chars).
        String reason = truncateFactor(
                "Process " + (processName != null ? processName : "pid " + pid)
                        + " connected to " + remoteAddressStr
                        + " " + sinceCreation.toMinutes() + "m after creation."
        );

        raiseAlert(
                databaseEvent,
                entity,
                RULE_NEW_PROCESS_CONNECTION,
                RULE_NEW_PROCESS_CONNECTION_NAME,
                Severity.MEDIUM,
                List.of(reason)
        );
    }

    // processCreateTime is stored on NETWORK_CONNECTION as an ISO-8601
    // string (see the collector's iso_utc()); PROCESS_START.occurredAt is a
    // Java OffsetDateTime read back from the same jsonb-adjacent column -
    // format it the same way for an exact string comparison, matching
    // frontend/src/utils/relatedActivity.ts's own rule 1 semantics.
    private String formatOccurredAt(Event event) {
        return event.getOccurredAt()
                .withOffsetSameInstant(java.time.ZoneOffset.UTC)
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));
    }

    // alert_factors.factor is VARCHAR(128) NOT NULL - never let a rule's
    // evidence string violate that constraint, regardless of how long an
    // entityId, address, or process name happens to be.
    private String truncateFactor(String factor) {
        return factor.length() <= 128 ? factor : factor.substring(0, 125) + "...";
    }

    private boolean isSameProcess(Event alertEvent, long pid, String processCreateTime) {
        if (alertEvent == null || alertEvent.getPayload() == null) {
            return false;
        }
        Object p = alertEvent.getPayload().get("pid");
        return (p instanceof Number) && ((Number) p).longValue() == pid
                && processCreateTime.equals(alertEvent.getPayload().get("processCreateTime"));
    }

    private boolean isLoopback(String address) {
        return address.startsWith("127.") || "::1".equals(address) || "localhost".equalsIgnoreCase(address);
    }

    /*
     * ============================================================
     * SHARED ALERT-RAISING PATH
     * ============================================================
     * Reuses the exact same Alert -> Incident -> AlertFactor -> AuditLog
     * sequence PredictionService.create uses for an ML-driven alert - see
     * that method's own STEP 5-7. prediction is left null by construction
     * (never set on this Alert).
     */
    /*
     * The same event can be evaluated by two threads at once (Kafka consumer
     * and an admin replay). Both would see "no alert yet" and both insert one.
     * Locking the event row for the rest of this transaction makes the second
     * evaluation wait and then find the first one's alert, so the existing
     * existsByEvent_IdAndRuleId / suppression checks stay the single place
     * that decides. uk_alerts_event_rule (V15) backs this up in the database.
     */
    private void lockEvent(Event databaseEvent) {
        eventRepository.lockForProcessing(databaseEvent.getId());
    }

    private void raiseAlert(
            Event databaseEvent,
            EntityProfile entity,
            String ruleId,
            String ruleName,
            Severity severity,
            List<String> evidence
    ) {

        Alert alert = new Alert();
        alert.setEvent(databaseEvent);
        alert.setEntity(entity);
        alert.setDecision(DecisionState.SUSPICIOUS);
        alert.setSeverity(severity);
        alert.setStatus(AlertStatus.OPEN);
        alert.setPolicyVersion(RULE_POLICY_VERSION);
        alert.setRuleId(ruleId);
        alert.setRuleName(ruleName);

        Alert savedAlert = alertRepository.save(alert);

        Incident incident = incidentService.findOrCreateIncident(savedAlert);
        savedAlert.setIncident(incident);
        alertRepository.save(savedAlert);

        int rank = 1;
        for (String factor : evidence) {
            AlertFactor alertFactor = new AlertFactor();
            alertFactor.setAlert(savedAlert);
            alertFactor.setFactor(factor);
            alertFactor.setRank(rank++);
            alertFactor.setCreatedAt(OffsetDateTime.now());
            alertFactorRepository.save(alertFactor);
        }

        recordDetectionCreated(savedAlert, ruleId, ruleName, evidence);

        log.info(
                "Deterministic rule fired ruleId={} entityId={} eventId={} alertId={} severity={}",
                ruleId,
                entity.getEntityId(),
                databaseEvent.getEventId(),
                savedAlert.getId(),
                severity
        );
    }

    private void recordDetectionCreated(Alert alert, String ruleId, String ruleName, List<String> evidence) {

        Map<String, Object> details = new HashMap<>();
        details.put("ruleId", ruleId);
        details.put("ruleName", ruleName);
        details.put("severity", alert.getSeverity().name());
        details.put("evidence", evidence);

        if (alert.getEvent() != null) {
            details.put("eventId", alert.getEvent().getEventId());
        }
        if (alert.getEntity() != null) {
            details.put("entityId", alert.getEntity().getEntityId());
        }

        auditLogService.log(
                "system",
                "DETECTION_CREATED",
                "ALERT",
                alert.getId(),
                null,
                details
        );
    }

    private void recordSuppressed(String ruleId, Event triggeringEvent, Alert existingAlert, String evidence) {

        // Rules run on every processing attempt, so a retried event (e.g. while
        // the ML service is unavailable) reaches this again: record the
        // suppression once per (alert, rule, triggering event), not per attempt.
        if (triggeringEvent.getEventId() != null
                && auditLogService.hasSuppressionRecord(existingAlert.getId(), ruleId, triggeringEvent.getEventId())) {
            return;
        }

        Map<String, Object> details = new HashMap<>();
        details.put("ruleId", ruleId);
        details.put("suppressedBecauseAlertId", existingAlert.getId().toString());
        details.put("evidence", evidence);

        if (triggeringEvent.getEventId() != null) {
            details.put("triggeringEventId", triggeringEvent.getEventId());
        }
        if (triggeringEvent.getEntity() != null) {
            details.put("entityId", triggeringEvent.getEntity().getEntityId());
        }

        // Auditable, non-destructive: the triggering event itself remains
        // persisted and visible (see Correlation Consumption's Related
        // Activity) - suppression only means "no second alert", never
        // "evidence discarded".
        auditLogService.log(
                "system",
                "DETECTION_SUPPRESSED",
                "ALERT",
                existingAlert.getId(),
                null,
                details
        );
    }
}
