package com.anomaly.platform.service;

import com.anomaly.platform.dto.IncidentAlertResponse;
import com.anomaly.platform.dto.IncidentResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.exception.InvalidStatusTransitionException;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.security.CurrentActor;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.IncidentRepository;

import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final AlertRepository alertRepository;
    private final AuditLogService auditLogService;
    private final TransactionTemplate newIncidentTransaction;

    public IncidentService(
            IncidentRepository incidentRepository,
            AlertRepository alertRepository,
            AuditLogService auditLogService,
            PlatformTransactionManager transactionManager
    ) {
        this.incidentRepository = incidentRepository;
        this.alertRepository = alertRepository;
        this.auditLogService = auditLogService;

        /*
         * The insert attempt below runs in its OWN transaction, isolated
         * from whatever transaction the caller (PredictionService) is
         * already in. See findOrCreateIncident for why.
         */
        this.newIncidentTransaction = new TransactionTemplate(transactionManager);
        this.newIncidentTransaction.setPropagationBehavior(
                TransactionDefinition.PROPAGATION_REQUIRES_NEW
        );
    }

    /*
     * ============================================================
     * AUTOMATIC INCIDENT CREATION
     * ============================================================
     *
     * incident_key has a DB-level UNIQUE constraint (see
     * V6__create_incidents.sql), so two concurrent calls racing on the
     * same key cannot both succeed at the database. This method relies on
     * that guarantee rather than any in-JVM lock: the loser's insert fails
     * with DataIntegrityViolationException, and it simply re-reads the row
     * the winner just committed - correct no matter how many application
     * instances or threads are calling this concurrently.
     */

    @Transactional
    public Incident findOrCreateIncident(
            Alert alert
    ) {

        EntityProfile entity =
                alert.getEntity();

        String eventType =
                alert.getEvent() != null
                        ? alert.getEvent().getEventType()
                        : "UNKNOWN";

        String baseIncidentKey =
                entity.getEntityId()
                        + ":"
                        + eventType;

        Incident existing =
                incidentRepository
                        .findByIncidentKey(
                                baseIncidentKey
                        )
                        .orElse(null);

        /*
         * Reuse active incident.
         */
        if (existing != null
                && (existing.getStatus() == IncidentStatus.OPEN
                || existing.getStatus() == IncidentStatus.INVESTIGATING)) {

            return existing;
        }

        /*
         * The base-key incident is missing or finished. Once one has been
         * resolved/closed, later incidents for the same entity and event
         * type carry a timestamp suffix - so an ACTIVE follow-up incident
         * lives under a suffixed key, not the base key. Look for it before
         * creating another one; otherwise every further alert would open
         * its own brand-new incident.
         */
        String familyPrefix = baseIncidentKey + ":";

        List<Incident> activeFollowUps =
                incidentRepository.findActiveByKeyFamily(
                        baseIncidentKey,
                        familyPrefix,
                        familyPrefix.length(),
                        List.of(IncidentStatus.OPEN, IncidentStatus.INVESTIGATING),
                        PageRequest.of(0, 1)
                );

        if (activeFollowUps != null && !activeFollowUps.isEmpty()) {
            return activeFollowUps.get(0);
        }

        /*
         * If the old incident is RESOLVED/CLOSED,
         * create a new unique incident.
         */
        String incidentKey =
                baseIncidentKey;

        if (existing != null) {

            incidentKey =
                    baseIncidentKey
                            + ":"
                            + System.currentTimeMillis();
        }

        String summary =
                "Anomalous "
                        + eventType
                        + " activity detected for entity "
                        + entity.getEntityId();

        final String finalIncidentKey = incidentKey;

        /*
         * The insert runs in a REQUIRES_NEW transaction rather than this
         * method's own transaction. A unique-constraint violation aborts
         * the whole enclosing Postgres transaction - not just the failed
         * statement - so catching the Java exception alone would not be
         * enough to keep this method's own transaction usable afterwards.
         * Isolating the insert means a losing thread's failure rolls back
         * only that inner transaction; this method's (and its caller's)
         * transaction is never touched by the failure and can safely go
         * on to re-read whichever row the winner committed.
         */
        try {

            Incident savedIncident =
                    insertIncident(
                            incidentKey,
                            entity,
                            summary
                    );

            recordIncidentCreation(
                    savedIncident
            );

            return savedIncident;

        } catch (DataIntegrityViolationException raceLost) {

            return incidentRepository
                    .findByIncidentKey(finalIncidentKey)
                    .orElseThrow(() -> new IllegalStateException(
                            "Incident insert conflicted on key "
                                    + finalIncidentKey
                                    + " but no incident with that key exists",
                            raceLost
                    ));
        }
    }

    /*
     * ============================================================
     * INSERT A NEW INCIDENT IN AN ISOLATED TRANSACTION
     * ============================================================
     */

    private Incident insertIncident(
            String incidentKey,
            EntityProfile entity,
            String summary
    ) {

        return newIncidentTransaction.execute(status -> {

            Incident incident = new Incident();

            incident.setIncidentKey(incidentKey);
            incident.setEntity(entity);
            incident.setStatus(IncidentStatus.OPEN);
            incident.setSummary(summary);

            /*
             * saveAndFlush (not save) so the unique-constraint violation
             * surfaces here, inside this isolated transaction, instead of
             * being deferred to a later flush the caller doesn't control.
             */
            return incidentRepository.saveAndFlush(incident);
        });
    }

    /*
     * ============================================================
     * AUDIT INCIDENT CREATION
     * ============================================================
     */

    private void recordIncidentCreation(
            Incident incident
    ) {

        Map<String, Object> details =
                new HashMap<>();

        details.put(
                "status",
                incident.getStatus().name()
        );

        details.put(
                "incidentKey",
                incident.getIncidentKey()
        );

        if (incident.getEntity() != null) {

            details.put(
                    "entityId",
                    incident.getEntity().getEntityId()
            );
        }

        auditLogService.log(
                "system",
                "INCIDENT_CREATED",
                "INCIDENT",
                incident.getId(),
                null,
                details
        );
    }

    /*
     * ============================================================
     * LIST INCIDENTS
     * ============================================================
     */

    @Transactional(readOnly = true)
    public PageResponse<IncidentResponse> list(
            IncidentStatus status,
            String entityId,
            String source,
            int page,
            int size
    ) {

        Pageable pageable =
                PageRequest.of(
                        Math.max(page, 0),
                        Math.min(
                                Math.max(size, 1),
                                100
                        ),
                        Sort.by(
                                Sort.Direction.DESC,
                                "createdAt"
                        )
                );

        Specification<Incident> spec = Specification.where(null);

        if (status != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("status"), status));
        }

        if (entityId != null && !entityId.isBlank()) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("entity").get("entityId"), entityId.trim()));
        }

        /*
         * Incident has no source column of its own (see Incident entity)
         * and can genuinely have alerts from more than one source (its
         * correlation key is entityId:eventType, not source - confirmed
         * against live data). "Matches source X" therefore means "has at
         * least one alert whose event came from source X", expressed as
         * an EXISTS subquery against Alert - no entity mapping change
         * needed, since Alert already has both `incident` and `event`.
         */
        if (source != null && !source.isBlank()) {
            String trimmedSource = source.trim();
            spec = spec.and((root, query, cb) -> {
                Subquery<UUID> sub = query.subquery(UUID.class);
                Root<Alert> alertRoot = sub.from(Alert.class);
                sub.select(alertRoot.get("id"));
                sub.where(
                        cb.equal(alertRoot.get("incident"), root),
                        cb.equal(alertRoot.get("event").get("source"), trimmedSource)
                );
                return cb.exists(sub);
            });
        }

        Page<Incident> incidents =
                incidentRepository.findAll(spec, pageable);

        List<UUID> ids = incidents.getContent()
                .stream()
                .map(Incident::getId)
                .toList();

        Map<UUID, Object[]> rollup = rollupFor(ids);
        Map<UUID, List<String>> sources = sourcesFor(ids);

        return PageResponse.from(
                incidents.map(i -> toResponse(
                        i,
                        rollup.get(i.getId()),
                        sources.getOrDefault(i.getId(), List.of())
                ))
        );
    }

    /*
     * ============================================================
     * GET SINGLE INCIDENT
     * ============================================================
     */

    @Transactional(readOnly = true)
    public IncidentResponse get(
            UUID id
    ) {

        Incident incident =
                incidentRepository
                        .findById(id)
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Incident not found: "
                                                + id
                                )
                        );

        return toResponse(
                incident
        );
    }

    /*
     * ============================================================
     * GET ALERTS BELONGING TO INCIDENT
     * ============================================================
     */

    @Transactional(readOnly = true)
    public List<IncidentAlertResponse> getAlerts(
            UUID incidentId
    ) {

        /*
         * Verify incident exists.
         */
        incidentRepository
                .findById(incidentId)
                .orElseThrow(() ->
                        new NotFoundException(
                                "Incident not found: "
                                        + incidentId
                        )
                );

        /*
         * Find all alerts belonging to incident.
         */
        List<Alert> alerts =
                alertRepository
                        .findByIncident_IdOrderByCreatedAtDesc(
                                incidentId
                        );

        /*
         * Convert to response.
         */
        return alerts
                .stream()
                .map(this::toIncidentAlertResponse)
                .toList();
    }

    /*
     * ============================================================
     * UPDATE INCIDENT STATUS
     * ============================================================
     */

    @Transactional
    public IncidentResponse updateStatus(
            UUID id,
            IncidentStatus next
    ) {

        Incident incident =
                incidentRepository
                        .findById(id)
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Incident not found: "
                                                + id
                                )
                        );

        IncidentStatus previous =
                incident.getStatus();

        /*
         * Check transition.
         */
        if (!allowed(
                previous,
                next
        )) {

            throw new InvalidStatusTransitionException(
                    previous
                            + " -> "
                            + next
                            + " is not allowed"
            );
        }

        /*
         * Same status does not need
         * another audit entry.
         */
        if (previous == next) {

            return toResponse(
                    incident
            );
        }

        /*
         * Update incident status.
         */
        incident.setStatus(
                next
        );

        /*
         * Set closed timestamp when incident
         * becomes RESOLVED or CLOSED.
         */
        if (next == IncidentStatus.RESOLVED
                || next == IncidentStatus.CLOSED) {

            incident.setClosedAt(
                    OffsetDateTime.now()
            );

        } else {

            /*
             * Active incidents should not have
             * a closed timestamp.
             */
            incident.setClosedAt(
                    null
            );
        }

        /*
         * Save incident first. saveAndFlush so a concurrent conflicting
         * update on this same incident (see Incident.version) is detected
         * here rather than silently lost - same reasoning as
         * AlertService.updateStatus.
         */
        Incident savedIncident =
                incidentRepository.saveAndFlush(
                        incident
                );

        /*
         * Audit incident status change.
         */
        recordIncidentStatusChange(
                savedIncident,
                previous,
                next
        );

        /*
         * Synchronize related alerts.
         */
        synchronizeAlerts(
                savedIncident
        );

        return toResponse(
                savedIncident
        );
    }

    /*
     * ============================================================
     * AUDIT INCIDENT STATUS CHANGE
     * ============================================================
     */

    private void recordIncidentStatusChange(
            Incident incident,
            IncidentStatus previous,
            IncidentStatus next
    ) {

        Map<String, Object> details =
                new HashMap<>();

        details.put(
                "fromStatus",
                previous.name()
        );

        details.put(
                "toStatus",
                next.name()
        );

        details.put(
                "incidentKey",
                incident.getIncidentKey()
        );

        if (incident.getEntity() != null) {

            details.put(
                    "entityId",
                    incident.getEntity().getEntityId()
            );
        }

        auditLogService.log(
                CurrentActor.name(),
                "STATUS_CHANGED",
                "INCIDENT",
                incident.getId(),
                null,
                details
        );
    }

    /*
     * ============================================================
     * SYNCHRONIZE ALERTS WITH INCIDENT
     * ============================================================
     */

    private void synchronizeAlerts(
            Incident incident
    ) {

        /*
         * Get all alerts belonging to this incident.
         */
        List<Alert> alerts =
                alertRepository
                        .findByIncident_IdOrderByCreatedAtDesc(
                                incident.getId()
                        );

        /*
         * Incident is RESOLVED.
         *
         * Active alerts become RESOLVED.
         */
        if (incident.getStatus()
                == IncidentStatus.RESOLVED) {

            for (Alert alert : alerts) {

                if (isActiveAlert(
                        alert.getStatus()
                )) {

                    AlertStatus previous =
                            alert.getStatus();

                    alert.setStatus(
                            AlertStatus.RESOLVED
                    );

                    alert.setResolvedAt(
                            OffsetDateTime.now()
                    );

                    recordAlertStatusChange(
                            alert,
                            previous,
                            AlertStatus.RESOLVED,
                            incident
                    );
                }
            }
        }

        /*
         * Incident is CLOSED.
         *
         * Active alerts become CLOSED.
         */
        else if (incident.getStatus()
                == IncidentStatus.CLOSED) {

            for (Alert alert : alerts) {

                if (isActiveAlert(
                        alert.getStatus()
                )) {

                    AlertStatus previous =
                            alert.getStatus();

                    alert.setStatus(
                            AlertStatus.CLOSED
                    );

                    alert.setResolvedAt(
                            OffsetDateTime.now()
                    );

                    recordAlertStatusChange(
                            alert,
                            previous,
                            AlertStatus.CLOSED,
                            incident
                    );
                }
            }
        }

        /*
         * Incident is INVESTIGATING.
         *
         * Active alerts become INVESTIGATING.
         */
        else if (incident.getStatus()
                == IncidentStatus.INVESTIGATING) {

            for (Alert alert : alerts) {

                if (alert.getStatus()
                        == AlertStatus.OPEN
                        || alert.getStatus()
                        == AlertStatus.ACKNOWLEDGED) {

                    AlertStatus previous =
                            alert.getStatus();

                    alert.setStatus(
                            AlertStatus.INVESTIGATING
                    );

                    recordAlertStatusChange(
                            alert,
                            previous,
                            AlertStatus.INVESTIGATING,
                            incident
                    );
                }
            }
        }

        /*
         * Save all modified alerts. Flushed explicitly so that if any one
         * of these alerts was concurrently modified directly (e.g. an
         * analyst's own PATCH /alerts/{id}/status racing this incident-wide
         * synchronization), the conflict is detected and this whole
         * incident status change rolls back atomically together with it -
         * never a partial synchronization silently overwriting a
         * concurrent direct change on just one alert.
         */
        alertRepository.saveAll(
                alerts
        );
        alertRepository.flush();
    }

    /*
     * ============================================================
     * AUDIT AUTOMATIC ALERT STATUS CHANGE
     * ============================================================
     */

    private void recordAlertStatusChange(
            Alert alert,
            AlertStatus previous,
            AlertStatus next,
            Incident incident
    ) {

        Map<String, Object> details =
                new HashMap<>();

        details.put(
                "fromStatus",
                previous.name()
        );

        details.put(
                "toStatus",
                next.name()
        );

        details.put(
                "source",
                "INCIDENT_STATUS_SYNCHRONIZATION"
        );

        details.put(
                "incidentId",
                incident.getId().toString()
        );

        details.put(
                "incidentKey",
                incident.getIncidentKey()
        );

        if (alert.getEvent() != null) {

            details.put(
                    "eventId",
                    alert.getEvent().getEventId()
            );
        }

        if (alert.getEntity() != null) {

            details.put(
                    "entityId",
                    alert.getEntity().getEntityId()
            );
        }

        auditLogService.log(
                CurrentActor.name(),
                "STATUS_CHANGED",
                "ALERT",
                alert.getId(),
                null,
                details
        );
    }

    /*
     * ============================================================
     * ACTIVE ALERT CHECK
     * ============================================================
     */

    private boolean isActiveAlert(
            AlertStatus status
    ) {

        return status == AlertStatus.OPEN
                || status == AlertStatus.ACKNOWLEDGED
                || status == AlertStatus.INVESTIGATING;
    }

    /*
     * ============================================================
     * INCIDENT STATUS TRANSITIONS
     * ============================================================
     */

    private boolean allowed(
            IncidentStatus from,
            IncidentStatus to
    ) {

        /*
         * Same status is allowed.
         */
        if (from == to) {
            return true;
        }

        return switch (from) {

            case OPEN ->
                    to == IncidentStatus.INVESTIGATING
                            || to == IncidentStatus.RESOLVED
                            || to == IncidentStatus.CLOSED;

            case INVESTIGATING ->
                    to == IncidentStatus.RESOLVED
                            || to == IncidentStatus.CLOSED;

            case RESOLVED ->
                    to == IncidentStatus.CLOSED;

            case CLOSED ->
                    false;
        };
    }

    /*
     * ============================================================
     * INCIDENT → RESPONSE
     * ============================================================
     */

    private IncidentResponse toResponse(
            Incident incident
    ) {

        UUID id = incident.getId();

        return toResponse(
                incident,
                rollupFor(List.of(id)).get(id),
                sourcesFor(List.of(id)).getOrDefault(id, List.of())
        );
    }

    private IncidentResponse toResponse(
            Incident incident,
            Object[] rollup,
            List<String> sources
    ) {

        long alertCount = 0;
        Severity maxSeverity = null;
        BigDecimal maxScore = null;

        if (rollup != null) {

            alertCount = ((Number) rollup[1]).longValue();

            maxSeverity = switch (((Number) rollup[2]).intValue()) {
                case 4 -> Severity.CRITICAL;
                case 3 -> Severity.HIGH;
                case 2 -> Severity.MEDIUM;
                default -> Severity.LOW;
            };

            maxScore = (BigDecimal) rollup[3];
        }

        return new IncidentResponse(
                incident.getId(),
                incident.getIncidentKey(),
                incident.getEntity() == null
                        ? null
                        : incident.getEntity().getEntityId(),
                incident.getStatus(),
                incident.getSummary(),
                incident.getCreatedAt(),
                incident.getUpdatedAt(),
                incident.getClosedAt(),
                alertCount,
                maxSeverity,
                maxScore,
                sources
        );
    }

    private Map<UUID, Object[]> rollupFor(
            List<UUID> incidentIds
    ) {

        Map<UUID, Object[]> result = new HashMap<>();

        if (incidentIds.isEmpty()) {
            return result;
        }

        for (Object[] row : alertRepository.summarizeByIncident(incidentIds)) {
            result.put((UUID) row[0], row);
        }

        return result;
    }

    /*
     * [incidentId -> distinct sources] for a batch of incidents, one
     * grouped query for the whole page (not per-row) - see
     * AlertRepository.sourcesByIncident for why this can be a list
     * rather than a single value.
     */
    private Map<UUID, List<String>> sourcesFor(
            List<UUID> incidentIds
    ) {

        Map<UUID, List<String>> result = new HashMap<>();

        if (incidentIds.isEmpty()) {
            return result;
        }

        for (Object[] row : alertRepository.sourcesByIncident(incidentIds)) {

            UUID incidentId = (UUID) row[0];
            String joined = (String) row[1];

            result.put(
                    incidentId,
                    joined == null || joined.isBlank()
                            ? List.of()
                            : List.of(joined.split(","))
            );
        }

        return result;
    }

    /*
     * ============================================================
     * ALERT → INCIDENT ALERT RESPONSE
     * ============================================================
     */

    private IncidentAlertResponse toIncidentAlertResponse(
            Alert alert
    ) {

        return new IncidentAlertResponse(
                alert.getId(),

                alert.getEvent() == null
                        ? null
                        : alert.getEvent().getEventId(),

                alert.getEntity() == null
                        ? null
                        : alert.getEntity().getEntityId(),

                alert.getDecision(),
                alert.getSeverity(),
                alert.getStatus(),
                alert.getAnomalyScore(),
                alert.getConfidence(),
                alert.getFusedScore(),
                alert.getPolicyVersion(),
                alert.getCreatedAt(),
                alert.getUpdatedAt(),
                alert.getRuleId(),
                alert.getRuleName(),
                alert.getRuleId() == null ? "ML" : "RULE"
        );
    }
}