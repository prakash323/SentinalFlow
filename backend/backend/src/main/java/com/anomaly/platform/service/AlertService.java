package com.anomaly.platform.service;

import com.anomaly.platform.dto.AlertResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.exception.InvalidStatusTransitionException;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.security.CurrentActor;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AlertService {

    private final AlertRepository repo;
    private final AlertFactorRepository factors;
    private final AuditLogService auditLogService;

    public AlertService(
            AlertRepository repo,
            AlertFactorRepository factors,
            AuditLogService auditLogService
    ) {
        this.repo = repo;
        this.factors = factors;
        this.auditLogService = auditLogService;
    }

    /*
     * ============================================================
     * LIST ALERTS
     * ============================================================
     */

    @Transactional(readOnly = true)
    public PageResponse<AlertResponse> list(
            AlertStatus status,
            Severity severity,
            DecisionState decision,
            String entityId,
            String source,
            int page,
            int size
    ) {

        Pageable p = PageRequest.of(
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

        /*
         * Every supplied filter is applied together (AND). The previous
         * if/else-if chain silently honored only the first non-null
         * filter, so e.g. status=OPEN&severity=HIGH returned every OPEN
         * alert regardless of severity.
         */
        Specification<Alert> spec = Specification.where(null);

        if (status != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("status"), status));
        }

        if (severity != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("severity"), severity));
        }

        if (decision != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("decision"), decision));
        }

        if (entityId != null && !entityId.isBlank()) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("entity").get("entityId"), entityId.trim()));
        }

        /*
         * source lives on the alert's originating Event, not on Alert
         * itself (see Alert.event) - an alert whose event was somehow
         * never linked (event_id is nullable) is correctly excluded when
         * a specific source is requested, since it has none.
         */
        if (source != null && !source.isBlank()) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("event").get("source"), source.trim()));
        }

        Page<Alert> x = repo.findAll(spec, p);

        return PageResponse.from(
                x.map(this::to)
        );
    }

    /*
     * ============================================================
     * GET SINGLE ALERT
     * ============================================================
     */

    @Transactional(readOnly = true)
    public AlertResponse get(
            UUID id
    ) {

        Alert alert =
                repo.findById(id)
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Alert not found: "
                                                + id
                                )
                        );

        return to(alert);
    }

    /*
     * ============================================================
     * UPDATE ALERT STATUS
     * ============================================================
     */

    @Transactional
    public AlertResponse updateStatus(
            UUID id,
            AlertStatus next
    ) {

        Alert alert =
                repo.findById(id)
                        .orElseThrow(() ->
                                new NotFoundException(
                                        "Alert not found: "
                                                + id
                                )
                        );

        AlertStatus previous =
                alert.getStatus();

        /*
         * Check whether the transition is allowed.
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
         * Same-status updates do not create
         * unnecessary audit records.
         */
        if (previous == next) {

            return to(alert);
        }

        /*
         * Update status.
         */
        alert.setStatus(next);

        /*
         * Record acknowledgement time.
         */
        if (next == AlertStatus.ACKNOWLEDGED) {

            alert.setAcknowledgedAt(
                    OffsetDateTime.now()
            );
        }

        /*
         * Record resolution time.
         */
        if (next == AlertStatus.RESOLVED
                || next == AlertStatus.CLOSED
                || next == AlertStatus.FALSE_POSITIVE) {

            alert.setResolvedAt(
                    OffsetDateTime.now()
            );
        }

        /*
         * Save alert first. saveAndFlush (not save) so a concurrent
         * conflicting update on this same alert (see Alert.version) is
         * detected here, inside this request, rather than silently losing
         * one of the two updates - confirmed live before this was added:
         * two concurrent PATCHes both returned 200, one of them lying about
         * the eventual real status, and the audit log kept both as if both
         * had taken effect.
         */
        Alert savedAlert =
                repo.saveAndFlush(alert);

        /*
         * Create audit record.
         */
        recordStatusChange(
                savedAlert,
                previous,
                next
        );

        return to(savedAlert);
    }

    /*
     * ============================================================
     * AUDIT STATUS CHANGE
     * ============================================================
     */

    private void recordStatusChange(
            Alert alert,
            AlertStatus previous,
            AlertStatus next
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

        /*
         * Add useful contextual information.
         */
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
     * ALERT STATUS TRANSITIONS
     * ============================================================
     */

    private boolean allowed(
            AlertStatus from,
            AlertStatus to
    ) {

        /*
         * Same status is allowed.
         */
        if (from == to) {
            return true;
        }

        return switch (from) {

            /*
             * OPEN
             */
            case OPEN ->
                    to == AlertStatus.ACKNOWLEDGED
                            || to == AlertStatus.INVESTIGATING
                            || to == AlertStatus.FALSE_POSITIVE
                            || to == AlertStatus.CLOSED;

            /*
             * ACKNOWLEDGED
             */
            case ACKNOWLEDGED ->
                    to == AlertStatus.INVESTIGATING
                            || to == AlertStatus.RESOLVED
                            || to == AlertStatus.FALSE_POSITIVE
                            || to == AlertStatus.CLOSED;

            /*
             * INVESTIGATING
             */
            case INVESTIGATING ->
                    to == AlertStatus.RESOLVED
                            || to == AlertStatus.FALSE_POSITIVE
                            || to == AlertStatus.CLOSED;

            /*
             * RESOLVED
             */
            case RESOLVED ->
                    to == AlertStatus.CLOSED;

            /*
             * FALSE POSITIVE
             */
            case FALSE_POSITIVE ->
                    false;

            /*
             * CLOSED
             */
            case CLOSED ->
                    false;
        };
    }

    /*
     * ============================================================
     * ALERT → RESPONSE
     * ============================================================
     */

    private AlertResponse to(
            Alert a
    ) {

        List<String> fs =
                factors
                        .findByAlert_IdOrderByRankAsc(
                                a.getId()
                        )
                        .stream()
                        .map(AlertFactor::getFactor)
                        .toList();

        return new AlertResponse(
                a.getId(),

                a.getEntity() == null
                        ? null
                        : a.getEntity().getEntityId(),

                a.getEvent() == null
                        ? null
                        : a.getEvent().getEventId(),

                /*
                 * Read from the same lazily-loaded Event this method
                 * already fetches for eventId above - no additional
                 * query (Source-Aware SOC phase).
                 */
                a.getEvent() == null
                        ? null
                        : a.getEvent().getSource(),

                a.getDecision(),
                a.getSeverity(),
                a.getStatus(),
                a.getAnomalyScore(),
                a.getConfidence(),
                a.getFusedScore(),
                a.getPolicyVersion(),
                fs,
                a.getCreatedAt(),
                a.getUpdatedAt(),
                a.getIncident() == null
                        ? null
                        : a.getIncident().getId(),
                a.getRuleId(),
                a.getRuleName(),
                a.getRuleId() == null ? "ML" : "RULE"
        );
    }
}