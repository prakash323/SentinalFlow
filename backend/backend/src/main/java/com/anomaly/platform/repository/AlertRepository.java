package com.anomaly.platform.repository;

import com.anomaly.platform.entity.*;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.*;

public interface AlertRepository
        extends JpaRepository<Alert, UUID>, JpaSpecificationExecutor<Alert> {

    Page<Alert> findByStatus(
            AlertStatus status,
            Pageable p
    );

    Page<Alert> findBySeverity(
            Severity severity,
            Pageable p
    );

    Page<Alert> findByDecision(
            DecisionState decision,
            Pageable p
    );

    Page<Alert> findByEntity_EntityId(
            String entityId,
            Pageable p
    );

    List<Alert> findByIncident_IdOrderByCreatedAtDesc(
            UUID incidentId
    );

    /*
     * Dashboard trend chart: alerts in the recent window, bucketed by
     * hour in the service layer.
     */
    List<Alert> findByCreatedAtGreaterThanEqual(
            OffsetDateTime since
    );

    /*
     * Newest alert raised for an event (an event has at most one in the
     * current pipeline, but the query is written defensively).
     */
    java.util.Optional<Alert> findTopByEvent_IdOrderByCreatedAtDesc(UUID eventId);

    /*
     * Independent deterministic detection (P1) idempotency: has this exact
     * triggering event already raised this rule's alert? A Kafka redelivery
     * of the same event must never create a second alert.
     */
    boolean existsByEvent_IdAndRuleId(UUID eventId, String ruleId);

    /*
     * Independent deterministic detection (P1) suppression: the most recent
     * still-active alert for this rule on this entity, if any - mirrors
     * IncidentService.findOrCreateIncident's own "reuse while active" idiom
     * so a repeating condition (e.g. an ongoing login-failure burst) does
     * not raise a fresh alert for every single qualifying event.
     */
    Optional<Alert> findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
            String entityId,
            String ruleId,
            List<AlertStatus> activeStatuses
    );

    List<Alert> findByEntity_EntityIdAndRuleIdAndStatusIn(
            String entityId,
            String ruleId,
            List<AlertStatus> activeStatuses
    );

    long countByStatus(AlertStatus status);

    long countBySeverity(Severity severity);

    /*
     * Per-incident rollup used by the incident list/detail views:
     * [incidentId, alertCount, severityRank (1=LOW..4=CRITICAL), maxScore].
     * One grouped query per page instead of one query per incident.
     */
    @Query("""
            SELECT a.incident.id,
                   COUNT(a),
                   MAX(CASE a.severity
                           WHEN com.anomaly.platform.entity.Severity.CRITICAL THEN 4
                           WHEN com.anomaly.platform.entity.Severity.HIGH THEN 3
                           WHEN com.anomaly.platform.entity.Severity.MEDIUM THEN 2
                           ELSE 1
                       END),
                   MAX(a.fusedScore)
            FROM Alert a
            WHERE a.incident.id IN :ids
            GROUP BY a.incident.id
            """)
    List<Object[]> summarizeByIncident(@Param("ids") java.util.Collection<UUID> ids);

    /*
     * [incidentId, comma-joined distinct sources] for the given incidents
     * (Source-Aware SOC phase) - an incident has no source column of its
     * own (see Incident entity); this is derived from its alerts' events,
     * batched for a whole page rather than one query per incident. An
     * incident CAN genuinely have alerts from more than one source (the
     * correlation key is entityId:eventType, not source) - confirmed
     * against live data, not assumed - so this returns every distinct
     * source, not a single "the" source.
     */
    @Query(value = """
            SELECT a.incident_id, string_agg(DISTINCT e.source, ',' ORDER BY e.source)
            FROM alerts a
            JOIN events e ON e.id = a.event_id
            WHERE a.incident_id IN :ids
            GROUP BY a.incident_id
            """, nativeQuery = true)
    List<Object[]> sourcesByIncident(@Param("ids") java.util.Collection<UUID> ids);

    @Query("SELECT a.severity, COUNT(a) FROM Alert a GROUP BY a.severity")
    List<Object[]> countGroupedBySeverity();

    @Query("SELECT a.status, COUNT(a) FROM Alert a GROUP BY a.status")
    List<Object[]> countGroupedByStatus();

    /*
     * [entityId, alertCount, maxScore, lastAlertAt], most alerts first.
     */
    @Query("""
            SELECT a.entity.entityId, COUNT(a), MAX(a.fusedScore), MAX(a.createdAt)
            FROM Alert a
            GROUP BY a.entity.entityId
            ORDER BY COUNT(a) DESC, MAX(a.fusedScore) DESC
            """)
    List<Object[]> topEntitiesByAlertCount(Pageable pageable);

    /*
     * Alerts per UTC hour since the given instant, as [hourKey, count]
     * where hourKey is 'YYYY-MM-DDTHH'. Returned as text so the result
     * does not depend on the JVM/driver time-zone handling of timestamps.
     */
    @Query(value = """
            SELECT to_char(date_trunc('hour', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24'),
                   COUNT(*)
            FROM alerts
            WHERE created_at >= :since
            GROUP BY 1
            """, nativeQuery = true)
    List<Object[]> hourlyCounts(@Param("since") OffsetDateTime since);

    /*
     * [entityUuid, alertCount, openAlertCount, maxScore] for the given
     * entities.
     */
    @Query("""
            SELECT a.entity.id,
                   COUNT(a),
                   SUM(CASE WHEN a.status = com.anomaly.platform.entity.AlertStatus.OPEN THEN 1 ELSE 0 END),
                   MAX(a.fusedScore)
            FROM Alert a
            WHERE a.entity.id IN :ids
            GROUP BY a.entity.id
            """)
    List<Object[]> summarizeByEntity(@Param("ids") java.util.Collection<UUID> ids);
}
