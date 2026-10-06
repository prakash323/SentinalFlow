package com.anomaly.platform.repository;

import com.anomaly.platform.entity.Event;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/*
 * JpaSpecificationExecutor added for the source filter (Source-Aware SOC
 * phase) - AlertRepository/IncidentRepository already used Specification
 * for their dynamic filters; EventService.list() previously branched by
 * hand over entityId/eventType, which does not scale to a third filter
 * dimension without an explosion of if/else branches.
 */
public interface EventRepository
        extends JpaRepository<Event, UUID>, JpaSpecificationExecutor<Event> {

    /*
     * Find a single event by its public event ID.
     */
    Optional<Event> findByEventId(
            String eventId
    );

    /*
     * Find events belonging to an entity.
     */
    Page<Event> findByEntity_EntityId(
            String entityId,
            Pageable pageable
    );

    /*
     * Find events belonging to an entity and event type.
     */
    Page<Event> findByEntity_EntityIdAndEventType(
            String entityId,
            String eventType,
            Pageable pageable
    );

    /*
     * Find events by event type.
     */
    Page<Event> findByEventType(
            String eventType,
            Pageable pageable
    );

    /*
     * Replay query.
     *
     * Loads Event and EntityProfile together so that
     * EntityProfile is available after the repository call.
     */
    @Query("""
            SELECT e
            FROM Event e
            JOIN FETCH e.entity
            WHERE e.eventId = :eventId
            """)
    Optional<Event> findByEventIdWithEntity(
            @Param("eventId") String eventId
    );

    /*
     * Dashboard trend chart: events in the recent window, bucketed by
     * hour in the service layer.
     */
    List<Event> findByOccurredAtGreaterThanEqual(
            OffsetDateTime since
    );

    @Query("SELECT e.eventType, COUNT(e) FROM Event e GROUP BY e.eventType")
    List<Object[]> countGroupedByType();

    /*
     * Drives the source filter dropdown's option list (Source-Aware SOC
     * phase) - the same "known values seen so far" pattern
     * countGroupedByType() already provides for event types. source has
     * no NOT NULL constraint, so a legacy/blank source is grouped as
     * NULL - the dropdown's own code decides whether to show it.
     */
    @Query("SELECT e.source, COUNT(e) FROM Event e GROUP BY e.source")
    List<Object[]> countGroupedBySource();

    @Query("SELECT e.processingStatus, COUNT(e) FROM Event e GROUP BY e.processingStatus")
    List<Object[]> countGroupedByProcessingStatus();

    /*
     * Events per UTC hour since the given instant, as [hourKey, count]
     * (see AlertRepository#hourlyCounts).
     */
    @Query(value = """
            SELECT to_char(date_trunc('hour', occurred_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24'),
                   COUNT(*)
            FROM events
            WHERE occurred_at >= :since
            GROUP BY 1
            """, nativeQuery = true)
    List<Object[]> hourlyCounts(@Param("since") OffsetDateTime since);

    /*
     * [entityUuid, eventCount, lastOccurredAt] for the given entities.
     */
    @Query("""
            SELECT e.entity.id, COUNT(e), MAX(e.occurredAt)
            FROM Event e
            WHERE e.entity.id IN :ids
            GROUP BY e.entity.id
            """)
    List<Object[]> summarizeByEntity(@Param("ids") java.util.Collection<UUID> ids);

    /*
     * PendingEventReconciler: claims (row-locks) the oldest event that was
     * stored but apparently never published. Must run inside a transaction;
     * SKIP LOCKED means a concurrent run skips this row instead of waiting.
     *
     * Eligible only if ALL hold:
     *  - PENDING with 0 attempts: the consumer never finished or failed it
     *    (markProcessed / markFailed both move it off this state);
     *  - no prediction on record: excludes events that were processed before
     *    status tracking existed (V12 backfilled them as PENDING) - re-sending
     *    those would re-score them;
     *  - created in [notBefore, staleBefore): old enough that the normal
     *    post-commit publish and consumer processing are long over, young
     *    enough to still be worth automatic recovery;
     *  - not given up on, fewer than :maxAttempts republish attempts, and no
     *    attempt since :retryBefore (attempts are EVENT_REPUBLISH_ATTEMPT
     *    audit rows, so the history survives restarts).
     */
    @Query(value = """
            SELECT e.id
            FROM events e
            WHERE e.processing_status = 'PENDING'
              AND e.processing_attempts = 0
              AND e.created_at < :staleBefore
              AND e.created_at >= :notBefore
              AND NOT EXISTS (SELECT 1 FROM predictions p WHERE p.event_id = e.id)
              AND NOT EXISTS (
                    SELECT 1 FROM audit_logs a
                    WHERE a.resource_type = 'EVENT' AND a.resource_id = e.id
                      AND (a.action = 'EVENT_REPUBLISH_EXHAUSTED'
                           OR (a.action = 'EVENT_REPUBLISH_ATTEMPT' AND a.created_at >= :retryBefore)))
              AND (SELECT COUNT(*) FROM audit_logs a
                   WHERE a.resource_type = 'EVENT' AND a.resource_id = e.id
                     AND a.action = 'EVENT_REPUBLISH_ATTEMPT') < :maxAttempts
            ORDER BY e.created_at
            LIMIT 1
            FOR UPDATE OF e SKIP LOCKED
            """, nativeQuery = true)
    Optional<UUID> claimNextUnpublished(
            @Param("staleBefore") OffsetDateTime staleBefore,
            @Param("notBefore") OffsetDateTime notBefore,
            @Param("retryBefore") OffsetDateTime retryBefore,
            @Param("maxAttempts") long maxAttempts
    );

    /*
     * ============================================================
     * SOURCE-CORRELATED DETECTION (Detection Engine 2.0)
     * ============================================================
     *
     * Events of one type whose payload field `:field` equals `:value`, inside a
     * time window, newest first, capped.
     *
     * This is the one correlation dimension the original rules had no query for:
     * "what else did THIS SOURCE do", as opposed to "what else did this entity
     * do". `payload->>'ip'` is the only source-side identity the event schema
     * carries (see EventPayloads.sourceIp), so PASSWORD_SPRAY and
     * ACCOUNT_ENUMERATION key on it.
     *
     * Bounded in the database rather than in Java: the window and LIMIT are part
     * of the query, so a busy source address cannot make one evaluation
     * expensive. V16 adds the supporting index.
     *
     * `field` is a fixed identifier chosen by the calling service, never user
     * input - it is bound as a parameter to ->> rather than concatenated.
     */
    @Query(value = """
            SELECT e.*
            FROM events e
            WHERE e.event_type = :eventType
              AND e.payload ->> CAST(:field AS text) = CAST(:value AS text)
              AND e.occurred_at >= :from
              AND e.occurred_at <= :to
            ORDER BY e.occurred_at DESC
            LIMIT :cap
            """, nativeQuery = true)
    List<Event> findByPayloadStringFieldAndType(
            @Param("field") String field,
            @Param("value") String value,
            @Param("eventType") String eventType,
            @Param("from") OffsetDateTime from,
            @Param("to") OffsetDateTime to,
            @Param("cap") int cap
    );

    /*
     * Row-locks one event until the surrounding transaction ends, so two
     * threads processing the same event (Kafka consumer and admin replay)
     * create its rule alerts and prediction one after the other. Must be
     * called inside a transaction. Empty if the event does not exist.
     */
    @Query(value = "SELECT e.id FROM events e WHERE e.id = :id FOR UPDATE", nativeQuery = true)
    Optional<UUID> lockForProcessing(@Param("id") UUID id);
}
