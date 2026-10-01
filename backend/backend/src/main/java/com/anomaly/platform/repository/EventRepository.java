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
}
