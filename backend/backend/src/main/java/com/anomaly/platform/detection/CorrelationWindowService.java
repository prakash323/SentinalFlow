package com.anomaly.platform.detection;

import com.anomaly.platform.entity.Event;
import com.anomaly.platform.repository.EventRepository;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/*
 * ============================================================
 * CORRELATION STATE
 * ============================================================
 *
 * THE CORRELATION STATE IS THE EVENTS TABLE. There is no in-memory window, no
 * cache, no singleton map and nothing to expire.
 *
 * Why: every rule here correlates over a short window of events that PostgreSQL
 * already stores as the system of record, and the pre-existing rules already
 * worked this way. Keeping it that way buys properties an in-memory window
 * cannot offer:
 *
 *   - MULTI-INSTANCE CORRECT. Two application instances see the same window.
 *     An in-JVM map would give each instance a different, partial view and make
 *     detection depend on which instance consumed the event.
 *   - NO UNBOUNDED GROWTH TO MANAGE. Nothing accumulates in the JVM, so there is
 *     no TTL to tune, no eviction policy to get wrong and no cleanup task to
 *     fail. The answer to "what is the maximum size of this cache?" is that
 *     there is no cache.
 *   - RESTART AND REPLAY SAFE. State cannot be lost on restart or diverge during
 *     a replay, because it is never a second copy of anything.
 *   - AUDITABLE. Every event an alert cites can still be fetched and read.
 *
 * What IS bounded, deliberately and in one place, is each query:
 *
 *   - a time window (the rule's own configured window, from the triggering
 *     event backwards), so a query never scans an entity's whole history;
 *   - a HARD ROW CAP (detection.max-correlation-events) applied to every query,
 *     so one evaluation's cost and memory are bounded however busy an entity is;
 *   - newest-first ordering, so when the cap does truncate, what survives is the
 *     most recent - the part a short-window rule cares about.
 *
 * Truncation is visible rather than silent: `WindowResult.truncated` tells a rule
 * its view was capped, and every rule that could under-count because of it says
 * so in its evidence instead of reporting a count it cannot stand behind.
 */
@Service
public class CorrelationWindowService {

    private final EventRepository eventRepository;

    public CorrelationWindowService(EventRepository eventRepository) {
        this.eventRepository = eventRepository;
    }

    /**
     * A bounded window of events, newest first, with whether the row cap cut it
     * short. A rule must never present a count from a truncated window as exact.
     */
    public record WindowResult(List<Event> events, boolean truncated, int cap) {

        public static WindowResult empty() {
            return new WindowResult(List.of(), false, 0);
        }

        public int size() {
            return events.size();
        }

        public boolean isEmpty() {
            return events.isEmpty();
        }
    }

    private static Pageable newestFirst(int cap) {
        return PageRequest.of(0, Math.max(1, cap), Sort.by(Sort.Direction.DESC, "occurredAt"));
    }

    /**
     * Keep only events inside [from, to] and cap the result.
     *
     * Both ends are inclusive and `to` is the triggering event's own timestamp,
     * so an event that happened AFTER the trigger (possible when events arrive
     * out of order) is excluded: a rule must not justify an alert with evidence
     * from the future relative to the event that fired it. This mirrors the
     * filter the original rules applied, unchanged.
     */
    private WindowResult windowed(List<Event> candidates, OffsetDateTime from, OffsetDateTime to, int cap) {
        if (candidates == null || candidates.isEmpty()) {
            return WindowResult.empty();
        }
        List<Event> kept = new ArrayList<>();
        for (Event e : candidates) {
            OffsetDateTime at = e.getOccurredAt();
            if (at == null || at.isBefore(from) || at.isAfter(to)) {
                continue;
            }
            kept.add(e);
        }
        // The repository already ordered newest-first and capped the page, so a
        // full page means the database may have had more to give.
        boolean truncated = candidates.size() >= cap;
        return new WindowResult(List.copyOf(kept), truncated, cap);
    }

    /* ------------------------------------------------------------------ by entity */

    /**
     * Events of one type for one entity, within `window` before (and including)
     * `at`. Uses the same repository method the original rules used, so the
     * historical query shape and its index usage are unchanged.
     */
    public WindowResult byEntityAndType(String entityId, String eventType, OffsetDateTime at, Duration window, int cap) {
        if (entityId == null || eventType == null || at == null || window == null) {
            return WindowResult.empty();
        }
        List<Event> page = eventRepository
                .findByEntity_EntityIdAndEventType(entityId, eventType, newestFirst(cap))
                .getContent();
        return windowed(page, at.minus(window), at, cap);
    }

    /** Events of several types for one entity, within the window. One query per type, each capped. */
    public WindowResult byEntityAndTypes(String entityId, Collection<String> eventTypes,
                                         OffsetDateTime at, Duration window, int cap) {
        if (entityId == null || eventTypes == null || eventTypes.isEmpty() || at == null || window == null) {
            return WindowResult.empty();
        }
        List<Event> all = new ArrayList<>();
        boolean truncated = false;
        for (String type : eventTypes) {
            WindowResult r = byEntityAndType(entityId, type, at, window, cap);
            all.addAll(r.events());
            truncated = truncated || r.truncated();
        }
        all.sort((a, b) -> b.getOccurredAt().compareTo(a.getOccurredAt()));
        if (all.size() > cap) {
            all = new ArrayList<>(all.subList(0, cap));
            truncated = true;
        }
        return new WindowResult(List.copyOf(all), truncated, cap);
    }

    /* ------------------------------------------------------------------ by source address */

    /**
     * Events of one type from one SOURCE ADDRESS, across entities, within the
     * window. This is the dimension the source-correlated rules need and the one
     * the original rules had no query for: `payload->>'ip'` is the only
     * source-side identity the schema carries.
     *
     * Capped and time-bounded in the database (see
     * EventRepository#findByPayloadStringFieldAndType), not in Java, so a busy
     * source address cannot make this query expensive.
     */
    public WindowResult bySourceIpAndType(String sourceIp, String eventType,
                                          OffsetDateTime at, Duration window, int cap) {
        if (sourceIp == null || sourceIp.isBlank() || eventType == null || at == null || window == null) {
            return WindowResult.empty();
        }
        int bounded = Math.max(1, cap);
        List<Event> rows = eventRepository.findByPayloadStringFieldAndType(
                "ip", sourceIp, eventType, at.minus(window), at, bounded);
        boolean truncated = rows.size() >= bounded;
        return new WindowResult(List.copyOf(rows), truncated, bounded);
    }
}
