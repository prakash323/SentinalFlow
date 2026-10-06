package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.service.AuditLogService;
import com.anomaly.platform.service.IncidentService;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/*
 * ============================================================
 * AN IN-MEMORY DETECTION WORLD
 * ============================================================
 *
 * The detection tests need a realistic world - an event store that answers the
 * same queries PostgreSQL answers, an alert store that enforces the same
 * uniqueness the database enforces, and an audit log that records what happened -
 * without a database.
 *
 * Mockito stubs are the wrong tool for that: a rule's behaviour depends on what
 * the store CONTAINS, and stubbing each query per test would mean the tests
 * assert the stubs rather than the detection. So this is a small hand-written
 * fake backed by real collections, with the behaviours that actually matter:
 *
 *   - events filtered and ordered exactly as the repository orders them
 *     (newest-first, capped by the Pageable), including the jsonb source query;
 *   - the uk_alerts_event_rule UNIQUE CONSTRAINT enforced on insert, so a test
 *     that would create a duplicate alert fails here the way it would fail in
 *     PostgreSQL rather than passing quietly;
 *   - incidents reused while active and recreated once resolved, matching
 *     IncidentService's real key semantics;
 *   - audit rows kept so suppression and escalation decisions can be asserted.
 *
 * Everything is deterministic: no clock is read, no randomness is used, and time
 * is always relative to a fixed NOW.
 */
public final class DetectionTestHarness {

    public static final OffsetDateTime NOW = OffsetDateTime.parse("2026-10-07T12:00:00Z");

    private static final DateTimeFormatter PROCESS_CREATE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public final FakeEventRepository events = new FakeEventRepository();
    public final FakeAlertRepository alerts = new FakeAlertRepository();
    public final FakeAlertFactorRepository factors = new FakeAlertFactorRepository();
    public final FakeIncidentService incidents = new FakeIncidentService();
    public final RecordingAuditLogService audit = new RecordingAuditLogService();

    public final DetectionProperties properties;
    public final RuleRegistry registry;
    public final DetectionEngine engine;

    private final Map<String, EntityProfile> entities = new LinkedHashMap<>();
    private final AtomicInteger eventSeq = new AtomicInteger();

    public DetectionTestHarness(DetectionProperties properties, List<DetectionRule> rules) {
        this.properties = properties;
        this.registry = new RuleRegistry(rules);
        this.engine = new DetectionEngine(
                registry,
                new CorrelationWindowService(events),
                properties,
                events,
                alerts,
                factors,
                incidents,
                audit
        );
    }

    /** The full production rule set, with the production default configuration. */
    public static DetectionTestHarness withAllRules() {
        return new DetectionTestHarness(DetectionProperties.defaults(),
                new com.anomaly.platform.detection.config.DetectionConfig().ruleRegistry().all());
    }

    public static DetectionTestHarness with(DetectionRule... rules) {
        return new DetectionTestHarness(DetectionProperties.defaults(), List.of(rules));
    }

    public static DetectionTestHarness with(DetectionProperties properties, DetectionRule... rules) {
        return new DetectionTestHarness(properties, List.of(rules));
    }

    /* ------------------------------------------------------------------ building a world */

    public EntityProfile entity(String entityId) {
        return entities.computeIfAbsent(entityId, id -> {
            EntityProfile e = new EntityProfile();
            e.setId(UUID.randomUUID());
            e.setEntityId(id);
            e.setEntityType("HOST");
            return e;
        });
    }

    /** Store an event and return it, exactly as the pipeline would have persisted it. */
    public Event store(String entityId, String eventType, OffsetDateTime at, Map<String, Object> payload) {
        Event e = new Event();
        e.setId(UUID.randomUUID());
        e.setEventId("EV-" + eventType + "-" + eventSeq.incrementAndGet());
        e.setEntity(entity(entityId));
        e.setEventType(eventType);
        e.setEventVersion("v1");
        e.setOccurredAt(at);
        e.setSource("test");
        e.setPayload(payload == null ? Map.of() : new HashMap<>(payload));
        events.save(e);
        return e;
    }

    /* ---- payload builders, using only fields this platform really produces ---- */

    public static Map<String, Object> login(boolean success, String ip) {
        Map<String, Object> p = new HashMap<>();
        p.put("loginSuccess", success);
        if (ip != null) {
            p.put("ip", ip);
        }
        return p;
    }

    public static Map<String, Object> login(boolean success, String ip, String location) {
        Map<String, Object> p = login(success, ip);
        if (location != null) {
            p.put("location", location);
        }
        return p;
    }

    public static Map<String, Object> processStart(long pid, String processName) {
        Map<String, Object> p = new HashMap<>();
        p.put("pid", pid);
        if (processName != null) {
            p.put("processName", processName);
        }
        return p;
    }

    public static Map<String, Object> connection(long pid, OffsetDateTime processCreatedAt, String remoteAddress) {
        Map<String, Object> p = new HashMap<>();
        p.put("pid", pid);
        if (processCreatedAt != null) {
            p.put("processCreateTime", iso(processCreatedAt));
        }
        p.put("remoteAddress", remoteAddress);
        return p;
    }

    public static Map<String, Object> fileAccess(String resource, String commandSequence) {
        Map<String, Object> p = new HashMap<>();
        p.put("resource", resource);
        if (commandSequence != null) {
            p.put("commandSequence", commandSequence);
        }
        return p;
    }

    /** A PROCESS_START's occurredAt in the exact form a connection's processCreateTime must equal. */
    public static String iso(OffsetDateTime t) {
        return t.withOffsetSameInstant(ZoneOffset.UTC).format(PROCESS_CREATE_TIME);
    }

    /* ------------------------------------------------------------------ asserting */

    public List<DetectionEngine.RuleEvaluation> evaluate(Event event) {
        return engine.evaluate(event);
    }

    /** The outcome one rule reached for the last evaluation, or NOT_APPLICABLE. */
    public static DetectionOutcome outcomeOf(List<DetectionEngine.RuleEvaluation> results, String ruleId) {
        return results.stream()
                .filter(r -> r.ruleId().equals(ruleId))
                .map(DetectionEngine.RuleEvaluation::outcome)
                .findFirst()
                .orElse(DetectionOutcome.NOT_APPLICABLE);
    }

    public static Severity severityOf(List<DetectionEngine.RuleEvaluation> results, String ruleId) {
        return results.stream()
                .filter(r -> r.ruleId().equals(ruleId))
                .map(DetectionEngine.RuleEvaluation::severity)
                .findFirst()
                .orElse(null);
    }

    public List<Alert> alertsFor(String ruleId) {
        return alerts.stored.stream().filter(a -> ruleId.equals(a.getRuleId())).toList();
    }

    public List<String> factorsOf(Alert alert) {
        return factors.stored.stream()
                .filter(f -> f.getAlert().getId().equals(alert.getId()))
                .sorted(java.util.Comparator.comparingInt(AlertFactor::getRank))
                .map(AlertFactor::getFactor)
                .toList();
    }

    /** The audit detail map of the newest row with this action, or null. */
    public Map<String, Object> lastAudit(String action) {
        return audit.rows.stream()
                .filter(r -> r.action().equals(action))
                .reduce((a, b) -> b)
                .map(RecordingAuditLogService.Row::details)
                .orElse(null);
    }

    public long auditCount(String action) {
        return audit.rows.stream().filter(r -> r.action().equals(action)).count();
    }

    /* ==================================================================== fakes */

    /**
     * An event store that answers the two query shapes the correlation layer uses,
     * with the real ordering and capping semantics.
     */
    public static final class FakeEventRepository implements EventRepository {

        public final List<Event> stored = new ArrayList<>();
        /** Every lockForProcessing call, so the locking contract can be asserted. */
        public final List<UUID> locks = new ArrayList<>();
        /** Set to make the next correlation query fail, for the never-throws tests. */
        public RuntimeException failQueriesWith;

        @Override
        public Page<Event> findByEntity_EntityIdAndEventType(String entityId, String eventType, Pageable pageable) {
            if (failQueriesWith != null) {
                throw failQueriesWith;
            }
            List<Event> matching = stored.stream()
                    .filter(e -> e.getEntity() != null && e.getEntity().getEntityId().equals(entityId))
                    .filter(e -> e.getEventType().equals(eventType))
                    .sorted((a, b) -> b.getOccurredAt().compareTo(a.getOccurredAt()))
                    .limit(pageable.getPageSize())
                    .toList();
            return new PageImpl<>(matching);
        }

        @Override
        public List<Event> findByPayloadStringFieldAndType(String field, String value, String eventType,
                                                           OffsetDateTime from, OffsetDateTime to, int cap) {
            if (failQueriesWith != null) {
                throw failQueriesWith;
            }
            return stored.stream()
                    .filter(e -> e.getEventType().equals(eventType))
                    .filter(e -> value.equals(String.valueOf(e.getPayload().get(field))))
                    .filter(e -> !e.getOccurredAt().isBefore(from) && !e.getOccurredAt().isAfter(to))
                    .sorted((a, b) -> b.getOccurredAt().compareTo(a.getOccurredAt()))
                    .limit(cap)
                    .toList();
        }

        @Override
        public java.util.Optional<UUID> lockForProcessing(UUID id) {
            locks.add(id);
            return java.util.Optional.of(id);
        }

        @Override
        public <S extends Event> S save(S entity) {
            stored.add(entity);
            return entity;
        }

        /* ---- everything else is unused by detection and intentionally unsupported ---- */

        @Override public java.util.Optional<Event> findByEventId(String eventId) { throw unsupported(); }
        @Override public Page<Event> findByEntity_EntityId(String entityId, Pageable pageable) { throw unsupported(); }
        @Override public Page<Event> findByEventType(String eventType, Pageable pageable) { throw unsupported(); }
        @Override public java.util.Optional<Event> findByEventIdWithEntity(String eventId) { throw unsupported(); }
        @Override public List<Event> findByOccurredAtGreaterThanEqual(OffsetDateTime since) { throw unsupported(); }
        @Override public List<Object[]> countGroupedByType() { throw unsupported(); }
        @Override public List<Object[]> countGroupedBySource() { throw unsupported(); }
        @Override public List<Object[]> countGroupedByProcessingStatus() { throw unsupported(); }
        @Override public List<Object[]> hourlyCounts(OffsetDateTime since) { throw unsupported(); }
        @Override public List<Object[]> summarizeByEntity(java.util.Collection<UUID> ids) { throw unsupported(); }
        @Override public java.util.Optional<UUID> claimNextUnpublished(OffsetDateTime a, OffsetDateTime b, OffsetDateTime c, long d) { throw unsupported(); }
        @Override public List<Event> findAll() { return List.copyOf(stored); }
        @Override public List<Event> findAll(org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public Page<Event> findAll(Pageable pageable) { throw unsupported(); }
        @Override public List<Event> findAllById(Iterable<UUID> ids) { throw unsupported(); }
        @Override public long count() { return stored.size(); }
        @Override public void deleteById(UUID id) { throw unsupported(); }
        @Override public void delete(Event entity) { throw unsupported(); }
        @Override public void deleteAllById(Iterable<? extends UUID> ids) { throw unsupported(); }
        @Override public void deleteAll(Iterable<? extends Event> entities) { throw unsupported(); }
        @Override public void deleteAll() { stored.clear(); }
        @Override public <S extends Event> List<S> saveAll(Iterable<S> entities) { throw unsupported(); }
        @Override public java.util.Optional<Event> findById(UUID id) {
            return stored.stream().filter(e -> id.equals(e.getId())).findFirst();
        }
        @Override public boolean existsById(UUID id) { return findById(id).isPresent(); }
        @Override public void flush() { }
        @Override public <S extends Event> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends Event> List<S> saveAllAndFlush(Iterable<S> entities) { throw unsupported(); }
        @Override public void deleteAllInBatch(Iterable<Event> entities) { throw unsupported(); }
        @Override public void deleteAllByIdInBatch(Iterable<UUID> ids) { throw unsupported(); }
        @Override public void deleteAllInBatch() { throw unsupported(); }
        @Override public Event getOne(UUID id) { throw unsupported(); }
        @Override public Event getById(UUID id) { throw unsupported(); }
        @Override public Event getReferenceById(UUID id) { throw unsupported(); }
        @Override public <S extends Event> java.util.Optional<S> findOne(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Event> List<S> findAll(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Event> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public <S extends Event> Page<S> findAll(org.springframework.data.domain.Example<S> example, Pageable pageable) { throw unsupported(); }
        @Override public <S extends Event> long count(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Event> boolean exists(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Event, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> fn) { throw unsupported(); }
        @Override public java.util.Optional<Event> findOne(org.springframework.data.jpa.domain.Specification<Event> spec) { throw unsupported(); }
        @Override public List<Event> findAll(org.springframework.data.jpa.domain.Specification<Event> spec) { throw unsupported(); }
        @Override public Page<Event> findAll(org.springframework.data.jpa.domain.Specification<Event> spec, Pageable pageable) { throw unsupported(); }
        @Override public List<Event> findAll(org.springframework.data.jpa.domain.Specification<Event> spec, org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public long count(org.springframework.data.jpa.domain.Specification<Event> spec) { throw unsupported(); }
        @Override public boolean exists(org.springframework.data.jpa.domain.Specification<Event> spec) { throw unsupported(); }
        @Override public long delete(org.springframework.data.jpa.domain.Specification<Event> spec) { throw unsupported(); }
        @Override public <S extends Event, R> R findBy(org.springframework.data.jpa.domain.Specification<Event> spec, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> fn) { throw unsupported(); }

        private static UnsupportedOperationException unsupported() {
            return new UnsupportedOperationException("not used by the detection engine");
        }
    }

    /** An alert store that enforces uk_alerts_event_rule the way PostgreSQL does. */
    public static final class FakeAlertRepository implements AlertRepository {

        public final List<Alert> stored = new ArrayList<>();

        @Override
        public <S extends Alert> S save(S alert) {
            if (alert.getId() == null) {
                // The database's UNIQUE (event_id, rule_id) WHERE rule_id IS NOT NULL.
                if (alert.getRuleId() != null && alert.getEvent() != null) {
                    boolean clash = stored.stream().anyMatch(a -> a.getRuleId() != null
                            && a.getRuleId().equals(alert.getRuleId())
                            && a.getEvent() != null
                            && a.getEvent().getId().equals(alert.getEvent().getId()));
                    if (clash) {
                        throw new org.springframework.dao.DataIntegrityViolationException(
                                "uk_alerts_event_rule violated for event " + alert.getEvent().getEventId()
                                        + " and rule " + alert.getRuleId());
                    }
                }
                alert.setId(UUID.randomUUID());
                alert.setCreatedAt(OffsetDateTime.now());
                alert.setUpdatedAt(OffsetDateTime.now());
                stored.add(alert);
            }
            return alert;
        }

        @Override
        public boolean existsByEvent_IdAndRuleId(UUID eventId, String ruleId) {
            return stored.stream().anyMatch(a -> ruleId.equals(a.getRuleId())
                    && a.getEvent() != null && a.getEvent().getId().equals(eventId));
        }

        @Override
        public java.util.Optional<Alert> findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                String entityId, String ruleId, List<AlertStatus> statuses) {
            return stored.stream()
                    .filter(a -> ruleId.equals(a.getRuleId()))
                    .filter(a -> a.getEntity() != null && a.getEntity().getEntityId().equals(entityId))
                    .filter(a -> statuses.contains(a.getStatus()))
                    .reduce((a, b) -> b);
        }

        @Override
        public List<Alert> findByEntity_EntityIdAndRuleIdAndStatusIn(String entityId, String ruleId, List<AlertStatus> statuses) {
            return stored.stream()
                    .filter(a -> ruleId.equals(a.getRuleId()))
                    .filter(a -> a.getEntity() != null && a.getEntity().getEntityId().equals(entityId))
                    .filter(a -> statuses.contains(a.getStatus()))
                    .toList();
        }

        @Override
        public List<Alert> findByRuleIdAndStatusIn(String ruleId, List<AlertStatus> statuses, Pageable pageable) {
            return stored.stream()
                    .filter(a -> ruleId.equals(a.getRuleId()))
                    .filter(a -> statuses.contains(a.getStatus()))
                    .limit(pageable.getPageSize())
                    .toList();
        }

        /* ---- unused by detection ---- */
        @Override public Page<Alert> findByStatus(AlertStatus s, Pageable p) { throw unsupported(); }
        @Override public Page<Alert> findBySeverity(Severity s, Pageable p) { throw unsupported(); }
        @Override public Page<Alert> findByDecision(com.anomaly.platform.entity.DecisionState d, Pageable p) { throw unsupported(); }
        @Override public Page<Alert> findByEntity_EntityId(String entityId, Pageable p) { throw unsupported(); }
        @Override public List<Alert> findByIncident_IdOrderByCreatedAtDesc(UUID incidentId) { throw unsupported(); }
        @Override public List<Alert> findByCreatedAtGreaterThanEqual(OffsetDateTime since) { throw unsupported(); }
        @Override public java.util.Optional<Alert> findTopByEvent_IdOrderByCreatedAtDesc(UUID eventId) { throw unsupported(); }
        @Override public List<Alert> findByEvent_IdOrderByCreatedAtDesc(UUID eventId) { throw unsupported(); }
        @Override public long countByStatus(AlertStatus status) { throw unsupported(); }
        @Override public long countBySeverity(Severity severity) { throw unsupported(); }
        @Override public List<Object[]> summarizeByIncident(java.util.Collection<UUID> ids) { throw unsupported(); }
        @Override public List<Object[]> sourcesByIncident(java.util.Collection<UUID> ids) { throw unsupported(); }
        @Override public List<Object[]> countGroupedBySeverity() { throw unsupported(); }
        @Override public List<Object[]> countGroupedByStatus() { throw unsupported(); }
        @Override public List<Object[]> topEntitiesByAlertCount(Pageable pageable) { throw unsupported(); }
        @Override public List<Object[]> hourlyCounts(OffsetDateTime since) { throw unsupported(); }
        @Override public List<Object[]> hourlyCountsBySeverity(OffsetDateTime since) { throw unsupported(); }
        @Override public List<Object[]> summarizeByEntity(java.util.Collection<UUID> ids) { throw unsupported(); }
        @Override public List<Alert> findAll() { return List.copyOf(stored); }
        @Override public List<Alert> findAll(org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public Page<Alert> findAll(Pageable pageable) { throw unsupported(); }
        @Override public List<Alert> findAllById(Iterable<UUID> ids) { throw unsupported(); }
        @Override public long count() { return stored.size(); }
        @Override public void deleteById(UUID id) { throw unsupported(); }
        @Override public void delete(Alert entity) { throw unsupported(); }
        @Override public void deleteAllById(Iterable<? extends UUID> ids) { throw unsupported(); }
        @Override public void deleteAll(Iterable<? extends Alert> entities) { throw unsupported(); }
        @Override public void deleteAll() { stored.clear(); }
        @Override public <S extends Alert> List<S> saveAll(Iterable<S> entities) { throw unsupported(); }
        @Override public java.util.Optional<Alert> findById(UUID id) {
            return stored.stream().filter(a -> id.equals(a.getId())).findFirst();
        }
        @Override public boolean existsById(UUID id) { return findById(id).isPresent(); }
        @Override public void flush() { }
        @Override public <S extends Alert> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends Alert> List<S> saveAllAndFlush(Iterable<S> entities) { throw unsupported(); }
        @Override public void deleteAllInBatch(Iterable<Alert> entities) { throw unsupported(); }
        @Override public void deleteAllByIdInBatch(Iterable<UUID> ids) { throw unsupported(); }
        @Override public void deleteAllInBatch() { throw unsupported(); }
        @Override public Alert getOne(UUID id) { throw unsupported(); }
        @Override public Alert getById(UUID id) { throw unsupported(); }
        @Override public Alert getReferenceById(UUID id) { throw unsupported(); }
        @Override public <S extends Alert> java.util.Optional<S> findOne(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Alert> List<S> findAll(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Alert> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public <S extends Alert> Page<S> findAll(org.springframework.data.domain.Example<S> example, Pageable pageable) { throw unsupported(); }
        @Override public <S extends Alert> long count(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Alert> boolean exists(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends Alert, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> fn) { throw unsupported(); }
        @Override public java.util.Optional<Alert> findOne(org.springframework.data.jpa.domain.Specification<Alert> spec) { throw unsupported(); }
        @Override public List<Alert> findAll(org.springframework.data.jpa.domain.Specification<Alert> spec) { throw unsupported(); }
        @Override public Page<Alert> findAll(org.springframework.data.jpa.domain.Specification<Alert> spec, Pageable pageable) { throw unsupported(); }
        @Override public List<Alert> findAll(org.springframework.data.jpa.domain.Specification<Alert> spec, org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public long count(org.springframework.data.jpa.domain.Specification<Alert> spec) { throw unsupported(); }
        @Override public boolean exists(org.springframework.data.jpa.domain.Specification<Alert> spec) { throw unsupported(); }
        @Override public long delete(org.springframework.data.jpa.domain.Specification<Alert> spec) { throw unsupported(); }
        @Override public <S extends Alert, R> R findBy(org.springframework.data.jpa.domain.Specification<Alert> spec, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> fn) { throw unsupported(); }

        private static UnsupportedOperationException unsupported() {
            return new UnsupportedOperationException("not used by the detection engine");
        }
    }

    /** Enforces UNIQUE(alert_id, rank) the way V8 does. */
    public static final class FakeAlertFactorRepository implements AlertFactorRepository {

        public final List<AlertFactor> stored = new ArrayList<>();

        @Override
        public <S extends AlertFactor> S save(S factor) {
            boolean clash = stored.stream().anyMatch(f -> f.getAlert().getId().equals(factor.getAlert().getId())
                    && f.getRank() == factor.getRank());
            if (clash) {
                throw new org.springframework.dao.DataIntegrityViolationException(
                        "UNIQUE(alert_id, rank) violated at rank " + factor.getRank());
            }
            if (factor.getFactor().length() > 128) {
                throw new org.springframework.dao.DataIntegrityViolationException(
                        "value too long for type character varying(128)");
            }
            factor.setId(UUID.randomUUID());
            stored.add(factor);
            return factor;
        }

        @Override
        public List<AlertFactor> findByAlert_IdOrderByRankAsc(UUID alertId) {
            return stored.stream()
                    .filter(f -> f.getAlert().getId().equals(alertId))
                    .sorted(java.util.Comparator.comparingInt(AlertFactor::getRank))
                    .toList();
        }

        @Override
        public long countByAlert_Id(UUID alertId) {
            return stored.stream().filter(f -> f.getAlert().getId().equals(alertId)).count();
        }

        @Override public List<AlertFactor> findAll() { return List.copyOf(stored); }
        @Override public List<AlertFactor> findAll(org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public Page<AlertFactor> findAll(Pageable pageable) { throw unsupported(); }
        @Override public List<AlertFactor> findAllById(Iterable<UUID> ids) { throw unsupported(); }
        @Override public long count() { return stored.size(); }
        @Override public void deleteById(UUID id) { throw unsupported(); }
        @Override public void delete(AlertFactor entity) { throw unsupported(); }
        @Override public void deleteAllById(Iterable<? extends UUID> ids) { throw unsupported(); }
        @Override public void deleteAll(Iterable<? extends AlertFactor> entities) { throw unsupported(); }
        @Override public void deleteAll() { stored.clear(); }
        @Override public <S extends AlertFactor> List<S> saveAll(Iterable<S> entities) { throw unsupported(); }
        @Override public java.util.Optional<AlertFactor> findById(UUID id) { throw unsupported(); }
        @Override public boolean existsById(UUID id) { throw unsupported(); }
        @Override public void flush() { }
        @Override public <S extends AlertFactor> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends AlertFactor> List<S> saveAllAndFlush(Iterable<S> entities) { throw unsupported(); }
        @Override public void deleteAllInBatch(Iterable<AlertFactor> entities) { throw unsupported(); }
        @Override public void deleteAllByIdInBatch(Iterable<UUID> ids) { throw unsupported(); }
        @Override public void deleteAllInBatch() { throw unsupported(); }
        @Override public AlertFactor getOne(UUID id) { throw unsupported(); }
        @Override public AlertFactor getById(UUID id) { throw unsupported(); }
        @Override public AlertFactor getReferenceById(UUID id) { throw unsupported(); }
        @Override public <S extends AlertFactor> java.util.Optional<S> findOne(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends AlertFactor> List<S> findAll(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends AlertFactor> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { throw unsupported(); }
        @Override public <S extends AlertFactor> Page<S> findAll(org.springframework.data.domain.Example<S> example, Pageable pageable) { throw unsupported(); }
        @Override public <S extends AlertFactor> long count(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends AlertFactor> boolean exists(org.springframework.data.domain.Example<S> example) { throw unsupported(); }
        @Override public <S extends AlertFactor, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> fn) { throw unsupported(); }

        private static UnsupportedOperationException unsupported() {
            return new UnsupportedOperationException("not used by the detection engine");
        }
    }

    /** Incident reuse with the real key semantics: entityId:eventType, reused while active. */
    public static final class FakeIncidentService extends IncidentService {

        public final Map<String, Incident> byKey = new LinkedHashMap<>();
        public final List<Incident> created = new ArrayList<>();

        public FakeIncidentService() {
            super(null, null, null, null);
        }

        @Override
        public Incident findOrCreateIncident(Alert alert) {
            String key = alert.getEntity().getEntityId() + ":"
                    + (alert.getEvent() == null ? "UNKNOWN" : alert.getEvent().getEventType());
            Incident existing = byKey.get(key);
            if (existing != null && (existing.getStatus() == com.anomaly.platform.entity.IncidentStatus.OPEN
                    || existing.getStatus() == com.anomaly.platform.entity.IncidentStatus.INVESTIGATING)) {
                return existing;
            }
            Incident incident = new Incident();
            incident.setId(UUID.randomUUID());
            incident.setIncidentKey(existing == null ? key : key + ":" + created.size());
            incident.setStatus(com.anomaly.platform.entity.IncidentStatus.OPEN);
            byKey.put(key, incident);
            created.add(incident);
            return incident;
        }
    }

    /** Keeps every audit row so suppression and escalation decisions can be asserted. */
    public static final class RecordingAuditLogService extends AuditLogService {

        public record Row(String action, UUID resourceId, Map<String, Object> details) {
        }

        public final List<Row> rows = new ArrayList<>();

        public RecordingAuditLogService() {
            super(null);
        }

        @Override
        public com.anomaly.platform.entity.AuditLog log(String actor, String action, String resourceType,
                                                        UUID resourceId, String correlationId, Map<String, Object> details) {
            rows.add(new Row(action, resourceId, details == null ? Map.of() : new LinkedHashMap<>(details)));
            return null;
        }

        /**
         * The real service's once-per-(alert, rule, event) guard, implemented over
         * the recorded rows so the "suppression recorded once across retries"
         * behaviour is genuinely exercised rather than stubbed.
         */
        @Override
        public boolean hasSuppressionRecord(UUID alertId, String ruleId, String triggeringEventId) {
            return rows.stream().anyMatch(r -> r.action().equals(DetectionEngine.AUDIT_DETECTION_SUPPRESSED)
                    && alertId.equals(r.resourceId())
                    && ruleId.equals(r.details().get("ruleId"))
                    && triggeringEventId.equals(r.details().get("triggeringEventId")));
        }
    }

    /* ------------------------------------------------------------------ small helpers */

    public static Duration seconds(long s) {
        return Duration.ofSeconds(s);
    }
}
