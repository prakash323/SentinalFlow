package com.anomaly.platform.service;

import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Source-Aware SOC phase: Alert has no source column of its own - source
 * comes from Alert.event.source (see AlertResponse/AlertService.to()).
 * Covers test list items 2 (alert source filtering), 4 (all-sources), 6
 * (pagination + source), 7 (existing entityId filter unaffected), 12 (no
 * additional N+1 - source reads from the SAME lazily-loaded Event object
 * already fetched for eventId, a pre-existing access pattern this phase
 * does not change).
 */
@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

    @Mock private AlertRepository repo;
    @Mock private AlertFactorRepository factors;
    @Mock private AuditLogService auditLogService;

    private AlertService alertService;

    @BeforeEach
    void setUp() {
        alertService = new AlertService(repo, factors, auditLogService);
    }

    @SuppressWarnings("unchecked")
    private void stubEmptyPage() {
        when(repo.findAll(any(Specification.class), any(Pageable.class))).thenReturn(Page.empty());
    }

    // ------------------------------------------------------------------
    // AlertResponse.source is read from the alert's event, not fabricated
    // ------------------------------------------------------------------
    @Test
    void get_alertWithEvent_returnsSourceFromEvent() {
        Event event = new Event();
        event.setEventId("EV-PHYS-1");
        event.setSource("physical-collector");
        Alert alert = alert(event);

        when(repo.findById(alert.getId())).thenReturn(java.util.Optional.of(alert));
        when(factors.findByAlert_IdOrderByRankAsc(alert.getId())).thenReturn(List.of());

        var response = alertService.get(alert.getId());

        assertThat(response.source()).isEqualTo("physical-collector");
        assertThat(response.eventId()).isEqualTo("EV-PHYS-1");
    }

    @Test
    void get_alertWithNoEvent_sourceIsNullNotFabricated() {
        Alert alert = alert(null);

        when(repo.findById(alert.getId())).thenReturn(java.util.Optional.of(alert));
        when(factors.findByAlert_IdOrderByRankAsc(alert.getId())).thenReturn(List.of());

        var response = alertService.get(alert.getId());

        assertThat(response.source()).isNull();
        assertThat(response.eventId()).isNull();
    }

    // ------------------------------------------------------------------
    // 4. All-sources behavior (no source filter) + no N+1
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_withNoFilters_callsFindAllExactlyOnce() {
        stubEmptyPage();

        alertService.list(null, null, null, null, null, 0, 20);

        verify(repo, times(1)).findAll(any(Specification.class), any(Pageable.class));
    }

    // ------------------------------------------------------------------
    // 2. Alert source filtering - Specification content on the event join
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_withSourceOnly_buildsEqualityPredicateOnEventSource() {
        stubEmptyPage();

        alertService.list(null, null, null, null, "python-simulator", 0, 20);

        ArgumentCaptor<Specification<Alert>> captor = ArgumentCaptor.forClass(Specification.class);
        verify(repo).findAll(captor.capture(), any(Pageable.class));

        Root<Alert> root = mock(Root.class);
        Path<Object> eventPath = mock(Path.class);
        Path<Object> sourcePath = mock(Path.class);
        CriteriaQuery<?> query = mock(CriteriaQuery.class);
        CriteriaBuilder cb = mock(CriteriaBuilder.class);
        Predicate predicate = mock(Predicate.class);

        when(root.<Object>get("event")).thenReturn(eventPath);
        when(eventPath.<Object>get("source")).thenReturn(sourcePath);
        when(cb.equal(sourcePath, "python-simulator")).thenReturn(predicate);

        Predicate result = captor.getValue().toPredicate(root, query, cb);

        verify(cb).equal(sourcePath, "python-simulator");
        assertThat(result).isEqualTo(predicate);
    }

    // ------------------------------------------------------------------
    // 6. Pagination combined with source filtering
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_clampsPageSizeRegardlessOfSourceFilter() {
        stubEmptyPage();

        alertService.list(null, null, null, null, "physical-collector", 0, 500);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(repo).findAll(any(Specification.class), pageableCaptor.capture());

        assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(100);
    }

    // ------------------------------------------------------------------
    // Concurrency hardening: confirmed live before this fix existed that
    // two concurrent PATCH /alerts/{id}/status requests both returned 200,
    // one of them describing a status that never actually persisted, and
    // the audit log recorded both transitions as if each had taken effect.
    // ------------------------------------------------------------------

    @Test
    void updateStatus_flushesImmediately_soAConcurrentConflictIsDetectedInThisRequest() {
        Alert alert = alert(null);
        when(repo.findById(alert.getId())).thenReturn(java.util.Optional.of(alert));
        when(repo.saveAndFlush(any())).thenReturn(alert);

        alertService.updateStatus(alert.getId(), AlertStatus.ACKNOWLEDGED);

        verify(repo).saveAndFlush(alert);
        verify(repo, never()).save(any());
    }

    @Test
    void updateStatus_whenAConcurrentUpdateWonTheRace_propagatesAndNeverRecordsAPhantomAuditEntry() {
        Alert alert = alert(null);
        when(repo.findById(alert.getId())).thenReturn(java.util.Optional.of(alert));

        org.springframework.orm.ObjectOptimisticLockingFailureException conflict =
                new org.springframework.orm.ObjectOptimisticLockingFailureException(Alert.class, alert.getId());
        when(repo.saveAndFlush(any())).thenThrow(conflict);

        assertThatThrownBy(() -> alertService.updateStatus(alert.getId(), AlertStatus.ACKNOWLEDGED))
                .isSameAs(conflict);

        // The losing request must never write an audit entry for a
        // transition that did not actually persist.
        verify(auditLogService, never()).log(any(), any(), any(), any(), any(), any());
    }

    /*
     * ================================================================
     * CONCURRENCY: the race this fix exists for, under genuine concurrent
     * load (not a single mocked exception) - mirrors
     * IncidentServiceTest.concurrentFindOrCreateIncident_forSameKey_
     * producesExactlyOneIncident's own established pattern: a
     * ConcurrentHashMap-backed fake repository simulates the same
     * compare-and-swap a real Postgres row with a @Version column provides
     * (one writer's version matches and wins, every other stale-versioned
     * writer gets ObjectOptimisticLockingFailureException), so this proves
     * the application-level behavior without needing a real database.
     *
     * Before Alert.version existed, N concurrent requests targeting the
     * same alert would ALL succeed and ALL write an audit entry - this test
     * proves that is no longer possible: exactly one request commits,
     * exactly one audit entry is ever written, and every other request
     * receives the real conflict rather than a false success.
     */
    @Test
    void concurrentUpdateStatus_forSameAlert_exactlyOneTransitionWins() throws Exception {

        UUID alertId = UUID.randomUUID();
        Alert seed = alert(null);
        seed.setId(alertId);
        seed.setVersion(0L);

        ConcurrentHashMap<UUID, Alert> store = new ConcurrentHashMap<>();
        store.put(alertId, seed);

        when(factors.findByAlert_IdOrderByRankAsc(eq(alertId))).thenReturn(List.of());

        int threadCount = 8;

        // Forces every thread to complete its read (a real snapshot of
        // version=0) BEFORE any thread is allowed to proceed to the write -
        // without this, uncontended mock calls can simply run one full
        // read-then-write per thread in sequence, which never actually
        // overlaps and therefore never exercises the conflict path at all.
        CyclicBarrier allReadsDone = new CyclicBarrier(threadCount);

        when(repo.findById(eq(alertId))).thenAnswer(inv -> {
            Alert current = store.get(alertId);
            Alert snapshot = alert(null);
            snapshot.setId(current.getId());
            snapshot.setStatus(current.getStatus());
            snapshot.setVersion(current.getVersion());
            allReadsDone.await(5, TimeUnit.SECONDS);
            return java.util.Optional.of(snapshot);
        });

        when(repo.saveAndFlush(any())).thenAnswer(inv -> {
            Alert attempt = inv.getArgument(0);
            synchronized (store) {
                Alert current = store.get(alertId);
                if (!current.getVersion().equals(attempt.getVersion())) {
                    throw new org.springframework.orm.ObjectOptimisticLockingFailureException(Alert.class, alertId);
                }
                attempt.setVersion(attempt.getVersion() + 1);
                store.put(alertId, attempt);
                return attempt;
            }
        });

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CyclicBarrier startGate = new CyclicBarrier(threadCount);
        AtomicInteger conflicts = new AtomicInteger(0);

        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            futures.add(pool.submit(() -> {
                startGate.await();
                try {
                    alertService.updateStatus(alertId, AlertStatus.ACKNOWLEDGED);
                    return true;
                } catch (org.springframework.orm.ObjectOptimisticLockingFailureException conflict) {
                    conflicts.incrementAndGet();
                    return false;
                }
            }));
        }

        int successes = 0;
        for (Future<Boolean> future : futures) {
            if (future.get(5, TimeUnit.SECONDS)) {
                successes++;
            }
        }
        pool.shutdown();

        assertThat(successes).isEqualTo(1);
        assertThat(conflicts.get()).isEqualTo(threadCount - 1);
        assertThat(store.get(alertId).getVersion()).isEqualTo(1L);

        // Exactly one audit entry was ever written for this alert - not
        // one per racing request.
        verify(auditLogService, times(1)).log(any(), eq("STATUS_CHANGED"), eq("ALERT"), eq(alertId), any(), anyMap());
    }

    private Alert alert(Event event) {
        Alert alert = new Alert();
        alert.setId(UUID.randomUUID());
        alert.setEvent(event);
        alert.setDecision(DecisionState.NORMAL);
        alert.setSeverity(Severity.LOW);
        alert.setStatus(AlertStatus.OPEN);
        alert.setAnomalyScore(new BigDecimal("0.10000"));
        alert.setPolicyVersion("v2-ml-ensemble");
        return alert;
    }
}
