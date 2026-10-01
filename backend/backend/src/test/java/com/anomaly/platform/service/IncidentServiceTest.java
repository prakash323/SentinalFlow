package com.anomaly.platform.service;

import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.IncidentRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Phase 2 focused tests for IncidentService.findOrCreateIncident - the
 * exact logic responsible for correlating repeated alerts on the same
 * entity/eventType into one incident instead of creating a new incident
 * every time. This had zero test coverage despite being on the direct
 * path from "alert created" to "incident correlation" in the detection
 * pipeline traced in Phase 1.
 *
 * Phase 7A adds the PlatformTransactionManager constructor dependency
 * (needed for the REQUIRES_NEW insert-isolation fix) and a concurrency
 * test proving the DB-unique-constraint-backed race fix actually works
 * under real concurrent access, not just sequentially.
 */
@ExtendWith(MockitoExtension.class)
class IncidentServiceTest {

    @Mock
    private IncidentRepository incidentRepository;

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private PlatformTransactionManager transactionManager;

    private IncidentService incidentService;

    @BeforeEach
    void setUp() {
        incidentService = new IncidentService(
                incidentRepository, alertRepository, auditLogService, transactionManager
        );
    }

    private Alert alertFor(String entityId, String eventType) {

        EntityProfile entity = new EntityProfile();
        entity.setId(UUID.randomUUID());
        entity.setEntityId(entityId);

        Event event = new Event();
        event.setId(UUID.randomUUID());
        event.setEventType(eventType);

        Alert alert = new Alert();
        alert.setEntity(entity);
        alert.setEvent(event);

        return alert;
    }

    @Test
    void noExistingIncident_createsNewOpenIncident_withDeterministicKey() {

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.empty());
        when(incidentRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            Incident incident = invocation.getArgument(0);
            incident.setId(UUID.randomUUID());
            return incident;
        });

        Incident result = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));

        assertThat(result.getIncidentKey()).isEqualTo("USER-1:LOGIN");
        assertThat(result.getStatus()).isEqualTo(IncidentStatus.OPEN);

        verify(incidentRepository).saveAndFlush(any());
        verify(auditLogService).log(
                eq("system"), eq("INCIDENT_CREATED"), eq("INCIDENT"), any(), any(), anyMap()
        );
    }

    @Test
    void openIncidentAlreadyExists_reusesIt_insteadOfCreatingADuplicate() {

        Incident existing = new Incident();
        existing.setId(UUID.randomUUID());
        existing.setIncidentKey("USER-1:LOGIN");
        existing.setStatus(IncidentStatus.OPEN);

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.of(existing));

        Incident result = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));

        assertThat(result).isSameAs(existing);
        verify(incidentRepository, never()).saveAndFlush(any());
        verify(auditLogService, never()).log(any(), any(), any(), any(), any(), anyMap());
    }

    @Test
    void investigatingIncidentAlreadyExists_reusesIt_insteadOfCreatingADuplicate() {

        Incident existing = new Incident();
        existing.setId(UUID.randomUUID());
        existing.setIncidentKey("USER-1:LOGIN");
        existing.setStatus(IncidentStatus.INVESTIGATING);

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.of(existing));

        Incident result = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));

        assertThat(result).isSameAs(existing);
        verify(incidentRepository, never()).saveAndFlush(any());
    }

    @Test
    void resolvedIncidentAlreadyExists_createsANewIncident_withADifferentKey() {

        Incident resolved = new Incident();
        resolved.setId(UUID.randomUUID());
        resolved.setIncidentKey("USER-1:LOGIN");
        resolved.setStatus(IncidentStatus.RESOLVED);

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.of(resolved));
        when(incidentRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            Incident incident = invocation.getArgument(0);
            incident.setId(UUID.randomUUID());
            return incident;
        });

        Incident result = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));

        assertThat(result).isNotSameAs(resolved);
        assertThat(result.getIncidentKey()).startsWith("USER-1:LOGIN:");
        assertThat(result.getStatus()).isEqualTo(IncidentStatus.OPEN);

        verify(incidentRepository).saveAndFlush(any());
        verify(auditLogService).log(
                eq("system"), eq("INCIDENT_CREATED"), eq("INCIDENT"), any(), any(), anyMap()
        );
    }

    @Test
    void baseIncidentResolved_butActiveFollowUpExists_reusesTheFollowUp_insteadOfOpeningAnotherOne() {

        Incident resolved = new Incident();
        resolved.setId(UUID.randomUUID());
        resolved.setIncidentKey("USER-1:LOGIN");
        resolved.setStatus(IncidentStatus.RESOLVED);

        Incident activeFollowUp = new Incident();
        activeFollowUp.setId(UUID.randomUUID());
        activeFollowUp.setIncidentKey("USER-1:LOGIN:1789791970599");
        activeFollowUp.setStatus(IncidentStatus.OPEN);

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.of(resolved));
        when(incidentRepository.findActiveByKeyFamily(
                eq("USER-1:LOGIN"), eq("USER-1:LOGIN:"), eq("USER-1:LOGIN:".length()), any(), any()
        )).thenReturn(java.util.List.of(activeFollowUp));

        Incident result = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));

        assertThat(result).isSameAs(activeFollowUp);
        verify(incidentRepository, never()).saveAndFlush(any());
    }

    @Test
    void closedIncidentAlreadyExists_createsANewIncident_ratherThanReopeningTheOldOne() {

        Incident closed = new Incident();
        closed.setId(UUID.randomUUID());
        closed.setIncidentKey("USER-1:LOGIN");
        closed.setStatus(IncidentStatus.CLOSED);

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.of(closed));
        when(incidentRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            Incident incident = invocation.getArgument(0);
            incident.setId(UUID.randomUUID());
            return incident;
        });

        Incident result = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));

        assertThat(result.getId()).isNotEqualTo(closed.getId());
        assertThat(result.getStatus()).isEqualTo(IncidentStatus.OPEN);
    }

    @Test
    void differentEventType_forSameEntity_getsItsOwnIncident_notLumpedTogether() {

        when(incidentRepository.findByIncidentKey("USER-1:LOGIN")).thenReturn(Optional.empty());
        when(incidentRepository.findByIncidentKey("USER-1:TRANSACTION")).thenReturn(Optional.empty());
        when(incidentRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            Incident incident = invocation.getArgument(0);
            incident.setId(UUID.randomUUID());
            return incident;
        });

        Incident loginIncident = incidentService.findOrCreateIncident(alertFor("USER-1", "LOGIN"));
        Incident transactionIncident = incidentService.findOrCreateIncident(alertFor("USER-1", "TRANSACTION"));

        assertThat(loginIncident.getIncidentKey()).isEqualTo("USER-1:LOGIN");
        assertThat(transactionIncident.getIncidentKey()).isEqualTo("USER-1:TRANSACTION");
        assertThat(loginIncident.getIncidentKey()).isNotEqualTo(transactionIncident.getIncidentKey());
    }

    /*
     * ================================================================
     * CONCURRENCY: the race this fix exists for
     * ================================================================
     *
     * incidentRepository is faked (not stubbed with canned answers) with
     * a ConcurrentHashMap using putIfAbsent for the same atomicity a real
     * Postgres UNIQUE constraint on incident_key provides: exactly one
     * concurrent insert for a given key can win, and saveAndFlush throws
     * DataIntegrityViolationException for every loser, exactly as a real
     * flush against Postgres would. transactionManager is an unstubbed
     * mock - TransactionTemplate.execute() only needs getTransaction/
     * commit/rollback to be callable, not backed by a real database, so
     * this test proves the application-level race-handling logic in
     * IncidentService itself, independent of any real DB round-trip.
     */
    @Test
    void concurrentFindOrCreateIncident_forSameKey_producesExactlyOneIncident() throws Exception {

        ConcurrentHashMap<String, Incident> store = new ConcurrentHashMap<>();

        when(incidentRepository.findByIncidentKey(anyString()))
                .thenAnswer(invocation -> Optional.ofNullable(store.get(invocation.getArgument(0, String.class))));

        when(incidentRepository.saveAndFlush(any())).thenAnswer(invocation -> {

            Incident candidate = invocation.getArgument(0);
            candidate.setId(UUID.randomUUID());

            Incident winner = store.putIfAbsent(candidate.getIncidentKey(), candidate);

            if (winner != null) {
                throw new DataIntegrityViolationException(
                        "duplicate key value violates unique constraint \"incidents_incident_key_key\""
                );
            }

            return candidate;
        });

        int threadCount = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CyclicBarrier startGate = new CyclicBarrier(threadCount);

        List<Future<Incident>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {

            futures.add(pool.submit(() -> {
                startGate.await();
                return incidentService.findOrCreateIncident(alertFor("USER-RACE", "LOGIN"));
            }));
        }

        List<Incident> results = new ArrayList<>();

        for (Future<Incident> future : futures) {
            results.add(future.get(5, TimeUnit.SECONDS));
        }

        pool.shutdown();

        assertThat(results).hasSize(threadCount);

        assertThat(results)
                .allSatisfy(incident -> assertThat(incident.getIncidentKey()).isEqualTo("USER-RACE:LOGIN"));

        // All callers obtained the SAME incident - not merely equal keys.
        Set<UUID> distinctIds = results.stream().map(Incident::getId).collect(Collectors.toSet());
        assertThat(distinctIds).hasSize(1);

        // Exactly one incident was ever actually stored.
        assertThat(store).hasSize(1);

        // Exactly one caller was the winner that recorded creation.
        verify(auditLogService, times(1)).log(
                eq("system"), eq("INCIDENT_CREATED"), eq("INCIDENT"), any(), any(), anyMap()
        );
    }

    /*
     * Confirms the transaction template plumbing itself: an unstubbed
     * PlatformTransactionManager mock is sufficient for the isolated
     * insert to run and return normally (no NPE, no real DB needed).
     */
    @Test
    void transactionManager_getTransactionAndCommit_areInvokedForEachInsert() {

        when(incidentRepository.findByIncidentKey("USER-2:LOGIN")).thenReturn(Optional.empty());
        when(transactionManager.getTransaction(any(TransactionDefinition.class)))
                .thenReturn(new SimpleTransactionStatus());
        when(incidentRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            Incident incident = invocation.getArgument(0);
            incident.setId(UUID.randomUUID());
            return incident;
        });

        incidentService.findOrCreateIncident(alertFor("USER-2", "LOGIN"));

        verify(transactionManager).getTransaction(any(TransactionDefinition.class));
        verify(transactionManager).commit(any(TransactionStatus.class));
        verify(transactionManager, never()).rollback(any());
    }

    /*
     * ================================================================
     * SOURCE-AWARE SOC PHASE
     * ================================================================
     *
     * Incident has no source column of its own - IncidentResponse.sources
     * is derived from AlertRepository.sourcesByIncident, a batched query
     * returning one comma-joined string per incident (see that method's
     * doc comment for why an incident can genuinely have more than one
     * distinct source). These tests cover the parsing/assembly logic
     * directly (fully mockable, no JPA needed); the EXISTS-subquery
     * source filter itself is proven against the live database instead
     * (see the phase's final report) - this project has no
     * @DataJpaTest/embedded-database infrastructure to mock a JPA
     * Subquery meaningfully without just re-testing Spring Data's own
     * internals.
     */

    private Incident incidentWithId(UUID id) {
        Incident incident = new Incident();
        incident.setId(id);
        incident.setIncidentKey("USER-1:LOGIN:" + id);
        incident.setStatus(IncidentStatus.OPEN);
        incident.setSummary("Anomalous LOGIN activity detected for entity USER-1");
        return incident;
    }

    @Test
    void list_singleSourceIncident_sourcesHasOneEntry() {
        Incident incident = incidentWithId(UUID.randomUUID());

        when(incidentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(incident)));
        when(alertRepository.summarizeByIncident(List.of(incident.getId())))
                .thenReturn(List.<Object[]>of(new Object[]{incident.getId(), 3L, 4, new java.math.BigDecimal("1.00000")}));
        when(alertRepository.sourcesByIncident(List.of(incident.getId())))
                .thenReturn(List.<Object[]>of(new Object[]{incident.getId(), "python-simulator"}));

        var page = incidentService.list(null, null, null, 0, 20);

        assertThat(page.content()).hasSize(1);
        assertThat(page.content().get(0).sources()).containsExactly("python-simulator");
    }

    @Test
    void list_multiSourceIncident_sourcesHasEveryDistinctSource() {
        // Confirmed against live data during the audit: an incident's
        // correlation key is entityId:eventType, not source, so this is a
        // real scenario, not a hypothetical one.
        Incident incident = incidentWithId(UUID.randomUUID());

        when(incidentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(incident)));
        when(alertRepository.summarizeByIncident(List.of(incident.getId())))
                .thenReturn(List.<Object[]>of(new Object[]{incident.getId(), 5L, 4, new java.math.BigDecimal("1.00000")}));
        when(alertRepository.sourcesByIncident(List.of(incident.getId())))
                .thenReturn(List.<Object[]>of(new Object[]{incident.getId(), "physical-collector,python-simulator"}));

        var page = incidentService.list(null, null, null, 0, 20);

        assertThat(page.content().get(0).sources())
                .containsExactlyInAnyOrder("physical-collector", "python-simulator");
    }

    @Test
    void list_incidentWithNoSourceRow_sourcesIsEmptyNotNull() {
        Incident incident = incidentWithId(UUID.randomUUID());

        when(incidentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(incident)));
        when(alertRepository.summarizeByIncident(List.of(incident.getId()))).thenReturn(List.of());
        when(alertRepository.sourcesByIncident(List.of(incident.getId()))).thenReturn(List.of());

        var page = incidentService.list(null, null, null, 0, 20);

        assertThat(page.content().get(0).sources()).isEmpty();
    }

    @Test
    void list_callsSourcesByIncidentExactlyOnceForTheWholePage_noNPlusOne() {
        Incident a = incidentWithId(UUID.randomUUID());
        Incident b = incidentWithId(UUID.randomUUID());

        when(incidentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(a, b)));
        when(alertRepository.summarizeByIncident(any())).thenReturn(List.of());
        when(alertRepository.sourcesByIncident(any())).thenReturn(List.of());

        incidentService.list(null, null, null, 0, 20);

        verify(alertRepository, times(1)).sourcesByIncident(any());
    }

    @Test
    void list_withSourceFilter_stillCallsFindAllWithSpecification() {
        when(incidentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of()));

        incidentService.list(null, null, "physical-collector", 0, 20);

        verify(incidentRepository, times(1)).findAll(any(Specification.class), any(Pageable.class));
    }

    /*
     * ================================================================
     * CONCURRENCY HARDENING
     * ================================================================
     * updateStatus now flushes the incident's own save immediately (same
     * reasoning as AlertService.updateStatus - see AlertServiceTest), and
     * synchronizeAlerts flushes its batch save so a concurrent direct
     * PATCH on one of this incident's alerts is detected and rolls back
     * this whole status change atomically, rather than silently
     * overwriting the concurrent change with stale data.
     */

    @Test
    void updateStatus_flushesTheIncidentSaveImmediately() {
        Incident incident = incidentWithId(UUID.randomUUID());
        incident.setStatus(IncidentStatus.OPEN);

        when(incidentRepository.findById(incident.getId())).thenReturn(Optional.of(incident));
        when(incidentRepository.saveAndFlush(any())).thenReturn(incident);
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incident.getId())).thenReturn(List.of());

        incidentService.updateStatus(incident.getId(), IncidentStatus.INVESTIGATING);

        verify(incidentRepository).saveAndFlush(incident);
        verify(incidentRepository, never()).save(any());
    }

    @Test
    void updateStatus_whenResolvingIncident_synchronizesAndFlushesLinkedAlerts() {
        Incident incident = incidentWithId(UUID.randomUUID());
        incident.setStatus(IncidentStatus.INVESTIGATING);

        Alert linkedAlert = alertFor("USER-1", "LOGIN");
        linkedAlert.setId(UUID.randomUUID());
        linkedAlert.setStatus(com.anomaly.platform.entity.AlertStatus.OPEN);

        when(incidentRepository.findById(incident.getId())).thenReturn(Optional.of(incident));
        when(incidentRepository.saveAndFlush(any())).thenReturn(incident);
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incident.getId()))
                .thenReturn(new ArrayList<>(List.of(linkedAlert)));

        incidentService.updateStatus(incident.getId(), IncidentStatus.RESOLVED);

        verify(alertRepository).saveAll(any());
        verify(alertRepository).flush();
        assertThat(linkedAlert.getStatus()).isEqualTo(com.anomaly.platform.entity.AlertStatus.RESOLVED);
    }
}
