package com.anomaly.platform.service;

import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Independent deterministic detection (P1). These tests exercise
 * DeterministicRuleService directly (not through EventProcessingService -
 * see EventProcessingServiceTest for the "ML down, rule still fires"
 * integration-level proof of independence).
 */
@ExtendWith(MockitoExtension.class)
class DeterministicRuleServiceTest {

    @Mock private EventRepository eventRepository;
    @Mock private AlertRepository alertRepository;
    @Mock private AlertFactorRepository alertFactorRepository;
    @Mock private IncidentService incidentService;
    @Mock private AuditLogService auditLogService;

    private DeterministicRuleService service;

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-09-30T12:00:00Z");

    @BeforeEach
    void setUp() {
        service = new DeterministicRuleService(
                eventRepository, alertRepository, alertFactorRepository, incidentService, auditLogService);
    }

    // Only the tests where a rule actually fires need the alert to be
    // persistable and an incident to exist - stubbing this unconditionally
    // in setUp() would trip Mockito's strict-stubbing check on every
    // negative-path test that never reaches these calls.
    private void stubAlertPersistence() {
        when(alertRepository.save(any())).thenAnswer(inv -> {
            Alert a = inv.getArgument(0);
            if (a.getId() == null) {
                a.setId(UUID.randomUUID());
            }
            return a;
        });
        Incident incident = new Incident();
        incident.setId(UUID.randomUUID());
        when(incidentService.findOrCreateIncident(any())).thenReturn(incident);
    }

    private EntityProfile entity(String entityId) {
        EntityProfile e = new EntityProfile();
        e.setId(UUID.randomUUID());
        e.setEntityId(entityId);
        e.setEntityType("HOST");
        return e;
    }

    private Event event(EntityProfile entity, String eventType, OffsetDateTime occurredAt, Map<String, Object> payload) {
        Event e = new Event();
        e.setId(UUID.randomUUID());
        e.setEventId("EV-" + UUID.randomUUID());
        e.setEntity(entity);
        e.setEventType(eventType);
        e.setEventVersion("v1");
        e.setOccurredAt(occurredAt);
        e.setSource("physical-collector");
        e.setPayload(payload);
        return e;
    }

    private void stubEventsOfType(String entityId, String eventType, List<Event> events) {
        when(eventRepository.findByEntity_EntityIdAndEventType(eq(entityId), eq(eventType), any(Pageable.class)))
                .thenReturn(new PageImpl<>(events));
    }

    // ---------------------------------------------------------------
    // AUTH_BURST
    // ---------------------------------------------------------------

    @Test
    void authBurst_fires_whenFailureCountReachesThreshold() {

        stubAlertPersistence();
        EntityProfile ent = entity("HOST-1");
        List<Event> logins = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusMinutes(4 - i),
                    Map.of("loginSuccess", false)));
        }
        stubEventsOfType("HOST-1", "LOGIN", logins);

        Event triggering = logins.get(logins.size() - 1);
        when(alertRepository.existsByEvent_IdAndRuleId(triggering.getId(), "AUTH_BURST")).thenReturn(false);
        when(alertRepository.findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                eq("HOST-1"), eq("AUTH_BURST"), any())).thenReturn(java.util.Optional.empty());

        service.evaluate(triggering);

        ArgumentCaptor<Alert> captor = ArgumentCaptor.forClass(Alert.class);
        verify(alertRepository, times(2)).save(captor.capture());
        Alert saved = captor.getValue();
        assertThat(saved.getRuleId()).isEqualTo("AUTH_BURST");
        assertThat(saved.getPrediction()).isNull();
        assertThat(saved.getDecision().name()).isEqualTo("SUSPICIOUS");

        verify(auditLogService).log(eq("system"), eq("DETECTION_CREATED"), eq("ALERT"), any(), any(), any());
    }

    @Test
    void authBurst_doesNotFire_belowThreshold() {

        EntityProfile ent = entity("HOST-2");
        List<Event> logins = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusMinutes(3 - i), Map.of("loginSuccess", false)));
        }
        stubEventsOfType("HOST-2", "LOGIN", logins);

        service.evaluate(logins.get(logins.size() - 1));

        verify(alertRepository, never()).save(any());
    }

    @Test
    void authBurst_ignoresSuccessfulLogin() {

        EntityProfile ent = entity("HOST-3");
        Event success = event(ent, "LOGIN", NOW, Map.of("loginSuccess", true));

        service.evaluate(success);

        verify(eventRepository, never()).findByEntity_EntityIdAndEventType(anyString(), anyString(), any());
        verify(alertRepository, never()).save(any());
    }

    @Test
    void authBurst_ignoresFailuresOutsideTheTimeWindow() {

        EntityProfile ent = entity("HOST-4");
        List<Event> logins = new ArrayList<>();
        // 4 failures long ago (outside the 5-minute window) + 1 recent -> only 1 counts.
        for (int i = 0; i < 4; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusHours(2).minusMinutes(i), Map.of("loginSuccess", false)));
        }
        Event recent = event(ent, "LOGIN", NOW, Map.of("loginSuccess", false));
        logins.add(recent);
        stubEventsOfType("HOST-4", "LOGIN", logins);

        service.evaluate(recent);

        verify(alertRepository, never()).save(any());
    }

    @Test
    void authBurst_suppressed_whileAPreviousActiveAlertExists() {

        EntityProfile ent = entity("HOST-5");
        List<Event> logins = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusMinutes(4 - i), Map.of("loginSuccess", false)));
        }
        stubEventsOfType("HOST-5", "LOGIN", logins);

        Event triggering = logins.get(logins.size() - 1);
        when(alertRepository.existsByEvent_IdAndRuleId(triggering.getId(), "AUTH_BURST")).thenReturn(false);

        Alert existingActive = new Alert();
        existingActive.setId(UUID.randomUUID());
        existingActive.setStatus(AlertStatus.OPEN);
        when(alertRepository.findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                eq("HOST-5"), eq("AUTH_BURST"), any())).thenReturn(java.util.Optional.of(existingActive));

        service.evaluate(triggering);

        verify(alertRepository, never()).save(any());
        verify(auditLogService).log(eq("system"), eq("DETECTION_SUPPRESSED"), eq("ALERT"),
                eq(existingActive.getId()), any(), any());
    }

    // Rules run on every processing attempt; while the ML service is down an
    // event is retried many times, and each attempt used to write another
    // identical DETECTION_SUPPRESSED audit row.
    @Test
    void authBurst_suppressionIsRecordedOnce_acrossRetriedAttemptsOfTheSameEvent() {

        EntityProfile ent = entity("HOST-6");
        List<Event> logins = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusMinutes(4 - i), Map.of("loginSuccess", false)));
        }
        stubEventsOfType("HOST-6", "LOGIN", logins);
        Event triggering = logins.get(logins.size() - 1);
        when(alertRepository.existsByEvent_IdAndRuleId(triggering.getId(), "AUTH_BURST")).thenReturn(false);
        Alert existingActive = new Alert();
        existingActive.setId(UUID.randomUUID());
        existingActive.setStatus(AlertStatus.OPEN);
        when(alertRepository.findTopByEntity_EntityIdAndRuleIdAndStatusInOrderByCreatedAtDesc(
                eq("HOST-6"), eq("AUTH_BURST"), any())).thenReturn(java.util.Optional.of(existingActive));
        when(auditLogService.hasSuppressionRecord(existingActive.getId(), "AUTH_BURST", triggering.getEventId()))
                .thenReturn(false, true, true);   // recorded by attempt 1

        service.evaluate(triggering);   // attempt 1
        service.evaluate(triggering);   // retry
        service.evaluate(triggering);   // retry

        verify(auditLogService, times(1)).log(eq("system"), eq("DETECTION_SUPPRESSED"), eq("ALERT"),
                eq(existingActive.getId()), any(), any());
        verify(alertRepository, never()).save(any());
    }

    @Test
    void authBurst_idempotent_sameTriggeringEventRedelivered() {

        EntityProfile ent = entity("HOST-6");
        List<Event> logins = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusMinutes(4 - i), Map.of("loginSuccess", false)));
        }
        stubEventsOfType("HOST-6", "LOGIN", logins);

        Event triggering = logins.get(logins.size() - 1);
        when(alertRepository.existsByEvent_IdAndRuleId(triggering.getId(), "AUTH_BURST")).thenReturn(true);

        service.evaluate(triggering);

        verify(alertRepository, never()).save(any());
        verify(incidentService, never()).findOrCreateIncident(any());
    }

    // ---------------------------------------------------------------
    // NEW_PROCESS_EXTERNAL_CONNECTION
    // ---------------------------------------------------------------

    private Map<String, Object> processStartPayload(long pid) {
        Map<String, Object> p = new HashMap<>();
        p.put("pid", pid);
        p.put("processName", "python.exe");
        return p;
    }

    private String iso(OffsetDateTime t) {
        return t.withOffsetSameInstant(ZoneOffset.UTC)
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));
    }

    @Test
    void newProcessConnection_fires_whenCorrelatedProcessStartIsRecent() {

        stubAlertPersistence();
        EntityProfile ent = entity("HOST-7");
        OffsetDateTime processStartTime = NOW.minusMinutes(1);
        Event processStart = event(ent, "PROCESS_START", processStartTime, processStartPayload(5216));
        stubEventsOfType("HOST-7", "PROCESS_START", List.of(processStart));

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 5216);
        netPayload.put("processCreateTime", iso(processStartTime));
        netPayload.put("remoteAddress", "2606:4700:10::6814:179a");

        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);
        when(alertRepository.existsByEvent_IdAndRuleId(netConn.getId(), "NEW_PROCESS_EXTERNAL_CONNECTION"))
                .thenReturn(false);

        service.evaluate(netConn);

        verify(alertRepository, times(2)).save(any());
        verify(auditLogService).log(eq("system"), eq("DETECTION_CREATED"), eq("ALERT"), any(), any(), any());
    }

    @Test
    void newProcessConnection_doesNotFire_whenNoCorrelatedProcessStart() {

        EntityProfile ent = entity("HOST-8");
        stubEventsOfType("HOST-8", "PROCESS_START", List.of());

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 9999);
        netPayload.put("processCreateTime", iso(NOW.minusMinutes(1)));
        netPayload.put("remoteAddress", "93.184.216.34");

        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);

        service.evaluate(netConn);

        verify(alertRepository, never()).save(any());
    }

    @Test
    void newProcessConnection_doesNotFire_whenRemoteAddressIsLoopback() {

        EntityProfile ent = entity("HOST-9");

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 100);
        netPayload.put("processCreateTime", iso(NOW.minusMinutes(1)));
        netPayload.put("remoteAddress", "127.0.0.1");

        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);

        service.evaluate(netConn);

        verify(eventRepository, never()).findByEntity_EntityIdAndEventType(anyString(), eq("PROCESS_START"), any());
        verify(alertRepository, never()).save(any());
    }

    @Test
    void newProcessConnection_doesNotFire_whenProcessStartIsOlderThanRecencyWindow() {

        EntityProfile ent = entity("HOST-10");
        OffsetDateTime staleProcessStart = NOW.minusMinutes(30);
        Event processStart = event(ent, "PROCESS_START", staleProcessStart, processStartPayload(42));
        stubEventsOfType("HOST-10", "PROCESS_START", List.of(processStart));

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 42);
        netPayload.put("processCreateTime", iso(staleProcessStart));
        netPayload.put("remoteAddress", "93.184.216.34");

        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);

        service.evaluate(netConn);

        verify(alertRepository, never()).save(any());
    }

    @Test
    void newProcessConnection_idempotent_sameTriggeringEventRedelivered() {

        EntityProfile ent = entity("HOST-11");
        OffsetDateTime processStartTime = NOW.minusMinutes(1);
        Event processStart = event(ent, "PROCESS_START", processStartTime, processStartPayload(7));
        stubEventsOfType("HOST-11", "PROCESS_START", List.of(processStart));

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 7);
        netPayload.put("processCreateTime", iso(processStartTime));
        netPayload.put("remoteAddress", "93.184.216.34");

        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);
        when(alertRepository.existsByEvent_IdAndRuleId(netConn.getId(), "NEW_PROCESS_EXTERNAL_CONNECTION"))
                .thenReturn(true);

        service.evaluate(netConn);

        verify(alertRepository, never()).save(any());
    }

    // Regression: one new process opening many connections used to raise one
    // alert per connection (27 OPEN alerts for a single pid on the physical host).
    @Test
    void newProcessConnection_suppressed_whileAnActiveAlertExistsForTheSameProcess() {

        EntityProfile ent = entity("HOST-15");
        OffsetDateTime processStartTime = NOW.minusMinutes(2);
        Event processStart = event(ent, "PROCESS_START", processStartTime, processStartPayload(16868));
        stubEventsOfType("HOST-15", "PROCESS_START", List.of(processStart));

        Map<String, Object> firstConnPayload = new HashMap<>();
        firstConnPayload.put("pid", 16868);
        firstConnPayload.put("processCreateTime", iso(processStartTime));
        firstConnPayload.put("remoteAddress", "93.184.216.34");
        Alert active = new Alert();
        active.setId(UUID.randomUUID());
        active.setRuleId("NEW_PROCESS_EXTERNAL_CONNECTION");
        active.setStatus(AlertStatus.OPEN);
        active.setEvent(event(ent, "NETWORK_CONNECTION", NOW.minusMinutes(1), firstConnPayload));
        when(alertRepository.findByEntity_EntityIdAndRuleIdAndStatusIn(
                eq("HOST-15"), eq("NEW_PROCESS_EXTERNAL_CONNECTION"), any()))
                .thenReturn(List.of(active));

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 16868);
        netPayload.put("processCreateTime", iso(processStartTime));
        netPayload.put("remoteAddress", "151.101.1.69");
        Event secondConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);

        service.evaluate(secondConn);

        verify(alertRepository, never()).save(any());
        verify(auditLogService).log(eq("system"), eq("DETECTION_SUPPRESSED"), eq("ALERT"),
                eq(active.getId()), any(), any());
    }

    @Test
    void newProcessConnection_stillFires_forADifferentProcessWhileAnotherProcessHasAnActiveAlert() {

        stubAlertPersistence();
        EntityProfile ent = entity("HOST-16");
        OffsetDateTime processStartTime = NOW.minusMinutes(1);
        Event processStart = event(ent, "PROCESS_START", processStartTime, processStartPayload(2001));
        stubEventsOfType("HOST-16", "PROCESS_START", List.of(processStart));

        Map<String, Object> otherProcessPayload = new HashMap<>();
        otherProcessPayload.put("pid", 1999);
        otherProcessPayload.put("processCreateTime", iso(NOW.minusMinutes(3)));
        otherProcessPayload.put("remoteAddress", "93.184.216.34");
        Alert activeForOtherProcess = new Alert();
        activeForOtherProcess.setId(UUID.randomUUID());
        activeForOtherProcess.setStatus(AlertStatus.OPEN);
        activeForOtherProcess.setEvent(event(ent, "NETWORK_CONNECTION", NOW.minusMinutes(2), otherProcessPayload));
        when(alertRepository.findByEntity_EntityIdAndRuleIdAndStatusIn(
                eq("HOST-16"), eq("NEW_PROCESS_EXTERNAL_CONNECTION"), any()))
                .thenReturn(List.of(activeForOtherProcess));

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 2001);
        netPayload.put("processCreateTime", iso(processStartTime));
        netPayload.put("remoteAddress", "93.184.216.34");
        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);

        service.evaluate(netConn);

        verify(alertRepository, times(2)).save(any());
        verify(auditLogService).log(eq("system"), eq("DETECTION_CREATED"), eq("ALERT"), any(), any(), any());
    }

    // ---------------------------------------------------------------
    // Robustness / unrelated event types
    // ---------------------------------------------------------------

    @Test
    void newProcessConnection_evidenceNeverExceedsTheAlertFactorColumnLimit() {

        // Regression test: an earlier version of this rule produced an
        // evidence string longer than alert_factors.factor's VARCHAR(128)
        // limit for a real IPv6 remoteAddress, which failed at the database
        // with "value too long for type character varying(128)" - caught
        // during live verification, not by this suite, which is why this
        // test now exists.
        stubAlertPersistence();
        EntityProfile ent = entity("HOST-14-with-a-fairly-long-entity-identifier-string");
        OffsetDateTime processStartTime = NOW.minusMinutes(1);
        Map<String, Object> psPayload = new HashMap<>();
        psPayload.put("pid", 5216);
        psPayload.put("processName", "some-unusually-long-executable-name-for-a-background-worker.exe");
        Event processStart = event(ent, "PROCESS_START", processStartTime, psPayload);
        stubEventsOfType(ent.getEntityId(), "PROCESS_START", List.of(processStart));

        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 5216);
        netPayload.put("processCreateTime", iso(processStartTime));
        netPayload.put("remoteAddress", "2606:4700:0010:0000:0000:0000:6814:179a");

        Event netConn = event(ent, "NETWORK_CONNECTION", NOW, netPayload);

        service.evaluate(netConn);

        ArgumentCaptor<com.anomaly.platform.entity.AlertFactor> captor =
                ArgumentCaptor.forClass(com.anomaly.platform.entity.AlertFactor.class);
        verify(alertFactorRepository).save(captor.capture());
        assertThat(captor.getValue().getFactor().length()).isLessThanOrEqualTo(128);
    }

    @Test
    void evaluate_ignoresEventTypesNoRuleCaresAbout() {

        EntityProfile ent = entity("HOST-12");
        Event logout = event(ent, "LOGOUT", NOW, Map.of());

        service.evaluate(logout);

        verify(alertRepository, never()).save(any());
        verify(eventRepository, never()).findByEntity_EntityIdAndEventType(anyString(), anyString(), any());
    }

    @Test
    void evaluate_neverThrows_whenARepositoryCallFails() {

        EntityProfile ent = entity("HOST-13");
        Event login = event(ent, "LOGIN", NOW, Map.of("loginSuccess", false));

        when(eventRepository.findByEntity_EntityIdAndEventType(anyString(), anyString(), any()))
                .thenThrow(new RuntimeException("simulated DB failure"));

        assertThatCode(() -> service.evaluate(login)).doesNotThrowAnyException();
    }

    // ---------------------------------------------------------------
    // Concurrent evaluation of the same event (consumer + admin replay)
    // ---------------------------------------------------------------

    @Test
    void ruleEvaluation_locksTheEventBeforeCheckingForAnExistingAlert() {

        EntityProfile ent = entity("HOST-20");
        List<Event> logins = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            logins.add(event(ent, "LOGIN", NOW.minusMinutes(4 - i), Map.of("loginSuccess", false)));
        }
        stubEventsOfType("HOST-20", "LOGIN", logins);
        Event triggering = logins.get(logins.size() - 1);
        when(alertRepository.existsByEvent_IdAndRuleId(triggering.getId(), "AUTH_BURST")).thenReturn(true);

        service.evaluate(triggering);

        // the second of two concurrent evaluations waits on the lock, then sees the first one's alert
        org.mockito.InOrder order = org.mockito.Mockito.inOrder(eventRepository, alertRepository);
        order.verify(eventRepository).lockForProcessing(triggering.getId());
        order.verify(alertRepository).existsByEvent_IdAndRuleId(triggering.getId(), "AUTH_BURST");
        verify(alertRepository, never()).save(any());
    }

    @Test
    void networkConnectionEvaluation_alsoLocksTheEvent() {

        EntityProfile ent = entity("HOST-21");
        Map<String, Object> netPayload = new HashMap<>();
        netPayload.put("pid", 1);
        netPayload.put("processCreateTime", iso(NOW.minusMinutes(1)));
        netPayload.put("remoteAddress", "127.0.0.1");   // loopback: rule exits early, after the lock

        service.evaluate(event(ent, "NETWORK_CONNECTION", NOW, netPayload));

        verify(eventRepository).lockForProcessing(any());
    }

    @Test
    void eventTypesWithoutRules_takeNoLock() {

        service.evaluate(event(entity("HOST-22"), "LOGOUT", NOW, Map.of()));

        verify(eventRepository, never()).lockForProcessing(any());
    }
}
