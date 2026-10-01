package com.anomaly.platform.ai;

import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.entity.Prediction;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.IncidentRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * AI-1 tests for AlertAiEvidenceService - the alert assistant's only
 * repository contact. Proves it maps real alert/event/prediction/incident
 * data (never invented values), handles missing pieces, and only ever reads.
 */
@ExtendWith(MockitoExtension.class)
class AlertAiEvidenceServiceTest {

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private AlertFactorRepository alertFactorRepository;

    @Mock
    private IncidentRepository incidentRepository;

    private AlertAiEvidenceService service;

    private UUID alertId;

    @BeforeEach
    void setUp() {
        IncidentEvidenceService incidentEvidenceService =
                new IncidentEvidenceService(incidentRepository, alertRepository, alertFactorRepository);
        service = new AlertAiEvidenceService(alertRepository, incidentEvidenceService);
        alertId = UUID.randomUUID();
    }

    private Alert alert(Incident incident, Event event, Prediction prediction) {

        EntityProfile entity = new EntityProfile();
        entity.setEntityId("U0001");

        Alert alert = new Alert();
        alert.setId(alertId);
        alert.setEntity(entity);
        alert.setEvent(event);
        alert.setPrediction(prediction);
        alert.setIncident(incident);
        alert.setDecision(DecisionState.KNOWN_ANOMALY);
        alert.setSeverity(Severity.CRITICAL);
        alert.setStatus(AlertStatus.OPEN);
        alert.setAnomalyScore(BigDecimal.valueOf(1.0));
        alert.setConfidence(BigDecimal.valueOf(0.996));
        alert.setFusedScore(BigDecimal.valueOf(1.0));
        alert.setPolicyVersion("v2-ml-ensemble");
        return alert;
    }

    private Event event() {
        Event event = new Event();
        event.setEventId("EV-1");
        event.setEventType("LOGIN");
        event.setSource("web-portal");
        event.setPayload(Map.of("password", "hunter2", "note", "raw payload must never reach the AI"));
        return event;
    }

    private Prediction prediction() {
        Prediction prediction = new Prediction();
        prediction.setFeatures(Map.of(
                "attackType", "device_spoofing",
                "reason", "Risk 100.0 - likely device spoofing."
        ));
        return prediction;
    }

    private Incident incident() {
        Incident incident = new Incident();
        incident.setId(UUID.randomUUID());
        incident.setIncidentKey("U0001:LOGIN");
        incident.setStatus(IncidentStatus.OPEN);
        incident.setSummary("Anomalous LOGIN activity detected for entity U0001");
        return incident;
    }

    private AlertFactor factor(String text) {
        AlertFactor f = new AlertFactor();
        f.setFactor(text);
        return f;
    }

    @Test
    void gather_alertNotFound_throwsNotFound() {

        when(alertRepository.findById(alertId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.gather(alertId))
                .isInstanceOf(NotFoundException.class)
                .hasMessageContaining("Alert not found");
    }

    @Test
    void gather_mapsTheAuthoritativeAlertFieldsWithoutRecomputing() {

        Alert alert = alert(null, event(), prediction());
        when(alertRepository.findById(alertId)).thenReturn(Optional.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alertId))
                .thenReturn(List.of(factor("unseen device fingerprint"), factor("new source IP")));

        AlertAiEvidence evidence = service.gather(alertId);

        assertThat(evidence.entityId()).isEqualTo("U0001");
        assertThat(evidence.eventSource()).isEqualTo("web-portal");

        AlertEvidence a = evidence.alert();
        assertThat(a.decision()).isEqualTo("KNOWN_ANOMALY");
        assertThat(a.severity()).isEqualTo("CRITICAL");
        assertThat(a.status()).isEqualTo("OPEN");
        assertThat(a.anomalyScore()).isEqualByComparingTo("1.0");
        assertThat(a.confidence()).isEqualByComparingTo("0.996");
        assertThat(a.fusedScore()).isEqualByComparingTo("1.0");
        assertThat(a.eventId()).isEqualTo("EV-1");
        assertThat(a.attackType()).isEqualTo("device_spoofing");
        assertThat(a.mlReason()).isEqualTo("Risk 100.0 - likely device spoofing.");
        assertThat(a.factors()).containsExactly("unseen device fingerprint", "new source IP");
    }

    @Test
    void gather_includesIncidentContext_whenTheAlertIsLinked() {

        Incident incident = incident();
        Alert alert = alert(incident, event(), prediction());
        when(alertRepository.findById(alertId)).thenReturn(Optional.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alertId)).thenReturn(List.of());
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incident.getId()))
                .thenReturn(List.of(alert, new Alert(), new Alert()));

        AlertAiEvidence evidence = service.gather(alertId);

        assertThat(evidence.incidentId()).isEqualTo(incident.getId().toString());
        assertThat(evidence.incidentKey()).isEqualTo("U0001:LOGIN");
        assertThat(evidence.incidentStatus()).isEqualTo("OPEN");
        assertThat(evidence.incidentSummary()).contains("U0001");
        assertThat(evidence.incidentAlertCount()).isEqualTo(3);
    }

    @Test
    void gather_withNoIncidentEventOrPrediction_leavesThoseFieldsNullForTheAiToCallUnknown() {

        Alert alert = alert(null, null, null);
        when(alertRepository.findById(alertId)).thenReturn(Optional.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alertId)).thenReturn(List.of());

        AlertAiEvidence evidence = service.gather(alertId);

        assertThat(evidence.incidentId()).isNull();
        assertThat(evidence.incidentAlertCount()).isNull();
        assertThat(evidence.eventSource()).isNull();
        assertThat(evidence.alert().eventId()).isNull();
        assertThat(evidence.alert().attackType()).isNull();
        assertThat(evidence.alert().mlReason()).isNull();
        assertThat(evidence.alert().factors()).isEmpty();
    }

    @Test
    void gather_neverIncludesTheRawEventPayload() {

        Alert alert = alert(null, event(), prediction());
        when(alertRepository.findById(alertId)).thenReturn(Optional.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alertId)).thenReturn(List.of());

        AlertAiEvidence evidence = service.gather(alertId);

        assertThat(evidence.toString()).doesNotContain("hunter2").doesNotContain("raw payload");
    }

    @Test
    void gather_neverWritesToAnyRepository() {

        Alert alert = alert(incident(), event(), prediction());
        when(alertRepository.findById(alertId)).thenReturn(Optional.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alertId)).thenReturn(List.of());
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(any())).thenReturn(List.of(alert));

        service.gather(alertId);

        verify(alertRepository, never()).save(any());
        verify(alertRepository, never()).saveAll(any());
        verify(alertRepository, never()).delete(any(Alert.class));
        verify(incidentRepository, never()).save(any());
        verify(alertFactorRepository, never()).save(any());
    }

    @Test
    void gather_runsInAReadOnlyTransaction() throws Exception {

        Transactional tx = AlertAiEvidenceService.class
                .getMethod("gather", UUID.class)
                .getAnnotation(Transactional.class);

        assertThat(tx).isNotNull();
        assertThat(tx.readOnly()).isTrue();
    }
}
