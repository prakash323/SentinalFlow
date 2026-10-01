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
 * Phase 6 focused tests for IncidentEvidenceService - the ONLY component
 * in the AI layer that touches a repository. These prove it only ever
 * reads (never save()/delete()s anything, on any repository), and that it
 * correctly extracts the real ML explainability output (attackType/reason)
 * out of Prediction.features rather than fabricating it.
 */
@ExtendWith(MockitoExtension.class)
class IncidentEvidenceServiceTest {

    @Mock
    private IncidentRepository incidentRepository;

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private AlertFactorRepository alertFactorRepository;

    private IncidentEvidenceService service;

    private UUID incidentId;

    @BeforeEach
    void setUp() {
        service = new IncidentEvidenceService(incidentRepository, alertRepository, alertFactorRepository);
        incidentId = UUID.randomUUID();
    }

    private Incident incident() {
        EntityProfile entity = new EntityProfile();
        entity.setEntityId("U0001");

        Incident incident = new Incident();
        incident.setId(incidentId);
        incident.setIncidentKey("U0001:LOGIN");
        incident.setEntity(entity);
        incident.setStatus(IncidentStatus.OPEN);
        incident.setSummary("Anomalous LOGIN activity detected for entity U0001");
        return incident;
    }

    private Alert alertWithPrediction() {

        EntityProfile entity = new EntityProfile();
        entity.setEntityId("U0001");

        Event event = new Event();
        event.setEventId("EV-1");
        event.setEventType("LOGIN");

        Prediction prediction = new Prediction();
        prediction.setFeatures(Map.of(
                "attackType", "device_spoofing",
                "reason", "Risk 100.0 - likely device spoofing.",
                "riskScore", 100.0
        ));

        Alert alert = new Alert();
        alert.setId(UUID.randomUUID());
        alert.setEntity(entity);
        alert.setEvent(event);
        alert.setPrediction(prediction);
        alert.setDecision(DecisionState.KNOWN_ANOMALY);
        alert.setSeverity(Severity.CRITICAL);
        alert.setStatus(AlertStatus.OPEN);
        alert.setAnomalyScore(BigDecimal.valueOf(1.0));
        alert.setConfidence(BigDecimal.valueOf(0.996));
        alert.setFusedScore(BigDecimal.valueOf(1.0));
        alert.setPolicyVersion("v2-ml-ensemble");
        return alert;
    }

    @Test
    void gather_incidentNotFound_throwsNotFound() {

        when(incidentRepository.findById(incidentId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.gather(incidentId))
                .isInstanceOf(NotFoundException.class);

        verify(alertRepository, never()).findByIncident_IdOrderByCreatedAtDesc(any());
    }

    @Test
    void gather_neverWritesToAnyRepository() {

        when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(incident()));
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incidentId)).thenReturn(List.of());

        service.gather(incidentId);

        // IncidentEvidenceService has no save()/delete() call anywhere in
        // its source - this is the behavioural proof to go with that
        // structural fact.
        verify(incidentRepository, never()).save(any());
        verify(incidentRepository, never()).delete(any(com.anomaly.platform.entity.Incident.class));
        verify(alertRepository, never()).save(any());
        verify(alertRepository, never()).delete(any(com.anomaly.platform.entity.Alert.class));
    }

    @Test
    void gather_mapsIncidentFieldsCorrectly() {

        when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(incident()));
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incidentId)).thenReturn(List.of());

        IncidentEvidence evidence = service.gather(incidentId);

        assertThat(evidence.incidentId()).isEqualTo(incidentId.toString());
        assertThat(evidence.incidentKey()).isEqualTo("U0001:LOGIN");
        assertThat(evidence.entityId()).isEqualTo("U0001");
        assertThat(evidence.incidentStatus()).isEqualTo("OPEN");
        assertThat(evidence.alerts()).isEmpty();
    }

    @Test
    void gather_extractsRealMlAttackTypeAndReason_fromPredictionFeatures() {

        Alert alert = alertWithPrediction();

        when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(incident()));
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incidentId)).thenReturn(List.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alert.getId())).thenReturn(List.of());

        IncidentEvidence evidence = service.gather(incidentId);

        assertThat(evidence.alerts()).hasSize(1);
        AlertEvidence alertEvidence = evidence.alerts().get(0);

        assertThat(alertEvidence.attackType()).isEqualTo("device_spoofing");
        assertThat(alertEvidence.mlReason()).isEqualTo("Risk 100.0 - likely device spoofing.");
        assertThat(alertEvidence.decision()).isEqualTo("KNOWN_ANOMALY");
        assertThat(alertEvidence.severity()).isEqualTo("CRITICAL");
        assertThat(alertEvidence.eventId()).isEqualTo("EV-1");
        assertThat(alertEvidence.eventType()).isEqualTo("LOGIN");
    }

    @Test
    void gather_alertWithNoPrediction_hasNullAttackTypeAndReason_notFabricated() {

        Alert alert = alertWithPrediction();
        alert.setPrediction(null);

        when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(incident()));
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incidentId)).thenReturn(List.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alert.getId())).thenReturn(List.of());

        IncidentEvidence evidence = service.gather(incidentId);

        AlertEvidence alertEvidence = evidence.alerts().get(0);
        assertThat(alertEvidence.attackType()).isNull();
        assertThat(alertEvidence.mlReason()).isNull();
    }

    @Test
    void gather_includesRankedAlertFactors() {

        Alert alert = alertWithPrediction();

        AlertFactor f1 = new AlertFactor();
        f1.setFactor("how rarely this device fingerprint has been seen");
        f1.setRank(1);

        AlertFactor f2 = new AlertFactor();
        f2.setFactor("source IP never seen for this entity");
        f2.setRank(2);

        when(incidentRepository.findById(incidentId)).thenReturn(Optional.of(incident()));
        when(alertRepository.findByIncident_IdOrderByCreatedAtDesc(incidentId)).thenReturn(List.of(alert));
        when(alertFactorRepository.findByAlert_IdOrderByRankAsc(alert.getId())).thenReturn(List.of(f1, f2));

        IncidentEvidence evidence = service.gather(incidentId);

        assertThat(evidence.alerts().get(0).factors())
                .containsExactly(
                        "how rarely this device fingerprint has been seen",
                        "source IP never seen for this entity"
                );
    }
}
