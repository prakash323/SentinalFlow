package com.anomaly.platform.service;

import com.anomaly.platform.config.AlertPolicyProperties;
import com.anomaly.platform.dto.CreatePredictionRequest;
import com.anomaly.platform.dto.PredictionResponse;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Prediction;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Phase 1 focused test for requirement 4 (idempotency): a duplicate Kafka
 * delivery of an event that already produced a Prediction must not create
 * a second Prediction, a second Alert, or a second Incident.
 *
 * This exercises PredictionService.create's existing early-return-on-
 * duplicate behavior directly, so a future regression here is caught even
 * though the Kafka-level idempotency test in EventProcessingServiceTest
 * cannot see inside PredictionService's own transaction.
 */
@ExtendWith(MockitoExtension.class)
class PredictionServiceIdempotencyTest {

    @Mock
    private PredictionRepository predictionRepository;

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private AlertFactorRepository alertFactorRepository;

    @Mock
    private EventRepository eventRepository;

    @Mock
    private AlertPolicyProperties alertPolicy;

    @Mock
    private IncidentService incidentService;

    private PredictionService predictionService;

    private UUID eventDbId;

    @BeforeEach
    void setUp() {

        predictionService = new PredictionService(
                predictionRepository,
                alertRepository,
                alertFactorRepository,
                eventRepository,
                alertPolicy,
                incidentService
        );

        eventDbId = UUID.randomUUID();
    }

    private CreatePredictionRequest request() {
        return new CreatePredictionRequest(
                eventDbId,
                "anomaly-detector",
                "v1",
                BigDecimal.valueOf(0.9),
                BigDecimal.valueOf(0.8),
                BigDecimal.valueOf(0.9),
                DecisionState.UNKNOWN_ANOMALY,
                java.util.Map.of("loginSuccess", false)
        );
    }

    private Prediction existingPrediction() {

        EntityProfile entity = new EntityProfile();
        entity.setId(UUID.randomUUID());
        entity.setEntityId("USER-1");

        Event event = new Event();
        event.setId(eventDbId);
        event.setEventId("EV-1");
        event.setEntity(entity);

        Prediction prediction = new Prediction();
        prediction.setId(UUID.randomUUID());
        prediction.setEvent(event);
        prediction.setEntity(entity);
        prediction.setModelName("anomaly-detector");
        prediction.setModelVersion("v1");
        prediction.setAnomalyScore(BigDecimal.valueOf(0.9));
        prediction.setConfidence(BigDecimal.valueOf(0.8));
        prediction.setFusedScore(BigDecimal.valueOf(0.9));
        prediction.setDecision(DecisionState.UNKNOWN_ANOMALY);
        prediction.setFeatures(java.util.Map.of());

        return prediction;
    }

    @Test
    void duplicateDelivery_withExistingPrediction_doesNotCreateAnotherPredictionAlertOrIncident() {

        Prediction existing = existingPrediction();

        when(predictionRepository.findTopByEvent_IdAndModelNameAndModelVersionOrderByCreatedAtDesc(
                eq(eventDbId), eq("anomaly-detector"), eq("v1")
        )).thenReturn(Optional.of(existing));

        PredictionResponse response = predictionService.create(request());

        assertThat(response.id()).isEqualTo(existing.getId());
        assertThat(response.eventId()).isEqualTo("EV-1");

        verify(predictionRepository, never()).save(any());
        verify(alertRepository, never()).save(any());
        verify(alertFactorRepository, never()).save(any());
        verify(incidentService, never()).findOrCreateIncident(any());
        verify(eventRepository, never()).findById(any());
    }

    @Test
    void firstDelivery_belowAlertThreshold_createsPredictionButNoAlert() {

        when(predictionRepository.findTopByEvent_IdAndModelNameAndModelVersionOrderByCreatedAtDesc(
                any(), any(), any()
        )).thenReturn(Optional.empty());

        EntityProfile entity = new EntityProfile();
        entity.setId(UUID.randomUUID());
        entity.setEntityId("USER-1");

        Event event = new Event();
        event.setId(eventDbId);
        event.setEventId("EV-1");
        event.setEntity(entity);

        when(eventRepository.findById(eventDbId)).thenReturn(Optional.of(event));
        when(predictionRepository.save(any())).thenAnswer(invocation -> {
            Prediction p = invocation.getArgument(0);
            p.setId(UUID.randomUUID());
            return p;
        });
        when(alertPolicy.getAlertThreshold()).thenReturn(0.95);

        CreatePredictionRequest lowScoreRequest = new CreatePredictionRequest(
                eventDbId, "anomaly-detector", "v1",
                BigDecimal.valueOf(0.1), BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.1),
                DecisionState.UNKNOWN_ANOMALY, java.util.Map.of()
        );

        predictionService.create(lowScoreRequest);

        verify(predictionRepository).save(any());
        verify(alertRepository, never()).save(any());
        verify(incidentService, never()).findOrCreateIncident(any());
    }

    @Test
    void alertFactorsFromTheMlService_neverExceedTheFactorColumnLimit() {

        when(predictionRepository.findTopByEvent_IdAndModelNameAndModelVersionOrderByCreatedAtDesc(
                any(), any(), any()
        )).thenReturn(Optional.empty());

        EntityProfile entity = new EntityProfile();
        entity.setId(UUID.randomUUID());
        entity.setEntityId("USER-1");
        Event event = new Event();
        event.setId(eventDbId);
        event.setEventId("EV-1");
        event.setEntity(entity);

        when(eventRepository.findById(eventDbId)).thenReturn(Optional.of(event));
        when(predictionRepository.save(any())).thenAnswer(invocation -> {
            Prediction p = invocation.getArgument(0);
            p.setId(UUID.randomUUID());
            return p;
        });
        when(alertRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(alertPolicy.getAlertThreshold()).thenReturn(0.99);
        when(alertPolicy.getSeverity()).thenReturn(new AlertPolicyProperties.SeverityThreshold());

        String longFactor = "x".repeat(300);
        predictionService.create(new CreatePredictionRequest(
                eventDbId, "behavioral-anomaly-ensemble", "pipeline-joblib",
                BigDecimal.ONE, BigDecimal.valueOf(0.9), BigDecimal.ONE,
                DecisionState.KNOWN_ANOMALY,
                java.util.Map.of("factors", java.util.List.of(longFactor, "short factor"))
        ));

        org.mockito.ArgumentCaptor<com.anomaly.platform.entity.AlertFactor> captor =
                org.mockito.ArgumentCaptor.forClass(com.anomaly.platform.entity.AlertFactor.class);
        verify(alertFactorRepository, org.mockito.Mockito.times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(0).getFactor()).hasSize(128).endsWith("...");
        assertThat(captor.getAllValues().get(1).getFactor()).isEqualTo("short factor");
    }
}
