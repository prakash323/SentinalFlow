package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreatePredictionRequest;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.KafkaEvent;
import com.anomaly.platform.ml.MlPredictionClient;
import com.anomaly.platform.ml.MlPredictionResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/*
 * Focused tests for EventProcessingService. Phase 1 established that the
 * event ledger (persistence and success/failure recording) must be touched
 * correctly regardless of whether the detection pipeline succeeds, and that
 * a processing failure must propagate instead of being swallowed. Phase 4
 * replaces the placeholder rule-based scorer with a call to the real ML
 * service (MlPredictionClient) - these tests were updated to mock that
 * client instead, and a dedicated case was added for "the ML service call
 * itself fails" (Phase 4 Step 12's failure scenario, verified here at the
 * unit level; the full stack version is verified live - see the Phase 4
 * report).
 */
@ExtendWith(MockitoExtension.class)
class EventProcessingServiceTest {

    @Mock
    private MlPredictionClient mlPredictionClient;

    @Mock
    private PredictionService predictionService;

    @Mock
    private EventProcessingLedgerService ledger;

    @Mock
    private DeterministicRuleService deterministicRuleService;

    private EventProcessingService service;

    private Event persistedEvent;

    @BeforeEach
    void setUp() {

        service = new EventProcessingService(
                mlPredictionClient,
                predictionService,
                ledger,
                deterministicRuleService
        );

        persistedEvent = new Event();
        persistedEvent.setId(UUID.randomUUID());
        persistedEvent.setEventId("EV-1");
    }

    private KafkaEvent validEvent() {
        return new KafkaEvent(
                "EV-1",
                "USER-1",
                "LOGIN",
                "v1",
                OffsetDateTime.now(),
                "test-source",
                Map.of("ip", "10.10.10.50", "loginSuccess", false)
        );
    }

    private MlPredictionResponse normalMlResponse() {
        return new MlPredictionResponse(
                "EV-1", "USER-1",
                BigDecimal.valueOf(0.12), BigDecimal.valueOf(12.0), null,
                "NORMAL", "behavioral-anomaly-ensemble", "pipeline-joblib",
                null, null, List.of()
        );
    }

    private MlPredictionResponse anomalousMlResponse() {
        return new MlPredictionResponse(
                "EV-1", "USER-1",
                BigDecimal.valueOf(0.99), BigDecimal.valueOf(99.0), BigDecimal.valueOf(0.87),
                "ANOMALOUS", "behavioral-anomaly-ensemble", "pipeline-joblib",
                "credential_stuffing", "Risk 99.0 - likely credential stuffing.",
                List.of("distinct accounts used from this IP in 1 hour")
        );
    }

    @Test
    void happyPath_marksEventProcessed_andNeverMarksFailed() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());

        service.process(validEvent());

        verify(ledger).markProcessed(persistedEvent.getId());
        verify(ledger, never()).markFailed(any(), any(), any());
        verify(ledger, never()).recordUnresolvableFailure(any(), any(), any());
        verify(predictionService).create(any());
        verify(deterministicRuleService).evaluate(persistedEvent);
    }

    // Regression: evaluate() is @Transactional, so a repository failure it
    // swallows internally still surfaces from its commit as
    // UnexpectedRollbackException. That must not skip ML scoring.
    @Test
    void ruleEvaluationThrowing_stillRunsMlScoring_andMarksProcessed() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        org.mockito.Mockito.doThrow(new org.springframework.transaction.UnexpectedRollbackException(
                        "Transaction silently rolled back because it has been marked as rollback-only"))
                .when(deterministicRuleService).evaluate(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());

        service.process(validEvent());

        verify(predictionService).create(any());
        verify(ledger).markProcessed(persistedEvent.getId());
        verify(ledger, never()).markFailed(any(), any(), any());
    }

    @Test
    void normalMlDecision_stillPersistsPrediction_justWithoutAnAlertLaterOn() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(normalMlResponse());

        service.process(validEvent());

        verify(ledger).markProcessed(persistedEvent.getId());
        verify(predictionService).create(any());
        // Whether a NORMAL-decision prediction actually creates an alert is
        // PredictionService's own policy threshold check (fusedScore vs.
        // anomaly.alert-policy.alert-threshold), not this service's concern.
    }

    @Test
    void mlDecisionNormal_mapsToDecisionStateNormal() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(normalMlResponse());

        service.process(validEvent());

        ArgumentCaptor<CreatePredictionRequest> captor = ArgumentCaptor.forClass(CreatePredictionRequest.class);
        verify(predictionService).create(captor.capture());

        assertThat(captor.getValue().decision()).isEqualTo(DecisionState.NORMAL);
    }

    @Test
    void mlAnomalousWithRecognizedAttackType_mapsToKnownAnomaly() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());

        service.process(validEvent());

        ArgumentCaptor<CreatePredictionRequest> captor = ArgumentCaptor.forClass(CreatePredictionRequest.class);
        verify(predictionService).create(captor.capture());

        CreatePredictionRequest request = captor.getValue();
        assertThat(request.decision()).isEqualTo(DecisionState.KNOWN_ANOMALY);
        assertThat(request.features()).containsEntry("attackType", "credential_stuffing");
    }

    @Test
    void mlAnomalousWithoutAnAttackType_mapsToUnknownAnomaly() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);

        MlPredictionResponse unclassified = new MlPredictionResponse(
                "EV-1", "USER-1",
                BigDecimal.valueOf(0.99), BigDecimal.valueOf(99.0), BigDecimal.valueOf(0.2),
                "ANOMALOUS", "behavioral-anomaly-ensemble", "pipeline-joblib",
                "unclassified", "Risk 99.0 - anomalous, no specific attack type assigned.",
                List.of()
        );
        when(mlPredictionClient.predict(any())).thenReturn(unclassified);

        service.process(validEvent());

        ArgumentCaptor<CreatePredictionRequest> captor = ArgumentCaptor.forClass(CreatePredictionRequest.class);
        verify(predictionService).create(captor.capture());

        assertThat(captor.getValue().decision()).isEqualTo(DecisionState.UNKNOWN_ANOMALY);
    }

    @Test
    void mlServiceCallFails_recordsFailureOnEvent_doesNotFabricateAPrediction_andPropagates() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);

        RuntimeException mlDown = new RuntimeException("Connection refused: ML service unreachable");
        when(mlPredictionClient.predict(any())).thenThrow(mlDown);

        KafkaEvent event = validEvent();

        assertThatThrownBy(() -> service.process(event))
                .isSameAs(mlDown);

        verify(ledger).markFailed(eq(persistedEvent.getId()), eq("EV-1"), eq(mlDown));
        verify(ledger, never()).markProcessed(any());
        verify(predictionService, never()).create(any());
        // Independent deterministic detection (P1): an ML outage must never
        // prevent rule evaluation - it already ran before the ML call.
        verify(deterministicRuleService).evaluate(persistedEvent);
    }

    @Test
    void processingFailure_recordsFailureOnEvent_doesNotMarkProcessed_andPropagates() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());

        RuntimeException dbFailure = new RuntimeException("simulated DB failure");
        when(predictionService.create(any())).thenThrow(dbFailure);

        KafkaEvent event = validEvent();

        assertThatThrownBy(() -> service.process(event))
                .isSameAs(dbFailure);

        verify(ledger).markFailed(eq(persistedEvent.getId()), eq("EV-1"), eq(dbFailure));
        verify(ledger, never()).markProcessed(any());
    }

    @Test
    void eventCannotBePersisted_recordsUnresolvableFailure_andNeverRunsDetectionPipeline() {

        NotFoundException entityMissing = new NotFoundException("Entity not found: USER-1");
        when(ledger.persistOrLoad(any())).thenThrow(entityMissing);

        KafkaEvent event = validEvent();

        assertThatThrownBy(() -> service.process(event))
                .isSameAs(entityMissing);

        verify(ledger).recordUnresolvableFailure("EV-1", "USER-1", entityMissing);
        verify(ledger, never()).markProcessed(any());
        verify(ledger, never()).markFailed(any(), any(), any());
        verifyNoInteractions(mlPredictionClient, predictionService, deterministicRuleService);
    }

    @Test
    void missingRequiredField_failsValidation_beforeTouchingLedgerOrPipeline() {

        KafkaEvent invalid = new KafkaEvent(
                " ", "USER-1", "LOGIN", "v1", OffsetDateTime.now(), "test-source", Map.of()
        );

        assertThatThrownBy(() -> service.process(invalid))
                .isInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(ledger, mlPredictionClient, predictionService, deterministicRuleService);
    }

    @Test
    void duplicateDelivery_reusesExistingPersistedEvent_insteadOfCreatingANewOne() {

        // Simulates a redelivered Kafka message for an event the ledger
        // already has on file: persistOrLoad is idempotent, so it must be
        // the ledger (not this service) that decides whether to insert.
        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());

        service.process(validEvent());
        service.process(validEvent());

        assertThat(persistedEvent.getId()).isNotNull();
        verify(ledger, org.mockito.Mockito.times(2)).persistOrLoad(any());
        verify(predictionService, org.mockito.Mockito.times(2)).create(any());
        // Whether the second call actually creates a duplicate Prediction/Alert
        // is PredictionService's own idempotency contract - covered separately
        // in PredictionServiceIdempotencyTest. Re-calling the ML service on a
        // redelivery is a known, harmless inefficiency - see the Phase 4 report.
    }
}
