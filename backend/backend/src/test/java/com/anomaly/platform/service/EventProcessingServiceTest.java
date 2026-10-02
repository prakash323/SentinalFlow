package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreatePredictionRequest;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.EventProcessingStatus;
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
        // The persisted event here stays PENDING (markProcessed is a mock), so
        // both deliveries take the full path; whether the second creates a
        // duplicate Prediction/Alert is PredictionService's own idempotency
        // contract (PredictionServiceIdempotencyTest). A redelivery of an event
        // that really reached PROCESSED is short-circuited - see the
        // idempotency-guard tests below.
    }

    // ---------------------------------------------------------------
    // Idempotency guard: PROCESSED + persisted prediction = complete
    // ---------------------------------------------------------------

    @Test
    void processedEventWithPrediction_isSkipped_withoutCallingMlOrRulesOrCreatingRecords() {

        persistedEvent.setProcessingStatus(EventProcessingStatus.PROCESSED);
        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(predictionService.hasPrediction(persistedEvent.getId())).thenReturn(true);

        assertThat(service.process(validEvent())).isEqualTo(EventProcessingService.Outcome.ALREADY_PROCESSED);

        // ML is never called again ...
        verifyNoInteractions(mlPredictionClient);
        // ... and nothing that creates predictions, alerts, incidents or audit
        // entries runs: rules (rule alerts, incidents, DETECTION_* audit),
        // PredictionService.create (prediction, ML alert, incident) and the
        // ledger's status/audit writers.
        verifyNoInteractions(deterministicRuleService);
        verify(predictionService, never()).create(any());
        verify(ledger, never()).markProcessed(any());
        verify(ledger, never()).markFailed(any(), any(), any());
        verify(ledger, never()).recordUnresolvableFailure(any(), any(), any());
    }

    @Test
    void redeliveryAfterSuccessfulProcessing_callsMlExactlyOnceAcrossBothDeliveries() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());
        // the real ledger flips the status; mirror that on the shared entity
        org.mockito.Mockito.doAnswer(inv -> {
            persistedEvent.setProcessingStatus(EventProcessingStatus.PROCESSED);
            return null;
        }).when(ledger).markProcessed(persistedEvent.getId());
        when(predictionService.hasPrediction(persistedEvent.getId())).thenReturn(true);

        service.process(validEvent());   // first delivery: full pipeline
        service.process(validEvent());   // redelivery / replay: skipped

        verify(mlPredictionClient, org.mockito.Mockito.times(1)).predict(any());
        verify(predictionService, org.mockito.Mockito.times(1)).create(any());
        verify(deterministicRuleService, org.mockito.Mockito.times(1)).evaluate(persistedEvent);
        verify(ledger, org.mockito.Mockito.times(1)).markProcessed(persistedEvent.getId());
    }

    @Test
    void newPendingEvent_takesTheNormalPath_andCallsMl() {

        // A freshly ingested event is PENDING (the entity default).
        assertThat(persistedEvent.getProcessingStatus()).isEqualTo(EventProcessingStatus.PENDING);
        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(normalMlResponse());

        assertThat(service.process(validEvent())).isEqualTo(EventProcessingService.Outcome.PROCESSED);

        verify(mlPredictionClient).predict(any());
        verify(predictionService).create(any());
        verify(ledger).markProcessed(persistedEvent.getId());
        // the guard only consults the prediction store for PROCESSED events
        verify(predictionService, never()).hasPrediction(any());
    }

    @Test
    void failedEvent_evenWithAPersistedPrediction_followsTheExistingRecoveryPath() {

        // e.g. the prediction committed but markProcessed then failed: the
        // workflow is incomplete, so it must be retried, not skipped.
        persistedEvent.setProcessingStatus(EventProcessingStatus.FAILED);
        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any())).thenReturn(anomalousMlResponse());

        service.process(validEvent());

        verify(deterministicRuleService).evaluate(persistedEvent);
        verify(mlPredictionClient).predict(any());
        verify(predictionService).create(any());   // idempotent on (event, model, version)
        verify(ledger).markProcessed(persistedEvent.getId());
        verify(predictionService, never()).hasPrediction(any());
    }

    @Test
    void processedEventWithNoPredictionOnRecord_isNotSkipped_butRecovered() {

        persistedEvent.setProcessingStatus(EventProcessingStatus.PROCESSED);
        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(predictionService.hasPrediction(persistedEvent.getId())).thenReturn(false);
        when(mlPredictionClient.predict(any())).thenReturn(normalMlResponse());

        service.process(validEvent());

        verify(mlPredictionClient).predict(any());
        verify(predictionService).create(any());
        verify(ledger).markProcessed(persistedEvent.getId());
    }

    // ---------------------------------------------------------------
    // Transient ML failure: retried attempts, then success, then redelivery
    // ---------------------------------------------------------------

    @Test
    void transientMlFailures_thenSuccess_persistOnce_andALaterRedeliverySkipsMl() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        // markFailed / markProcessed as the real ledger does
        org.mockito.Mockito.doAnswer(inv -> {
            persistedEvent.setProcessingStatus(EventProcessingStatus.FAILED);
            return null;
        }).when(ledger).markFailed(eq(persistedEvent.getId()), any(), any());
        org.mockito.Mockito.doAnswer(inv -> {
            persistedEvent.setProcessingStatus(EventProcessingStatus.PROCESSED);
            return null;
        }).when(ledger).markProcessed(persistedEvent.getId());
        when(mlPredictionClient.predict(any()))
                .thenThrow(new com.anomaly.platform.ml.MlServiceUnavailableException("timeout", false, null))
                .thenThrow(new com.anomaly.platform.ml.MlServiceUnavailableException("warming up", true, null))
                .thenReturn(anomalousMlResponse());
        when(predictionService.hasPrediction(persistedEvent.getId())).thenReturn(true);

        // attempts 1 and 2 fail and propagate, so the Kafka error handler can retry them
        assertThatThrownBy(() -> service.process(validEvent()))
                .isInstanceOf(com.anomaly.platform.ml.MlServiceUnavailableException.class);
        assertThatThrownBy(() -> service.process(validEvent()))
                .isInstanceOf(com.anomaly.platform.ml.MlServiceUnavailableException.class);
        // attempt 3 succeeds
        service.process(validEvent());
        // a later redelivery / replay of the completed event
        service.process(validEvent());

        verify(mlPredictionClient, org.mockito.Mockito.times(3)).predict(any());   // never on the redelivery
        verify(predictionService, org.mockito.Mockito.times(1)).create(any());     // prediction/alert/incident once
        verify(ledger, org.mockito.Mockito.times(2)).markFailed(eq(persistedEvent.getId()), any(), any());
        verify(ledger, org.mockito.Mockito.times(1)).markProcessed(persistedEvent.getId());
        // rules ran on each attempt (they are idempotent), not on the redelivery
        verify(deterministicRuleService, org.mockito.Mockito.times(3)).evaluate(persistedEvent);
    }

    @Test
    void permanentMlRejection_isRecordedAsFailed_andPropagatesForTheDeadLetterPath() {

        when(ledger.persistOrLoad(any())).thenReturn(persistedEvent);
        when(mlPredictionClient.predict(any()))
                .thenThrow(new com.anomaly.platform.ml.MlResponseRejectedException("unknown decision"));

        assertThatThrownBy(() -> service.process(validEvent()))
                .isInstanceOf(com.anomaly.platform.ml.MlResponseRejectedException.class);

        verify(ledger).markFailed(eq(persistedEvent.getId()), any(), any());
        verify(predictionService, never()).create(any());
        verify(ledger, never()).markProcessed(any());
    }
}
