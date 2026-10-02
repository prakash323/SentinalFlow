package com.anomaly.platform.config;

import com.anomaly.platform.kafka.KafkaTopics;

import org.apache.kafka.clients.admin.NewTopic;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.CommonErrorHandler;
import org.springframework.kafka.listener.DefaultErrorHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/*
 * Phase 1 focused test for the Kafka retry/dead-letter wiring.
 *
 * This verifies the bean definitions build correctly and the topic names
 * line up with KafkaTopics. It intentionally does NOT try to assert the
 * DefaultErrorHandler's internal retry/classification behavior via
 * reflection - that is better verified with an embedded-Kafka integration
 * test (tracked as a Phase 2 follow-up covering the Kafka pipeline).
 */
class KafkaErrorHandlingConfigTest {

    private final KafkaErrorHandlingConfig config = new KafkaErrorHandlingConfig();

    @Test
    void rawEventsTopic_matchesSharedConstant() {

        NewTopic topic = config.rawEventsTopic();

        assertThat(topic.name()).isEqualTo(KafkaTopics.RAW_EVENTS);
        assertThat(topic.numPartitions()).isEqualTo(1);
    }

    @Test
    void deadLetterTopic_isOriginalTopicPlusDltSuffix() {

        NewTopic dlt = config.rawEventsDeadLetterTopic();

        assertThat(dlt.name()).isEqualTo(KafkaTopics.RAW_EVENTS + ".DLT");
        assertThat(dlt.name()).isEqualTo(KafkaTopics.RAW_EVENTS_DLT);
    }

    @Test
    void kafkaErrorHandler_buildsADefaultErrorHandler_withoutThrowing() {

        @SuppressWarnings("unchecked")
        KafkaTemplate<String, String> template = mock(KafkaTemplate.class);

        CommonErrorHandler errorHandler = config.kafkaErrorHandler(template);

        assertThat(errorHandler).isInstanceOf(DefaultErrorHandler.class);
    }

    @Test
    void transientMlBackOff_isExponentialFrom1sCappedAt30s_forAboutFiveMinutes() {

        org.springframework.util.backoff.BackOffExecution execution =
                KafkaErrorHandlingConfig.transientMlBackOff().start();
        java.util.List<Long> waits = new java.util.ArrayList<>();
        long wait;
        while ((wait = execution.nextBackOff()) != org.springframework.util.backoff.BackOffExecution.STOP) {
            waits.add(wait);
        }

        assertThat(waits).startsWith(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L);
        assertThat(waits).allMatch(w -> w <= 30_000L);
        assertThat(waits).hasSize(14);                                   // 14 retries = 15 attempts
        assertThat(waits.stream().mapToLong(Long::longValue).sum()).isEqualTo(301_000L);   // ~5 min of waiting
    }

    @Test
    void hasCause_findsTheMlFailureInsideTheListenerWrapper() {

        Exception wrapped = new RuntimeException("listener failed",
                new com.anomaly.platform.ml.MlServiceUnavailableException("down", false, null));

        assertThat(KafkaErrorHandlingConfig.hasCause(wrapped, com.anomaly.platform.ml.MlServiceUnavailableException.class)).isTrue();
        assertThat(KafkaErrorHandlingConfig.hasCause(new RuntimeException("db"), com.anomaly.platform.ml.MlServiceUnavailableException.class)).isFalse();
    }

    // ---- DLT headers: failure reason and supported recovery ----

    private static Exception wrapped(Throwable cause) {
        return new org.springframework.kafka.listener.ListenerExecutionFailedException("Listener method threw exception", cause);
    }

    @Test
    void failureReason_isTheRealCause_notSpringsListenerWrapper() {

        String reason = KafkaErrorHandlingConfig.failureReason(
                wrapped(new com.anomaly.platform.exception.NotFoundException("Entity not found: HOST-X")));

        assertThat(reason).isEqualTo("NotFoundException: Entity not found: HOST-X");
    }

    @Test
    void recoveryAction_unregisteredEntity_meansNoRowWasStored_soRepublishNotReplay() {

        String action = KafkaErrorHandlingConfig.recoveryAction(
                wrapped(new com.anomaly.platform.exception.NotFoundException("Entity not found: HOST-X")));

        assertThat(action).contains("No event row was stored").contains("POST /api/v1/entities")
                .contains("re-publish").contains("cannot recover");
    }

    @Test
    void recoveryAction_mlUnavailable_meansStoredAndFailed_soReplay() {

        String action = KafkaErrorHandlingConfig.recoveryAction(
                wrapped(new com.anomaly.platform.ml.MlServiceUnavailableException("ML down", false, null)));

        assertThat(action).contains("stored and FAILED").contains("POST /api/v1/replay-runs");
    }

    @Test
    void recoveryAction_mlRejected_warnsThatAnUnchangedRetryFailsAgain() {

        String action = KafkaErrorHandlingConfig.recoveryAction(
                wrapped(new com.anomaly.platform.ml.MlResponseRejectedException("unknown decision")));

        assertThat(action).contains("stored and FAILED").contains("fails again");
    }

    @Test
    void recoveryAction_malformedRecord_isNotRecoverableAsSent() {

        String action = KafkaErrorHandlingConfig.recoveryAction(
                wrapped(new IllegalArgumentException("Malformed Kafka event payload")));

        assertThat(action).contains("malformed").contains("corrected event");
    }

    @Test
    void recoveryAction_unknownCause_explainsHowToTellWhichRecoveryApplies() {

        String action = KafkaErrorHandlingConfig.recoveryAction(wrapped(new RuntimeException("database unavailable")));

        assertThat(action).contains("GET /api/v1/events/{eventId}").contains("replay-runs").contains("re-publish");
    }
}
