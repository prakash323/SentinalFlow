package com.anomaly.platform.config;

import com.anomaly.platform.exception.NotFoundException;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.KafkaMessageListenerContainer;
import org.springframework.kafka.listener.MessageListener;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.EmbeddedKafkaKraftBroker;
import org.springframework.kafka.test.utils.ContainerTestUtils;
import org.springframework.kafka.test.utils.KafkaTestUtils;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/*
 * ================================================================
 * REAL-KAFKA VERIFICATION OF KafkaErrorHandlingConfig
 * ================================================================
 *
 * KafkaErrorHandlingConfigTest (Phase 1) only proves the beans build
 * without throwing - it cannot see whether retries actually happen the
 * right number of times, whether a non-retryable exception really skips
 * them, or whether an exhausted record really lands on the dead-letter
 * topic. Those are exactly the behaviors Phase 1's fix depends on
 * ("Kafka processing failures must be observable, not silently dropped"),
 * so this test exercises the production kafkaErrorHandler(...) bean
 * against a real embedded Kafka broker instead of mocks.
 */
class KafkaErrorHandlingIntegrationTest {

    private static final String SUCCESSFUL_RETRY_TOPIC = "test.successful-retry";
    private static final String RETRY_EXHAUSTED_TOPIC = "test.retry-exhausted";
    private static final String NON_RETRYABLE_TOPIC = "test.non-retryable";
    private static final String ML_RECOVERS_TOPIC = "test.ml-recovers";
    private static final String ML_EXHAUSTED_TOPIC = "test.ml-exhausted";
    private static final String ML_REJECTED_TOPIC = "test.ml-rejected";

    /*
     * Same shape as the production transient-ML policy, scaled down so the
     * test runs in milliseconds: 10, 20, 40, 40, 40, 40, 40 ms -> 7 retries,
     * 8 attempts (production: 1s..30s over ~5 min, 15 attempts).
     */
    private static org.springframework.util.backoff.ExponentialBackOff shortMlBackOff() {
        var backOff = new org.springframework.util.backoff.ExponentialBackOff(10L, 2.0);
        backOff.setMaxInterval(40L);
        backOff.setMaxElapsedTime(200L);
        return backOff;
    }

    private static EmbeddedKafkaBroker broker;

    private KafkaMessageListenerContainer<String, String> container;
    private KafkaTemplate<String, String> template;

    @BeforeAll
    static void startBroker() {

        broker = new EmbeddedKafkaKraftBroker(
                1, 1,
                SUCCESSFUL_RETRY_TOPIC, SUCCESSFUL_RETRY_TOPIC + ".DLT",
                RETRY_EXHAUSTED_TOPIC, RETRY_EXHAUSTED_TOPIC + ".DLT",
                NON_RETRYABLE_TOPIC, NON_RETRYABLE_TOPIC + ".DLT",
                ML_RECOVERS_TOPIC, ML_RECOVERS_TOPIC + ".DLT",
                ML_EXHAUSTED_TOPIC, ML_EXHAUSTED_TOPIC + ".DLT",
                ML_REJECTED_TOPIC, ML_REJECTED_TOPIC + ".DLT"
        );

        broker.afterPropertiesSet();
    }

    @AfterAll
    static void stopBroker() {
        broker.destroy();
    }

    @AfterEach
    void stopContainer() {
        if (container != null) {
            container.stop();
        }
    }

    private KafkaTemplate<String, String> kafkaTemplate() {

        // KafkaTestUtils.producerProps defaults to IntegerSerializer for the
        // key; production uses StringSerializer for both key and value
        // (application.yml), so override it to match.
        var producerProps = KafkaTestUtils.producerProps(broker);
        producerProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        DefaultKafkaProducerFactory<String, String> producerFactory =
                new DefaultKafkaProducerFactory<>(producerProps);

        return new KafkaTemplate<>(producerFactory);
    }

    private void startListener(
            String topic,
            String groupId,
            MessageListener<String, String> listener
    ) throws InterruptedException {
        startListener(topic, groupId, listener, KafkaErrorHandlingConfig.transientMlBackOff());
    }

    private void startListener(
            String topic,
            String groupId,
            MessageListener<String, String> listener,
            org.springframework.util.backoff.BackOff mlBackOff
    ) throws InterruptedException {

        // Same fix as kafkaTemplate(): KafkaTestUtils.consumerProps also
        // defaults to IntegerDeserializer for the key.
        var consumerProps = KafkaTestUtils.consumerProps(groupId, "false", broker);
        consumerProps.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);

        DefaultKafkaConsumerFactory<String, String> consumerFactory =
                new DefaultKafkaConsumerFactory<>(consumerProps);

        ContainerProperties containerProperties = new ContainerProperties(topic);
        containerProperties.setMessageListener(listener);

        container = new KafkaMessageListenerContainer<>(consumerFactory, containerProperties);

        // The exact bean under test - built the same way Spring Boot
        // wires it into the real listener container in production.
        container.setCommonErrorHandler(new KafkaErrorHandlingConfig().kafkaErrorHandler(kafkaTemplate(), mlBackOff));

        container.start();
        ContainerTestUtils.waitForAssignment(container, 1);
    }

    private Consumer<String, String> dltConsumer(String dltTopic, String groupId) {

        var consumerProps = KafkaTestUtils.consumerProps(groupId, "true", broker);
        consumerProps.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);

        DefaultKafkaConsumerFactory<String, String> consumerFactory =
                new DefaultKafkaConsumerFactory<>(consumerProps);

        Consumer<String, String> consumer = consumerFactory.createConsumer();
        broker.consumeFromAnEmbeddedTopic(consumer, dltTopic);
        return consumer;
    }

    @Test
    void transientFailure_succeedsOnRetry_andNeverReachesTheDeadLetterTopic() throws Exception {

        AtomicInteger attempts = new AtomicInteger(0);
        CountDownLatch succeeded = new CountDownLatch(1);

        startListener(SUCCESSFUL_RETRY_TOPIC, "successful-retry-group", record -> {
            int attempt = attempts.incrementAndGet();
            if (attempt == 1) {
                throw new RuntimeException("simulated transient failure");
            }
            succeeded.countDown();
        });

        template = kafkaTemplate();
        template.send(SUCCESSFUL_RETRY_TOPIC, "EV-RETRY-OK", "payload").get(5, TimeUnit.SECONDS);

        boolean recovered = succeeded.await(10, TimeUnit.SECONDS);

        assertThat(recovered).as("listener should eventually succeed after one retry").isTrue();
        assertThat(attempts.get()).isEqualTo(2);

        Consumer<String, String> dlt = dltConsumer(
                SUCCESSFUL_RETRY_TOPIC + ".DLT", "successful-retry-dlt-group"
        );
        try {
            ConsumerRecord<String, String> dltRecord =
                    KafkaTestUtils.getSingleRecord(dlt, SUCCESSFUL_RETRY_TOPIC + ".DLT", Duration.ofSeconds(2));
            assertThat(dltRecord).as("a successfully-retried record must not end up on the DLT").isNull();
        } catch (IllegalStateException expectedTimeout) {
            // KafkaTestUtils throws when no record arrives before the timeout -
            // that is exactly the "nothing was dead-lettered" outcome we want.
        } finally {
            dlt.close();
        }
    }

    @Test
    void retriesExhausted_publishesOriginalRecordToDeadLetterTopic() throws Exception {

        AtomicInteger attempts = new AtomicInteger(0);

        startListener(RETRY_EXHAUSTED_TOPIC, "retry-exhausted-group", record -> {
            attempts.incrementAndGet();
            throw new RuntimeException("simulated permanent failure");
        });

        template = kafkaTemplate();
        template.send(RETRY_EXHAUSTED_TOPIC, "EV-RETRY-EXHAUSTED", "payload").get(5, TimeUnit.SECONDS);

        Consumer<String, String> dlt = dltConsumer(
                RETRY_EXHAUSTED_TOPIC + ".DLT", "retry-exhausted-dlt-group"
        );
        try {
            ConsumerRecord<String, String> dltRecord =
                    KafkaTestUtils.getSingleRecord(dlt, RETRY_EXHAUSTED_TOPIC + ".DLT", Duration.ofSeconds(15));

            assertThat(dltRecord.key()).isEqualTo("EV-RETRY-EXHAUSTED");
            assertThat(dltRecord.value()).isEqualTo("payload");

            // FixedBackOff(1000L, 2L) in KafkaErrorHandlingConfig = 1 initial
            // attempt + 2 retries = 3 total invocations before giving up.
            assertThat(attempts.get()).isEqualTo(3);

        } finally {
            dlt.close();
        }
    }

    @Test
    void nonRetryableException_goesStraightToDeadLetterTopic_withoutAnyRetries() throws Exception {

        AtomicInteger attempts = new AtomicInteger(0);

        startListener(NON_RETRYABLE_TOPIC, "non-retryable-group", record -> {
            attempts.incrementAndGet();
            throw new NotFoundException("entity does not exist");
        });

        template = kafkaTemplate();
        template.send(NON_RETRYABLE_TOPIC, "EV-NON-RETRYABLE", "payload").get(5, TimeUnit.SECONDS);

        Consumer<String, String> dlt = dltConsumer(
                NON_RETRYABLE_TOPIC + ".DLT", "non-retryable-dlt-group"
        );
        try {
            ConsumerRecord<String, String> dltRecord =
                    KafkaTestUtils.getSingleRecord(dlt, NON_RETRYABLE_TOPIC + ".DLT", Duration.ofSeconds(10));

            assertThat(dltRecord.key()).isEqualTo("EV-NON-RETRYABLE");

            // NotFoundException is registered as non-retryable in
            // KafkaErrorHandlingConfig - it must be dead-lettered on the
            // very first failure, with no retries in between.
            assertThat(attempts.get()).isEqualTo(1);

        } finally {
            dlt.close();
        }
    }

    // ---------------------------------------------------------------
    // Transient vs permanent ML-service failures
    // ---------------------------------------------------------------

    @Test
    void mlServiceUnavailable_isRetriedBeyondTheDefaultThreeAttempts_andRecovers() throws Exception {

        AtomicInteger attempts = new AtomicInteger(0);
        CountDownLatch succeeded = new CountDownLatch(1);
        startListener(ML_RECOVERS_TOPIC, "ml-recovers-group", record -> {
            if (attempts.incrementAndGet() <= 5) {
                // what MlPredictionClient throws for a timeout / refused connection / 5xx / warm-up
                throw new com.anomaly.platform.ml.MlServiceUnavailableException("ML down", false, null);
            }
            succeeded.countDown();
        }, shortMlBackOff());

        template = kafkaTemplate();
        template.send(ML_RECOVERS_TOPIC, "EV-ML-RECOVERS", "payload").get(5, TimeUnit.SECONDS);

        assertThat(succeeded.await(10, TimeUnit.SECONDS)).as("recovers on attempt 6").isTrue();
        assertThat(attempts.get()).isEqualTo(6);   // the default policy would have dead-lettered it after 3

        Consumer<String, String> dlt = dltConsumer(ML_RECOVERS_TOPIC + ".DLT", "ml-recovers-dlt-group");
        try {
            KafkaTestUtils.getSingleRecord(dlt, ML_RECOVERS_TOPIC + ".DLT", Duration.ofSeconds(2));
            org.assertj.core.api.Assertions.fail("a recovered record must not be dead-lettered");
        } catch (IllegalStateException expectedTimeout) {
            // nothing dead-lettered
        } finally {
            dlt.close();
        }
    }

    @Test
    void mlServiceUnavailable_pastItsRetryBudget_isDeadLettered() throws Exception {

        AtomicInteger attempts = new AtomicInteger(0);
        startListener(ML_EXHAUSTED_TOPIC, "ml-exhausted-group", record -> {
            attempts.incrementAndGet();
            throw new com.anomaly.platform.ml.MlServiceUnavailableException("ML still down", true, null);
        }, shortMlBackOff());

        template = kafkaTemplate();
        template.send(ML_EXHAUSTED_TOPIC, "EV-ML-EXHAUSTED", "payload").get(5, TimeUnit.SECONDS);

        Consumer<String, String> dlt = dltConsumer(ML_EXHAUSTED_TOPIC + ".DLT", "ml-exhausted-dlt-group");
        try {
            ConsumerRecord<String, String> dltRecord =
                    KafkaTestUtils.getSingleRecord(dlt, ML_EXHAUSTED_TOPIC + ".DLT", Duration.ofSeconds(15));
            assertThat(dltRecord.key()).isEqualTo("EV-ML-EXHAUSTED");
            assertThat(attempts.get()).isEqualTo(8);   // 1 + 7 retries of the ML policy
        } finally {
            dlt.close();
        }
    }

    @Test
    void mlResponseRejected_goesStraightToTheDeadLetterTopic_withoutRetries() throws Exception {

        AtomicInteger attempts = new AtomicInteger(0);
        startListener(ML_REJECTED_TOPIC, "ml-rejected-group", record -> {
            attempts.incrementAndGet();
            // what MlPredictionClient throws for a 4xx or a malformed response
            throw new com.anomaly.platform.ml.MlResponseRejectedException("malformed ML response");
        }, shortMlBackOff());

        template = kafkaTemplate();
        template.send(ML_REJECTED_TOPIC, "EV-ML-REJECTED", "payload").get(5, TimeUnit.SECONDS);

        Consumer<String, String> dlt = dltConsumer(ML_REJECTED_TOPIC + ".DLT", "ml-rejected-dlt-group");
        try {
            ConsumerRecord<String, String> dltRecord =
                    KafkaTestUtils.getSingleRecord(dlt, ML_REJECTED_TOPIC + ".DLT", Duration.ofSeconds(10));
            assertThat(dltRecord.key()).isEqualTo("EV-ML-REJECTED");
            assertThat(attempts.get()).isEqualTo(1);
            // the actual reason and the supported recovery travel with the record
            assertThat(new String(dltRecord.headers().lastHeader(KafkaErrorHandlingConfig.FAILURE_HEADER).value(),
                    java.nio.charset.StandardCharsets.UTF_8))
                    .isEqualTo("MlResponseRejectedException: malformed ML response");
            assertThat(new String(dltRecord.headers().lastHeader(KafkaErrorHandlingConfig.RECOVERY_HEADER).value(),
                    java.nio.charset.StandardCharsets.UTF_8))
                    .contains("POST /api/v1/replay-runs");
            // Spring's own context headers are still there
            assertThat(dltRecord.headers().lastHeader("kafka_dlt-original-topic")).isNotNull();
        } finally {
            dlt.close();
        }
    }
}
