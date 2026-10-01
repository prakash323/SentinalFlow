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

    private static EmbeddedKafkaBroker broker;

    private KafkaMessageListenerContainer<String, String> container;
    private KafkaTemplate<String, String> template;

    @BeforeAll
    static void startBroker() {

        broker = new EmbeddedKafkaKraftBroker(
                1, 1,
                SUCCESSFUL_RETRY_TOPIC, SUCCESSFUL_RETRY_TOPIC + ".DLT",
                RETRY_EXHAUSTED_TOPIC, RETRY_EXHAUSTED_TOPIC + ".DLT",
                NON_RETRYABLE_TOPIC, NON_RETRYABLE_TOPIC + ".DLT"
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
        container.setCommonErrorHandler(new KafkaErrorHandlingConfig().kafkaErrorHandler(kafkaTemplate()));

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
}
