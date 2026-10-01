package com.anomaly.platform.config;

import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.KafkaTopics;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.CommonErrorHandler;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.RetryListener;
import org.springframework.util.backoff.FixedBackOff;

/*
 * ================================================================
 * KAFKA RETRY / DEAD-LETTER CONFIGURATION
 * ================================================================
 *
 * Before this existed, EventKafkaConsumer caught every exception itself,
 * which meant Spring Kafka's container never saw a failure: no retry ever
 * happened, and the offset committed as if the record had been processed
 * successfully. A single transient DB hiccup silently and permanently
 * dropped that event from detection processing.
 *
 * This bean is picked up automatically by Spring Boot's auto-configured
 * ConcurrentKafkaListenerContainerFactory (a single CommonErrorHandler bean
 * in the context is applied to it), so no other Kafka wiring changes are
 * required.
 *
 * Behavior:
 *   - Transient failures are retried twice with a 1 second backoff
 *     (3 attempts total) before giving up.
 *   - NotFoundException / IllegalArgumentException (bad data - retrying
 *     will not help) skip straight to the dead-letter topic.
 *   - Once retries are exhausted (or a non-retryable exception is thrown),
 *     the original record is published to "raw.events.v1.DLT" instead of
 *     being silently discarded, and the failure is logged.
 */
@Configuration
public class KafkaErrorHandlingConfig {

    private static final Logger log = LoggerFactory.getLogger(KafkaErrorHandlingConfig.class);

    @Bean
    public NewTopic rawEventsTopic() {
        return new NewTopic(KafkaTopics.RAW_EVENTS, 1, (short) 1);
    }

    @Bean
    public NewTopic rawEventsDeadLetterTopic() {
        return new NewTopic(KafkaTopics.RAW_EVENTS_DLT, 1, (short) 1);
    }

    @Bean
    public CommonErrorHandler kafkaErrorHandler(KafkaTemplate<String, String> kafkaTemplate) {

        DeadLetterPublishingRecoverer recoverer =
                new DeadLetterPublishingRecoverer(kafkaTemplate);

        DefaultErrorHandler errorHandler =
                new DefaultErrorHandler(recoverer, new FixedBackOff(1000L, 2L));

        errorHandler.addNotRetryableExceptions(
                NotFoundException.class,
                IllegalArgumentException.class
        );

        errorHandler.setRetryListeners(new RetryListener() {

            @Override
            public void failedDelivery(ConsumerRecord<?, ?> record, Exception ex, int deliveryAttempt) {

                log.warn(
                        "Kafka message processing failed, will retry. topic={} key={} attempt={} reason={}",
                        record.topic(),
                        record.key(),
                        deliveryAttempt,
                        ex.getMessage()
                );
            }

            @Override
            public void recovered(ConsumerRecord<?, ?> record, Exception ex) {

                log.error(
                        "Kafka message sent to dead-letter topic after exhausted retries. topic={} key={} reason={}",
                        record.topic(),
                        record.key(),
                        ex.getMessage(),
                        ex
                );
            }

            @Override
            public void recoveryFailed(ConsumerRecord<?, ?> record, Exception original, Exception failure) {

                log.error(
                        "Kafka dead-letter publish itself failed. topic={} key={} originalReason={} recoveryReason={}",
                        record.topic(),
                        record.key(),
                        original.getMessage(),
                        failure.getMessage(),
                        failure
                );
            }
        });

        return errorHandler;
    }
}
