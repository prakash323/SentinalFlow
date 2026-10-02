package com.anomaly.platform.config;

import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.kafka.KafkaTopics;
import com.anomaly.platform.ml.MlResponseRejectedException;
import com.anomaly.platform.ml.MlServiceUnavailableException;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.internals.RecordHeaders;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.CommonErrorHandler;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.ListenerExecutionFailedException;
import org.springframework.kafka.listener.RetryListener;
import org.springframework.util.backoff.BackOff;

import java.nio.charset.StandardCharsets;
import org.springframework.util.backoff.ExponentialBackOff;
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
 *   - A transient ML-service failure (MlServiceUnavailableException) is
 *     retried with exponential backoff for ~5 minutes - see
 *     transientMlBackOff().
 *   - Any other failure is retried twice with a 1 second backoff
 *     (3 attempts total) before giving up.
 *   - A permanent ML failure (MlResponseRejectedException: 4xx or a
 *     malformed response) is not retried.
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

    /*
     * Backoff for a transient ML-service failure (MlServiceUnavailableException:
     * unreachable, timeout, 5xx incl. warm-up): 1s, 2s, 4s, 8s, 16s, then 30s
     * steps until 5 minutes of waiting have been spent - 14 retries, 15
     * attempts. Each attempt also takes up to connect (2s) + read (8s)
     * timeout, so the wall-clock window is ~5 min when the service refuses
     * connections and up to ~7.5 min when every attempt times out. The
     * longest single wait (30s) stays far below the consumer's
     * max.poll.interval.ms (5 min default).
     *
     * Throughput trade-off: raw.events.v1 has one partition and one consumer,
     * so while one event waits out its backoff every event behind it waits
     * too (they would fail the same way during an ML outage). An outage of
     * T minutes dead-letters roughly T/5 events instead of every event that
     * arrives; the rest are processed once the service is back.
     */
    static ExponentialBackOff transientMlBackOff() {
        ExponentialBackOff backOff = new ExponentialBackOff(1000L, 2.0);
        backOff.setMaxInterval(30_000L);
        backOff.setMaxElapsedTime(300_000L);
        return backOff;
    }

    @Bean
    public CommonErrorHandler kafkaErrorHandler(KafkaTemplate<String, String> kafkaTemplate) {
        return kafkaErrorHandler(kafkaTemplate, transientMlBackOff());
    }

    /* The ML backoff is a parameter so tests can run the same handler with short delays. */
    CommonErrorHandler kafkaErrorHandler(KafkaTemplate<String, String> kafkaTemplate, BackOff transientMlBackOff) {

        DeadLetterPublishingRecoverer recoverer =
                new DeadLetterPublishingRecoverer(kafkaTemplate);

        // Spring already adds kafka_dlt-* headers (original topic/partition/
        // offset, exception class, full stack trace) and keeps the key
        // (= eventId) and value. Its exception-message header is only the
        // generic listener wrapper, so add the actual reason and what an
        // operator can do about this record.
        recoverer.setHeadersFunction((record, ex) -> {
            RecordHeaders headers = new RecordHeaders();
            headers.add(FAILURE_HEADER, failureReason(ex).getBytes(StandardCharsets.UTF_8));
            headers.add(RECOVERY_HEADER, recoveryAction(ex).getBytes(StandardCharsets.UTF_8));
            return headers;
        });

        // Default for everything else (e.g. a database hiccup): unchanged,
        // 3 attempts 1 second apart.
        DefaultErrorHandler errorHandler =
                new DefaultErrorHandler(recoverer, new FixedBackOff(1000L, 2L));

        errorHandler.setBackOffFunction((record, ex) ->
                hasCause(ex, MlServiceUnavailableException.class) ? transientMlBackOff : null);

        errorHandler.addNotRetryableExceptions(
                NotFoundException.class,
                IllegalArgumentException.class,
                // 4xx / malformed ML response: retrying cannot change the answer
                MlResponseRejectedException.class
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
                        "Kafka message sent to dead-letter topic {}. topic={} eventId={} reason={} recovery={}",
                        KafkaTopics.RAW_EVENTS_DLT,
                        record.topic(),
                        record.key(),
                        failureReason(ex),
                        recoveryAction(ex),
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

    static final String FAILURE_HEADER = "sentinelflow-failure";
    static final String RECOVERY_HEADER = "sentinelflow-recovery";

    /* "ExceptionType: message" of the first cause that is not Spring's listener wrapper. */
    static String failureReason(Throwable ex) {
        Throwable reason = ex;
        while (reason instanceof ListenerExecutionFailedException && reason.getCause() != null) {
            reason = reason.getCause();
        }
        String text = reason.getClass().getSimpleName() + ": " + reason.getMessage();
        return text.length() <= 500 ? text : text.substring(0, 497) + "...";
    }

    /*
     * The supported recovery for a dead-lettered record. Whether an event row
     * exists decides it: POST /api/v1/replay-runs works only from the stored
     * event; a record whose event was never stored can only be re-published.
     */
    static String recoveryAction(Throwable ex) {

        if (hasCause(ex, MlServiceUnavailableException.class)) {
            return "Event is stored and FAILED: the ML service stayed unavailable for the whole retry window. "
                    + "Once it is healthy, recover the event with POST /api/v1/replay-runs.";
        }
        if (hasCause(ex, MlResponseRejectedException.class)) {
            return "Event is stored and FAILED: the ML service rejected the request or returned an unusable response, "
                    + "so retrying it unchanged fails again. Check GET /api/v1/events/{eventId}/trail, fix the cause, "
                    + "then use POST /api/v1/replay-runs.";
        }
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof NotFoundException && String.valueOf(t.getMessage()).startsWith("Entity not found")) {
                return "No event row was stored: the entity is not registered. Register it (POST /api/v1/entities), "
                        + "then re-publish this record's value to " + KafkaTopics.RAW_EVENTS + " (key = eventId). "
                        + "POST /api/v1/replay-runs cannot recover it.";
            }
            if (t instanceof IllegalArgumentException) {
                return "No event row was stored: the record is malformed or invalid and cannot be processed as sent. "
                        + "Fix the producer and send a corrected event.";
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return "If GET /api/v1/events/{eventId} finds the event, it is FAILED with this error recorded: fix the cause "
                + "and recover it with POST /api/v1/replay-runs. If not found, no row was stored: fix the cause and "
                + "re-publish this record's value to " + KafkaTopics.RAW_EVENTS + ".";
    }

    /* The listener's exception arrives wrapped (ListenerExecutionFailedException). */
    static boolean hasCause(Throwable ex, Class<? extends Throwable> type) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (type.isInstance(t)) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }
}
