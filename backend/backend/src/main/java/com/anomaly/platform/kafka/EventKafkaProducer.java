package com.anomaly.platform.kafka;

import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.exception.PayloadTooLargeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Component
public class EventKafkaProducer {

    private static final Logger log = LoggerFactory.getLogger(EventKafkaProducer.class);

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public EventKafkaProducer(
            KafkaTemplate<String, String> kafkaTemplate,
            ObjectMapper objectMapper
    ) {
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
    }

    /*
     * Largest serialized event accepted for publication. The producer's
     * max.request.size is Kafka's 1 MiB default; this leaves headroom for
     * record/batch overhead. Real events are a few hundred bytes.
     */
    static final int MAX_EVENT_BYTES = 512 * 1024;

    /*
     * Called by EventService BEFORE the event is persisted: an event Kafka
     * would refuse used to be committed first and then fail in afterCommit -
     * the client got a 500 while the row stayed PENDING forever (and a
     * retry was rejected as a duplicate).
     */
    public void ensurePublishable(CreateEventRequest request) {

        int size = serialize(request).getBytes(StandardCharsets.UTF_8).length;

        if (size > MAX_EVENT_BYTES) {
            throw new PayloadTooLargeException(
                    "Event is " + size + " bytes; the maximum is " + MAX_EVENT_BYTES + " bytes"
            );
        }
    }

    private String serialize(CreateEventRequest request) {

        try {
            return objectMapper.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(
                    "Failed to serialize event: " + request.eventId(),
                    e
            );
        }
    }

    /*
     * Synchronous publish for PendingEventReconciler: returns only once the
     * broker acknowledged the record, otherwise throws. (send() itself can
     * still block up to the producer's max.block.ms while the broker is
     * unreachable, before the timeout below starts.)
     */
    public void publishNow(CreateEventRequest request, Duration timeout) {

        String eventJson = serialize(request);

        try {
            var result = kafkaTemplate
                    .send(KafkaTopics.RAW_EVENTS, request.eventId(), eventJson)
                    .get(timeout.toMillis(), TimeUnit.MILLISECONDS);

            log.info(
                    "Event re-published to Kafka eventId={} partition={} offset={}",
                    request.eventId(),
                    result.getRecordMetadata().partition(),
                    result.getRecordMetadata().offset()
            );
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while re-publishing event: " + request.eventId(), e);
        } catch (ExecutionException | TimeoutException | RuntimeException e) {
            throw new IllegalStateException("Failed to re-publish event to Kafka: " + request.eventId(), e);
        }
    }

    public void publish(CreateEventRequest request) {

        try {

            String eventJson =
                    objectMapper.writeValueAsString(request);

            /*
             * ========================================================
             * IMPORTANT
             * ========================================================
             *
             * EventService is @Transactional.
             *
             * If we publish to Kafka immediately, Kafka may deliver
             * the message before PostgreSQL commits the Event.
             *
             * Therefore the Kafka consumer may not find the Event
             * and may try to insert it again.
             *
             * We publish ONLY AFTER the database transaction commits.
             */

            if (TransactionSynchronizationManager
                    .isSynchronizationActive()) {

                TransactionSynchronizationManager
                        .registerSynchronization(
                                new TransactionSynchronization() {

                                    @Override
                                    public void afterCommit() {

                                        // The event is already committed, so
                                        // throwing here only turned a stored
                                        // event into a 500 the client could
                                        // not retry (409 duplicate). It stays
                                        // PENDING and is recoverable through
                                        // POST /api/v1/replay-runs.
                                        try {
                                            sendToKafka(
                                                    request.eventId(),
                                                    eventJson
                                            );
                                        } catch (RuntimeException publishFailure) {
                                            log.error(
                                                    "Event persisted but NOT published to Kafka eventId={} - it stays PENDING until replayed",
                                                    request.eventId(),
                                                    publishFailure
                                            );
                                        }
                                    }
                                }
                        );

            } else {

                /*
                 * If there is no active transaction,
                 * publish immediately.
                 */

                sendToKafka(
                        request.eventId(),
                        eventJson
                );
            }

        } catch (JsonProcessingException e) {

            throw new IllegalStateException(
                    "Failed to serialize event: "
                            + request.eventId(),
                    e
            );
        }
    }

    /*
     * ============================================================
     * ACTUAL KAFKA SEND
     * ============================================================
     */

    private void sendToKafka(
            String eventId,
            String eventJson
    ) {

        try {

            kafkaTemplate
                    .send(
                            KafkaTopics.RAW_EVENTS,
                            eventId,
                            eventJson
                    )
                    .whenComplete(
                            (result, exception) -> {

                                if (exception != null) {

                                    log.error(
                                            "Failed to publish event to Kafka eventId={}",
                                            eventId,
                                            exception
                                    );

                                } else {

                                    log.info(
                                            "Event published to Kafka eventId={} partition={} offset={}",
                                            eventId,
                                            result.getRecordMetadata().partition(),
                                            result.getRecordMetadata().offset()
                                    );
                                }
                            }
                    );

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Failed to publish event to Kafka: "
                            + eventId,
                    e
            );
        }
    }
}
