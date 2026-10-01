package com.anomaly.platform.kafka;

import com.anomaly.platform.dto.CreateEventRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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

                                        sendToKafka(
                                                request.eventId(),
                                                eventJson
                                        );
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
