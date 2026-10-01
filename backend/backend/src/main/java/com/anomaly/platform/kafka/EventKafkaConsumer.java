package com.anomaly.platform.kafka;

import com.anomaly.platform.service.EventProcessingService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
public class EventKafkaConsumer {

    private static final Logger log = LoggerFactory.getLogger(EventKafkaConsumer.class);

    private final ObjectMapper objectMapper;
    private final EventProcessingService processingService;

    public EventKafkaConsumer(
            ObjectMapper objectMapper,
            EventProcessingService processingService
    ) {
        this.objectMapper = objectMapper;
        this.processingService = processingService;
    }

    /*
     * Exceptions are intentionally NOT caught-and-discarded here.
     *
     * Letting them propagate out of the listener lets the CommonErrorHandler
     * configured in KafkaErrorHandlingConfig retry transient failures with
     * backoff and route exhausted/non-retryable failures to the dead-letter
     * topic (raw.events.v1.DLT), instead of the previous behavior of
     * printing a stack trace and committing the offset as if nothing
     * happened - which is how a processing failure used to make an event
     * disappear from the detection pipeline with no trace at all.
     */
    @KafkaListener(
            topics = KafkaTopics.RAW_EVENTS,
            groupId = "anomaly-platform-events"
    )
    public void consume(String eventJson) {

        KafkaEvent event;

        try {

            event = objectMapper.readValue(
                    eventJson,
                    KafkaEvent.class
            );

        } catch (Exception parseException) {

            log.error(
                    "Failed to parse Kafka event payload: {}",
                    eventJson,
                    parseException
            );

            throw new IllegalArgumentException(
                    "Malformed Kafka event payload",
                    parseException
            );
        }

        processingService.process(event);
    }
}
