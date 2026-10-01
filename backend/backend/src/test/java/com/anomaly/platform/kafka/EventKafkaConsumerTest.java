package com.anomaly.platform.kafka;

import com.anomaly.platform.service.EventProcessingService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/*
 * Phase 1 focused test for the Kafka consumer.
 *
 * Root cause fixed here: consume() used to catch every exception itself
 * and print a stack trace, so Spring Kafka's container never saw a
 * failure - no retry, no dead letter, and the offset committed as if the
 * message had been handled. These tests lock in that exceptions now
 * propagate out of consume() so the CommonErrorHandler configured in
 * KafkaErrorHandlingConfig can act on them.
 */
class EventKafkaConsumerTest {

    @Test
    void processingFailure_propagatesOutOfConsume_insteadOfBeingSwallowed() {

        ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
        EventProcessingService processingService = mock(EventProcessingService.class);

        EventKafkaConsumer consumer = new EventKafkaConsumer(objectMapper, processingService);

        String json = "{"
                + "\"eventId\":\"EV-1\","
                + "\"entityId\":\"USER-1\","
                + "\"eventType\":\"LOGIN\","
                + "\"eventVersion\":\"v1\","
                + "\"occurredAt\":\"2026-01-01T00:00:00Z\","
                + "\"source\":\"test\","
                + "\"payload\":{}"
                + "}";

        RuntimeException failure = new RuntimeException("simulated processing failure");
        doThrow(failure).when(processingService).process(any());

        assertThatThrownBy(() -> consumer.consume(json))
                .isSameAs(failure);
    }

    @Test
    void malformedJson_throwsIllegalArgumentException_andNeverCallsProcessingService() {

        ObjectMapper objectMapper = new ObjectMapper();
        EventProcessingService processingService = mock(EventProcessingService.class);

        EventKafkaConsumer consumer = new EventKafkaConsumer(objectMapper, processingService);

        assertThatThrownBy(() -> consumer.consume("not-valid-json"))
                .isInstanceOf(IllegalArgumentException.class);

        verify(processingService, never()).process(any());
    }

    @Test
    void validEvent_isParsedAndHandedToProcessingService() {

        ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
        EventProcessingService processingService = mock(EventProcessingService.class);

        EventKafkaConsumer consumer = new EventKafkaConsumer(objectMapper, processingService);

        String json = "{"
                + "\"eventId\":\"EV-1\","
                + "\"entityId\":\"USER-1\","
                + "\"eventType\":\"LOGIN\","
                + "\"eventVersion\":\"v1\","
                + "\"occurredAt\":\"2026-01-01T00:00:00Z\","
                + "\"source\":\"test\","
                + "\"payload\":{}"
                + "}";

        consumer.consume(json);

        verify(processingService, times(1)).process(any());
    }
}
