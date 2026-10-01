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
}
