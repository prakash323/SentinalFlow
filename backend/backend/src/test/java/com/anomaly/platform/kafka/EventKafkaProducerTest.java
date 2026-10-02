package com.anomaly.platform.kafka;

import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.exception.PayloadTooLargeException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.apache.kafka.common.errors.RecordTooLargeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.OffsetDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Regression for an event that was committed to PostgreSQL but could never
 * reach Kafka: reproduced live with a 1.1 MB payload - the client got a 500
 * while the row stayed PENDING forever, and a retry was rejected as a
 * duplicate (409).
 */
class EventKafkaProducerTest {

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, String> kafkaTemplate = mock(KafkaTemplate.class);

    private final EventKafkaProducer producer = new EventKafkaProducer(
            kafkaTemplate,
            new ObjectMapper().registerModule(new JavaTimeModule())
    );

    @AfterEach
    void clearSynchronization() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private CreateEventRequest event(String blob) {
        return new CreateEventRequest(
                "EV-1", "HOST-1", "LOGIN", "v1",
                OffsetDateTime.parse("2026-10-02T04:00:00Z"), "test",
                Map.of("loginSuccess", false, "blob", blob)
        );
    }

    @Test
    void ensurePublishable_acceptsANormalEvent() {

        assertThatCode(() -> producer.ensurePublishable(event("x")))
                .doesNotThrowAnyException();
    }

    @Test
    void ensurePublishable_rejectsAnEventTooLargeForKafka() {

        assertThatThrownBy(() -> producer.ensurePublishable(
                event("x".repeat(EventKafkaProducer.MAX_EVENT_BYTES))))
                .isInstanceOf(PayloadTooLargeException.class)
                .hasMessageContaining("maximum is " + EventKafkaProducer.MAX_EVENT_BYTES);
    }

    @Test
    void sendFailureAfterCommit_isLoggedNotThrown_becauseTheEventIsAlreadyStored() {

        when(kafkaTemplate.send(anyString(), anyString(), anyString()))
                .thenThrow(new KafkaException("send failed", new RecordTooLargeException("too large")));

        TransactionSynchronizationManager.initSynchronization();
        producer.publish(event("x"));

        for (TransactionSynchronization synchronization : TransactionSynchronizationManager.getSynchronizations()) {
            assertThatCode(synchronization::afterCommit).doesNotThrowAnyException();
        }
        verify(kafkaTemplate).send(eq(KafkaTopics.RAW_EVENTS), eq("EV-1"), any());
    }

    // ---- publishNow: synchronous publish used by PendingEventReconciler ----

    @Test
    void publishNow_returnsOnceTheBrokerAcknowledges() {

        var metadata = new org.apache.kafka.clients.producer.RecordMetadata(
                new org.apache.kafka.common.TopicPartition(KafkaTopics.RAW_EVENTS, 0), 7L, 0, 0L, 4, 10);
        when(kafkaTemplate.send(anyString(), anyString(), anyString())).thenReturn(
                java.util.concurrent.CompletableFuture.completedFuture(
                        new org.springframework.kafka.support.SendResult<>(null, metadata)));

        assertThatCode(() -> producer.publishNow(event("x"), java.time.Duration.ofSeconds(1)))
                .doesNotThrowAnyException();
        verify(kafkaTemplate).send(eq(KafkaTopics.RAW_EVENTS), eq("EV-1"), any());
    }

    @Test
    void publishNow_throwsWhenTheBrokerRejectsTheRecord() {

        when(kafkaTemplate.send(anyString(), anyString(), anyString())).thenReturn(
                java.util.concurrent.CompletableFuture.failedFuture(new KafkaException("broker unavailable")));

        assertThatThrownBy(() -> producer.publishNow(event("x"), java.time.Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("EV-1");
    }

    @Test
    void publishNow_throwsWhenTheBrokerDoesNotAcknowledgeInTime() {

        when(kafkaTemplate.send(anyString(), anyString(), anyString()))
                .thenReturn(new java.util.concurrent.CompletableFuture<>());   // never completes

        assertThatThrownBy(() -> producer.publishNow(event("x"), java.time.Duration.ofMillis(50)))
                .isInstanceOf(IllegalStateException.class)
                .hasCauseInstanceOf(java.util.concurrent.TimeoutException.class);
    }
}
