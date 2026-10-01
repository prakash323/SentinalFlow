package com.anomaly.platform.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "events")
@Getter
@Setter
@NoArgsConstructor
public class Event {

 @Id
 @GeneratedValue(strategy = GenerationType.UUID)
 private UUID id;

 @Column(name = "event_id", nullable = false, unique = true, length = 128)
 private String eventId;

 @ManyToOne(fetch = FetchType.LAZY, optional = false)
 @JoinColumn(name = "entity_id")
 private EntityProfile entity;

 @Column(name = "event_type", nullable = false, length = 128)
 private String eventType;

 @Column(name = "event_version", nullable = false, length = 32)
 private String eventVersion;

 @Column(name = "occurred_at", nullable = false)
 private OffsetDateTime occurredAt;

 @Column(length = 128)
 private String source;

 @JdbcTypeCode(SqlTypes.JSON)
 @Column(columnDefinition = "jsonb", nullable = false)
 private Map<String, Object> payload;

 @Column(name = "created_at", nullable = false, updatable = false)
 private OffsetDateTime createdAt;

 /*
  * Processing lifecycle of this event through the detection pipeline.
  *
  * Defaults to PENDING so that an event created via the REST API (which
  * does not set this explicitly) is correctly reported as not-yet-processed
  * until the Kafka consumer (or a replay run) runs it through
  * EventProcessingService.
  */
 @Enumerated(EnumType.STRING)
 @Column(name = "processing_status", nullable = false, length = 32)
 private EventProcessingStatus processingStatus = EventProcessingStatus.PENDING;

 @Column(name = "processing_attempts", nullable = false)
 private int processingAttempts = 0;

 @Column(name = "last_processing_error", columnDefinition = "text")
 private String lastProcessingError;

 @Column(name = "processed_at")
 private OffsetDateTime processedAt;

 @PrePersist
 protected void onCreate() {
  createdAt = OffsetDateTime.now();
 }
}