package com.anomaly.platform.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "replay_runs")
@Getter
@Setter
@NoArgsConstructor
public class ReplayRun {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(
            name = "run_key",
            nullable = false,
            unique = true,
            length = 128
    )
    private String runKey;

    @Column(name = "source_name")
    private String sourceName;

    @Enumerated(EnumType.STRING)
    @Column(
            nullable = false,
            length = 32
    )
    private ReplayStatus status;

    @Column(
            name = "total_events",
            nullable = false
    )
    private int totalEvents;

    @Column(
            name = "processed_events",
            nullable = false
    )
    private int processedEvents;

    @Column(
            name = "failed_events",
            nullable = false
    )
    private int failedEvents;

    @Column(name = "started_at")
    private OffsetDateTime startedAt;

    @Column(name = "completed_at")
    private OffsetDateTime completedAt;

    @Column(
            name = "created_at",
            nullable = false,
            updatable = false
    )
    private OffsetDateTime createdAt;

    @PrePersist
    protected void onCreate() {

        if (createdAt == null) {
            createdAt = OffsetDateTime.now();
        }

        if (status == null) {
            status = ReplayStatus.CREATED;
        }
    }
}