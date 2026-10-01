package com.anomaly.platform.entity;
import jakarta.persistence.*; import lombok.*; import java.math.BigDecimal; import java.time.OffsetDateTime; import java.util.*;
@Entity
@Table(name="alerts")
@Getter @Setter @NoArgsConstructor
public class Alert extends BaseTimestamps {
    @Id
    @GeneratedValue(strategy=GenerationType.UUID) private UUID id;
    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="event_id")
    private Event event;
    @ManyToOne(fetch=FetchType.LAZY,optional=false)
    @JoinColumn(name="entity_id")
    private EntityProfile entity;
    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="prediction_id")
    private Prediction prediction;
    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="incident_id")
    private Incident incident;
    @Enumerated(EnumType.STRING)
    @Column(nullable=false)
    private DecisionState decision;
    @Enumerated(EnumType.STRING)
    @Column(nullable=false)
    private Severity severity;
    @Enumerated(EnumType.STRING)
    @Column(nullable=false)
    private AlertStatus status;
    @Column(name="anomaly_score",precision=6,scale=5)
    private BigDecimal anomalyScore;
    @Column(precision=6,scale=5)
    private BigDecimal confidence;
    @Column(name="fused_score",precision=6,scale=5)
    private BigDecimal fusedScore;
    @Column(name="policy_version",nullable=false)
    private String policyVersion;
    @Column(name="acknowledged_at")
    private OffsetDateTime acknowledgedAt;
    @Column(name="resolved_at")
    private OffsetDateTime resolvedAt;
    // Independent deterministic detection (P1): non-null only when this
    // alert was raised by a platform rule rather than an ML prediction.
    @Column(name="rule_id",length=64)
    private String ruleId;
    @Column(name="rule_name",length=200)
    private String ruleName;
    // Concurrency hardening: without this, two concurrent status PATCHes on
    // the same alert both succeed, the loser's response lies about the
    // final state, and the audit log permanently records a transition that
    // never actually took effect - confirmed live, not hypothetical. See
    // AlertService.updateStatus and V14__add_optimistic_locking.sql.
    @Version
    @Column(nullable=false)
    private Long version;
}
