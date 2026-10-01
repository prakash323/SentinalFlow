package com.anomaly.platform.entity;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes; import lombok.*; import java.time.OffsetDateTime; import java.util.Map; import java.util.UUID;
@Entity @Table(name="feature_snapshots") @Getter @Setter @NoArgsConstructor
public class FeatureSnapshot { @Id @GeneratedValue(strategy=GenerationType.UUID) private UUID id; @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="event_id") private Event event; @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="entity_id") private EntityProfile entity; @Column(name="feature_version",nullable=false) private String featureVersion; @JdbcTypeCode(SqlTypes.JSON) @Column(columnDefinition="jsonb",nullable=false) private Map<String,Object> features; @Column(name="created_at",nullable=false,updatable=false) private OffsetDateTime createdAt; }
