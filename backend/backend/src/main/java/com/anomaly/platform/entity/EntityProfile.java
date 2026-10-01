package com.anomaly.platform.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import lombok.*;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Entity @Table(name="entities") @Getter @Setter @NoArgsConstructor
public class EntityProfile extends BaseTimestamps {
 @Id @GeneratedValue(strategy=GenerationType.UUID) private UUID id;
 @Column(name="entity_id", nullable=false, unique=true, length=128) private String entityId;
 @Column(name="entity_type", nullable=false, length=64) private String entityType;
 @Column(name="display_name") private String displayName;
 @JdbcTypeCode(SqlTypes.JSON) @Column(columnDefinition="jsonb", nullable=false) private Map<String,Object> metadata;
}
