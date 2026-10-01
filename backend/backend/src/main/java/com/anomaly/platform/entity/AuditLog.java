package com.anomaly.platform.entity;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes; import lombok.*; import java.time.OffsetDateTime; import java.util.Map; import java.util.UUID;
@Entity
@Table(name="audit_logs")
@Getter
@Setter
@NoArgsConstructor
public class AuditLog {
    @Id
    @GeneratedValue(strategy=GenerationType.UUID)
    private UUID id;
    private String actor;
    @Column(nullable=false)
    private String action;
    @Column(name="resource_type",nullable=false)
    private String resourceType;
    @Column(name="resource_id")
    private UUID resourceId;
    @Column(name="correlation_id")
    private String correlationId;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition="jsonb",nullable=false)
    private Map<String,Object> details;
    @Column(name="created_at",nullable=false,updatable=false)
    private OffsetDateTime createdAt;
}
