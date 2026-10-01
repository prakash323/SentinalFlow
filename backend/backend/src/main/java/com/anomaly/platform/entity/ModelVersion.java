package com.anomaly.platform.entity;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes; import lombok.*; import java.time.OffsetDateTime; import java.util.Map; import java.util.UUID;
@Entity
@Table(name="model_versions")
@Getter
@Setter
@NoArgsConstructor
public class ModelVersion {
    @Id
    @GeneratedValue(strategy=GenerationType.UUID)
    private UUID id;
    @Column(name="model_name",nullable=false)
    private String modelName;
    @Column(nullable=false)
    private String version;
    @Column(name="artifact_uri")
    private String artifactUri;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition="jsonb",nullable=false)
    private Map<String,Object> metadata;
    @Column(nullable=false)
    private boolean active;
    @Column(name="created_at",nullable=false,updatable=false)
    private OffsetDateTime createdAt;
}
