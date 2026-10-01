package com.anomaly.platform.entity;
import jakarta.persistence.*; import lombok.*; import java.time.OffsetDateTime; import java.util.UUID;
@Entity @Table(name="incidents") @Getter @Setter @NoArgsConstructor
public class Incident extends BaseTimestamps { @Id @GeneratedValue(strategy=GenerationType.UUID) private UUID id; @Column(name="incident_key",nullable=false,unique=true) private String incidentKey; @ManyToOne(fetch=FetchType.LAZY) @JoinColumn(name="entity_id") private EntityProfile entity; @Enumerated(EnumType.STRING) @Column(nullable=false) private IncidentStatus status; @Column(columnDefinition="text") private String summary; @Column(name="closed_at") private OffsetDateTime closedAt;
    // Concurrency hardening: see Alert.version and V14__add_optimistic_locking.sql
    // - the same lost-update risk applies here, including when
    // IncidentService.synchronizeAlerts races a concurrent direct alert PATCH.
    @Version
    @Column(nullable=false)
    private Long version;
}
