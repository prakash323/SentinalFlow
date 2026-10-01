package com.anomaly.platform.entity;
import jakarta.persistence.*; import lombok.*; import java.time.OffsetDateTime; import java.util.UUID;
@Entity @Table(name="alert_factors")
@Getter @Setter @NoArgsConstructor
public class AlertFactor {
    @Id
    @GeneratedValue(strategy=GenerationType.UUID)
    private UUID id;
    @ManyToOne(fetch=FetchType.LAZY,optional=false)
    @JoinColumn(name="alert_id")
    private Alert alert;
    @Column(nullable=false,length=128)
    private String factor;
    @Column(name="rank",nullable=false)
    private int rank;
    @Column(name="created_at",nullable=false,updatable=false)
    private OffsetDateTime createdAt;
}
