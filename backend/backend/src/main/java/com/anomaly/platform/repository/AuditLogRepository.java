package com.anomaly.platform.repository;
import com.anomaly.platform.entity.AuditLog; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface AuditLogRepository extends JpaRepository<AuditLog,UUID> {

    /* Uses idx_audit_logs_resource_created(resource_type, resource_id, created_at). */
    long countByResourceTypeAndResourceIdAndAction(String resourceType, UUID resourceId, String action);

    /* Whether this alert already has a DETECTION_SUPPRESSED record for this rule and triggering event. */
    @org.springframework.data.jpa.repository.Query(value = """
            SELECT EXISTS (
                SELECT 1 FROM audit_logs
                WHERE resource_type = 'ALERT'
                  AND resource_id = :alertId
                  AND action = 'DETECTION_SUPPRESSED'
                  AND details ->> 'ruleId' = :ruleId
                  AND details ->> 'triggeringEventId' = :triggeringEventId)
            """, nativeQuery = true)
    boolean existsSuppressionRecord(
            @org.springframework.data.repository.query.Param("alertId") UUID alertId,
            @org.springframework.data.repository.query.Param("ruleId") String ruleId,
            @org.springframework.data.repository.query.Param("triggeringEventId") String triggeringEventId
    );
}
