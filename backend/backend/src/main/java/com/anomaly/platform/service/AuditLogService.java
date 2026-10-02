package com.anomaly.platform.service;

import com.anomaly.platform.dto.AuditLogResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.entity.AuditLog;
import com.anomaly.platform.repository.AuditLogRepository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(
            AuditLogRepository auditLogRepository
    ) {
        this.auditLogRepository = auditLogRepository;
    }

    /*
     * ============================================================
     * LIST AUDIT LOGS (newest first)
     * ============================================================
     *
     * Read-only addition for Phase 3 - does not touch log(...), which
     * Phase 1/2 reliability code depends on.
     */
    @Transactional(readOnly = true)
    public PageResponse<AuditLogResponse> list(
            int page,
            int size
    ) {

        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 200),
                Sort.by(Sort.Direction.DESC, "createdAt")
        );

        Page<AuditLog> logs = auditLogRepository.findAll(pageable);

        return PageResponse.from(
                logs.map(this::toResponse)
        );
    }

    private AuditLogResponse toResponse(AuditLog log) {

        return new AuditLogResponse(
                log.getId(),
                log.getActor(),
                log.getAction(),
                log.getResourceType(),
                log.getResourceId(),
                log.getCorrelationId(),
                log.getDetails(),
                log.getCreatedAt()
        );
    }

    @Transactional(readOnly = true)
    public boolean hasSuppressionRecord(UUID alertId, String ruleId, String triggeringEventId) {
        return auditLogRepository.existsSuppressionRecord(alertId, ruleId, triggeringEventId);
    }

    @Transactional
    public AuditLog log(
            String actor,
            String action,
            String resourceType,
            UUID resourceId,
            String correlationId,
            Map<String, Object> details
    ) {

        AuditLog auditLog = new AuditLog();

        auditLog.setActor(actor);
        auditLog.setAction(action);
        auditLog.setResourceType(resourceType);
        auditLog.setResourceId(resourceId);
        auditLog.setCorrelationId(correlationId);

        auditLog.setDetails(
                details == null
                        ? Map.of()
                        : details
        );

        auditLog.setCreatedAt(
                OffsetDateTime.now()
        );

        return auditLogRepository.save(
                auditLog
        );
    }
}