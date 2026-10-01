package com.anomaly.platform.controller;

import com.anomaly.platform.dto.AuditLogResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.service.AuditLogService;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/audit-logs")
public class AuditLogController {

    private final AuditLogService service;

    public AuditLogController(AuditLogService service) {
        this.service = service;
    }

    @GetMapping
    public PageResponse<AuditLogResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return service.list(page, size);
    }
}
