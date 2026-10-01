package com.anomaly.platform.controller;

import com.anomaly.platform.dto.IncidentAlertResponse;
import com.anomaly.platform.dto.IncidentResponse;
import com.anomaly.platform.dto.IncidentStatusUpdateRequest;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.service.IncidentService;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/incidents")
public class IncidentController {

    private final IncidentService service;

    public IncidentController(
            IncidentService service
    ) {
        this.service = service;
    }

    /*
     * ============================================================
     * GET /api/v1/incidents
     * ============================================================
     */

    @GetMapping
    public PageResponse<IncidentResponse> list(
            @RequestParam(
                    required = false
            )
            IncidentStatus status,

            @RequestParam(
                    required = false
            )
            String entityId,

            @RequestParam(
                    required = false
            )
            String source,

            @RequestParam(
                    defaultValue = "0"
            )
            int page,

            @RequestParam(
                    defaultValue = "20"
            )
            int size
    ) {

        return service.list(
                status,
                entityId,
                source,
                page,
                size
        );
    }

    /*
     * ============================================================
     * GET /api/v1/incidents/{id}
     * ============================================================
     */

    @GetMapping("/{id}")
    public IncidentResponse get(
            @PathVariable UUID id
    ) {

        return service.get(id);
    }

    /*
     * ============================================================
     * GET /api/v1/incidents/{id}/alerts
     * ============================================================
     */

    @GetMapping("/{id}/alerts")
    public List<IncidentAlertResponse> getAlerts(
            @PathVariable UUID id
    ) {

        return service.getAlerts(id);
    }

    /*
     * ============================================================
     * PATCH /api/v1/incidents/{id}/status
     * ============================================================
     */

    @PatchMapping("/{id}/status")
    public IncidentResponse updateStatus(
            @PathVariable UUID id,

            @Valid
            @RequestBody
            IncidentStatusUpdateRequest request
    ) {

        return service.updateStatus(
                id,
                request.status()
        );
    }
}