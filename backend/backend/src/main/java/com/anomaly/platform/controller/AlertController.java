package com.anomaly.platform.controller;
import com.anomaly.platform.dto.*; import com.anomaly.platform.entity.*; import com.anomaly.platform.service.AlertService; import jakarta.validation.Valid; import org.springframework.web.bind.annotation.*; import java.util.*;
@RestController @RequestMapping("/api/v1/alerts")
public class AlertController {
    private final AlertService service;
    public AlertController(AlertService service){
        this.service=service;
    }
    @GetMapping public PageResponse<AlertResponse> list(@RequestParam(required=false) AlertStatus status,@RequestParam(required=false) Severity severity,@RequestParam(required=false) DecisionState decision,@RequestParam(required=false) String entityId,@RequestParam(required=false) String source,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size){
        return service.list(status,severity,decision,entityId,source,page,size);
    }
    @GetMapping("/{id}")
    public AlertResponse get(@PathVariable UUID id){return service.get(id);
    }
    @PatchMapping("/{id}/status") public AlertResponse update(@PathVariable UUID id,@Valid @RequestBody StatusUpdateRequest r){
        return service.updateStatus(id,r.status());
    }
}
