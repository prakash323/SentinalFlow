package com.anomaly.platform.controller;

import com.anomaly.platform.dto.CreateEntityRequest;
import com.anomaly.platform.dto.EntityDetailResponse;
import com.anomaly.platform.dto.EntityResponse;
import com.anomaly.platform.dto.EntitySummaryResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.service.EntityService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/entities")
public class EntityController {

    private final EntityService service;

    public EntityController(EntityService service) {
        this.service = service;
    }

    @GetMapping
    public PageResponse<EntitySummaryResponse> list(
            @RequestParam(required = false) String q,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return service.list(q, page, size);
    }

    @PostMapping
    public ResponseEntity<EntityResponse> create(@Valid @RequestBody CreateEntityRequest r) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(r));
    }

    @GetMapping("/{entityId}")
    public EntityDetailResponse get(@PathVariable String entityId) {
        return service.get(entityId);
    }
}
