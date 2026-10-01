package com.anomaly.platform.controller;

import com.anomaly.platform.dto.CreatePredictionRequest;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.dto.PredictionResponse;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.service.PredictionService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/predictions")
public class PredictionController {

    private final PredictionService service;

    public PredictionController(PredictionService service) {
        this.service = service;
    }

    @GetMapping
    public PageResponse<PredictionResponse> list(
            @RequestParam(required = false) String entityId,
            @RequestParam(required = false) DecisionState decision,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return service.list(entityId, decision, page, size);
    }

    @GetMapping("/{id}")
    public PredictionResponse get(
            @PathVariable UUID id
    ) {
        return service.get(id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PredictionResponse create(
            @Valid @RequestBody CreatePredictionRequest request
    ) {
        return service.create(request);
    }
}