package com.anomaly.platform.controller;

import com.anomaly.platform.dto.CreateReplayRunRequest;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.dto.ReplayRunResponse;
import com.anomaly.platform.service.ReplayRunService;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/replay-runs")
public class ReplayRunController {

    private final ReplayRunService replayRunService;

    public ReplayRunController(
            ReplayRunService replayRunService
    ) {
        this.replayRunService = replayRunService;
    }

    /*
     * ============================================================
     * CREATE REPLAY RUN
     * ============================================================
     */

    @PostMapping
    public ReplayRunResponse create(
            @Valid
            @RequestBody
            CreateReplayRunRequest request
    ) {

        return replayRunService.create(
                request
        );
    }

    /*
     * ============================================================
     * LIST REPLAY RUNS
     * ============================================================
     */

    @GetMapping
    public PageResponse<ReplayRunResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {

        return replayRunService.list(page, size);
    }

    /*
     * ============================================================
     * GET REPLAY RUN
     * ============================================================
     */

    @GetMapping("/{runKey}")
    public ReplayRunResponse get(
            @PathVariable String runKey
    ) {

        return replayRunService.get(
                runKey
        );
    }
}