package com.anomaly.platform.controller;

import com.anomaly.platform.dto.DashboardSummaryResponse;
import com.anomaly.platform.service.DashboardService;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/dashboard")
public class DashboardController {

    private final DashboardService service;

    public DashboardController(DashboardService service) {
        this.service = service;
    }

    @GetMapping("/summary")
    public DashboardSummaryResponse summary(
            @RequestParam(defaultValue = "8") int hours
    ) {
        return service.summary(hours);
    }
}
