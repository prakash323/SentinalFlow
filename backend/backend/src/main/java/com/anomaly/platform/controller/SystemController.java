package com.anomaly.platform.controller;

import com.anomaly.platform.dto.SystemStatusResponse;
import com.anomaly.platform.service.SystemStatusService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/system")
public class SystemController {

    private final SystemStatusService service;

    public SystemController(SystemStatusService service) {
        this.service = service;
    }

    @GetMapping("/status")
    public SystemStatusResponse status() {
        return service.status();
    }
}
