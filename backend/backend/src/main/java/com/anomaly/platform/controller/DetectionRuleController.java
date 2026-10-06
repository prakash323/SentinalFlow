package com.anomaly.platform.controller;

import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.RuleDescriptor;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/*
 * ============================================================
 * THE RULE CATALOG, READ-ONLY
 * ============================================================
 *
 * GET /api/v1/detection/rules
 *
 * Answers "what deterministic detection does this deployment actually run?" -
 * which, before the detection engine existed, could only be answered by reading
 * the source. An analyst looking at a RULE alert can now see what that rule is,
 * what it consumes and whether it is enabled.
 *
 * Authorisation needs no new configuration: SecurityConfig already requires
 * ADMIN or ANALYST for everything under /api/v1/** that is not explicitly opened,
 * so this endpoint inherits exactly that.
 *
 * ------------------------------------------------------------
 * WHAT IT DELIBERATELY DOES NOT RETURN
 * ------------------------------------------------------------
 * No thresholds, no cooldowns and no configuration values. Publishing "AUTH_BURST
 * fires at 5 failures in 5 minutes" tells anyone who can read it exactly how far
 * to stay under the bar. The window is included because it describes the rule's
 * shape rather than its sensitivity; the full threshold table lives in the
 * operator documentation, not on an API.
 *
 * Read-only by construction: there is no write method here and no way to enable,
 * disable or retune a rule through the API. Detection configuration changes go
 * through application.yml and a restart, where they are reviewable.
 */
@RestController
@RequestMapping("/api/v1/detection")
public class DetectionRuleController {

    private final DetectionEngine engine;

    public DetectionRuleController(DetectionEngine engine) {
        this.engine = engine;
    }

    @GetMapping("/rules")
    public List<RuleDescriptor> rules() {
        return engine.registry().describe(engine.properties());
    }
}
