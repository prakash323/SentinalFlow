package com.anomaly.platform.controller;

import com.anomaly.platform.ai.AiDetail;
import com.anomaly.platform.ai.IncidentAiResponse;
import com.anomaly.platform.ai.IncidentAiService;
import com.anomaly.platform.ai.IncidentEvidence;
import com.anomaly.platform.ai.IncidentEvidenceService;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/*
 * Analyst-assistance endpoints for an existing incident. Keyed by the same
 * UUID `id` IncidentController already uses for GET/{id} and
 * PATCH/{id}/status, for consistency with the rest of this controller
 * family - not by incidentKey, which nothing else in this API uses as a
 * path variable.
 *
 * No @PreAuthorize/role annotation is needed here: these paths fall under
 * the existing SecurityConfig catch-all
 * (.requestMatchers("/api/v1/**").hasAnyRole("ADMIN","ANALYST")), so they
 * already require authentication and at least ANALYST - verified in
 * IncidentAiControllerTest and live in the Phase 6 report.
 */
@RestController
@RequestMapping("/api/v1/incidents/{id}/ai")
public class IncidentAiController {

    private final IncidentEvidenceService evidenceService;
    private final IncidentAiService aiService;

    public IncidentAiController(
            IncidentEvidenceService evidenceService,
            IncidentAiService aiService
    ) {
        this.evidenceService = evidenceService;
        this.aiService = aiService;
    }

    /*
     * `detail` is optional on all three. Absent (or "concise") keeps the
     * original single-argument service call, so the default path is exactly
     * what it was; "detailed" is the explicit opt-in behind "Show detailed
     * analysis". Any other value is a 400 (see AiDetail.parse).
     */
    @PostMapping("/explanation")
    @ResponseStatus(HttpStatus.OK)
    public IncidentAiResponse explanation(
            @PathVariable UUID id,
            @RequestParam(name = "detail", required = false) String detail
    ) {
        AiDetail level = AiDetail.parse(detail);
        IncidentEvidence evidence = evidenceService.gather(id);
        return level == AiDetail.DETAILED
                ? aiService.explain(evidence, level)
                : aiService.explain(evidence);
    }

    @PostMapping("/evidence-summary")
    @ResponseStatus(HttpStatus.OK)
    public IncidentAiResponse evidenceSummary(
            @PathVariable UUID id,
            @RequestParam(name = "detail", required = false) String detail
    ) {
        AiDetail level = AiDetail.parse(detail);
        IncidentEvidence evidence = evidenceService.gather(id);
        return level == AiDetail.DETAILED
                ? aiService.summarizeEvidence(evidence, level)
                : aiService.summarizeEvidence(evidence);
    }

    @PostMapping("/investigation")
    @ResponseStatus(HttpStatus.OK)
    public IncidentAiResponse investigation(
            @PathVariable UUID id,
            @RequestParam(name = "detail", required = false) String detail
    ) {
        AiDetail level = AiDetail.parse(detail);
        IncidentEvidence evidence = evidenceService.gather(id);
        return level == AiDetail.DETAILED
                ? aiService.recommendInvestigation(evidence, level)
                : aiService.recommendInvestigation(evidence);
    }
}
