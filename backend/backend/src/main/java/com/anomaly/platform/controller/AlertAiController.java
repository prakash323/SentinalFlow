package com.anomaly.platform.controller;

import com.anomaly.platform.ai.AiDetail;
import com.anomaly.platform.ai.AlertAiEvidence;
import com.anomaly.platform.ai.AlertAiEvidenceService;
import com.anomaly.platform.ai.AlertAiResponse;
import com.anomaly.platform.ai.AlertAiService;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/*
 * Analyst-assistance endpoint for an existing alert. Keyed by the same UUID
 * `id` AlertController uses. It is deliberately a separate controller from
 * AlertController: nothing that can change an alert is reachable from here,
 * and it only POSTs to generate text (no state is written).
 *
 * No role annotation is needed: /api/v1/** already requires ADMIN or ANALYST
 * (see SecurityConfig) - verified in AlertAiControllerTest.
 *
 * `detail` is optional; absent means the concise default. "detailed" is the
 * explicit opt-in behind the "Show detailed analysis" interaction.
 */
@RestController
@RequestMapping("/api/v1/alerts/{id}/ai")
public class AlertAiController {

    private final AlertAiEvidenceService evidenceService;
    private final AlertAiService aiService;

    public AlertAiController(
            AlertAiEvidenceService evidenceService,
            AlertAiService aiService
    ) {
        this.evidenceService = evidenceService;
        this.aiService = aiService;
    }

    @PostMapping("/explanation")
    @ResponseStatus(HttpStatus.OK)
    public AlertAiResponse explanation(
            @PathVariable UUID id,
            @RequestParam(name = "detail", required = false) String detail
    ) {
        AiDetail level = AiDetail.parse(detail);
        AlertAiEvidence evidence = evidenceService.gather(id);
        return aiService.explain(evidence, level);
    }
}
