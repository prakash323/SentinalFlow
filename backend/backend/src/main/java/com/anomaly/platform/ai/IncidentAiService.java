package com.anomaly.platform.ai;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/*
 * ================================================================
 * ANALYST-ASSISTANCE LAYER (Phase 6) - ARCHITECTURE RULE
 * ================================================================
 *
 * This service ONLY explains, summarizes, and suggests investigation
 * steps in plain English, over evidence someone else already computed.
 * It has NO dependency on any repository, the ML client, PredictionService,
 * AlertService, or IncidentService's mutation methods - it structurally
 * cannot recalculate a score, change a decision, set severity, or mutate
 * alert/incident state, because it has no path to do any of those things,
 * not merely because it chooses not to. The one input type it accepts
 * (IncidentEvidence) is an immutable snapshot assembled by
 * IncidentEvidenceService.
 */
@Service
public class IncidentAiService {

    /*
     * Concise is the default for every operation: a handful of short lines
     * that lead with the strongest evidence. The detailed variants are only
     * used when the analyst explicitly asks for them (AiDetail.DETAILED).
     * The grounding rules that bind both come from AiPromptSupport.SYSTEM_PROMPT.
     */
    private static final String EXPLANATION_CONCISE = """
            Write a concise incident summary as 3 to 5 short bullet points
            (start each line with "- "), each a single line of at most about
            20 words. Cover only the most useful points: what happened, the
            strongest evidence, related activity across the linked alerts, and
            the current situation (status). Do not restate every field and do
            not write an introduction, headings or a conclusion. If something an
            analyst would expect is not in the evidence, say it is unknown.
            Start any bullet that is your own inference (rather than an observed
            or model-reported fact) with "Likely: ".
            """;

    private static final String EXPLANATION_DETAILED = """
            Write a detailed analysis of about 250 words or fewer, using these
            headed sections in this order, with short bullets under each:
            "Observed" (what happened, as present in the evidence),
            "Model-derived" (what the ML model and policy reported: scores,
            decision, severity, attack type, reasons, and why it was considered
            suspicious), "Assessment" (your own reasoning, worded tentatively) and
            "Unknown" (what the available evidence does not cover). Cite the
            specific evidence behind each claim.
            """;

    private static final String EVIDENCE_SUMMARY_CONCISE = """
            Summarize the evidence associated with this incident as 3 to 5 short
            bullet points (start each line with "- "), one line each, grouping
            related facts (entity, timing, strongest ML findings, alert history).
            State facts only - no interpretation, no recommendations, no
            introduction.
            """;

    private static final String EVIDENCE_SUMMARY_DETAILED = """
            Produce an analyst-readable summary of the evidence associated with
            this incident, about 250 words or fewer. Group related facts under
            short headings (entity, timing, ML findings, alert history). Only
            summarize what is present in the evidence above - do not add
            interpretation or recommendations here.
            """;

    private static final String INVESTIGATION_CONCISE = """
            Give 2 to 4 numbered investigation recommendations ("1.", "2.", ...),
            each a single sentence that names the check to perform and the
            specific evidence that motivates it. Recommendations are ADVISORY
            ONLY for a human analyst: never word them as though any action has
            been taken, and do not recommend destructive, irreversible or
            automated remediation. Give recommendations only - no summary of the
            incident and no introduction.
            """;

    private static final String INVESTIGATION_DETAILED = """
            Based only on the evidence above, list concrete next investigation
            steps a SOC analyst should take, about 250 words or fewer. Number each
            recommendation and briefly justify it by referencing the specific
            evidence that motivates it. Recommendations are ADVISORY ONLY: do not
            phrase them as though any action has already been taken, and do not
            recommend destructive, irreversible or automated remediation.
            """;

    private final ChatClient chatClient;
    private final String modelName;

    public IncidentAiService(
            ChatClient.Builder chatClientBuilder,
            @Value("${spring.ai.openai.chat.options.model:gpt-4o-mini}") String modelName
    ) {
        this.chatClient = chatClientBuilder
                .defaultSystem(AiPromptSupport.SYSTEM_PROMPT)
                .build();
        this.modelName = modelName;
    }

    public IncidentAiResponse explain(IncidentEvidence evidence) {
        return explain(evidence, AiDetail.CONCISE);
    }

    public IncidentAiResponse explain(IncidentEvidence evidence, AiDetail detail) {
        return generate(evidence, "EXPLANATION", detail, EXPLANATION_CONCISE, EXPLANATION_DETAILED);
    }

    public IncidentAiResponse summarizeEvidence(IncidentEvidence evidence) {
        return summarizeEvidence(evidence, AiDetail.CONCISE);
    }

    public IncidentAiResponse summarizeEvidence(IncidentEvidence evidence, AiDetail detail) {
        return generate(evidence, "EVIDENCE_SUMMARY", detail, EVIDENCE_SUMMARY_CONCISE, EVIDENCE_SUMMARY_DETAILED);
    }

    public IncidentAiResponse recommendInvestigation(IncidentEvidence evidence) {
        return recommendInvestigation(evidence, AiDetail.CONCISE);
    }

    public IncidentAiResponse recommendInvestigation(IncidentEvidence evidence, AiDetail detail) {
        return generate(evidence, "INVESTIGATION_RECOMMENDATIONS", detail, INVESTIGATION_CONCISE, INVESTIGATION_DETAILED);
    }

    private IncidentAiResponse generate(
            IncidentEvidence evidence,
            String kind,
            AiDetail detail,
            String conciseInstruction,
            String detailedInstruction
    ) {

        String instruction = detail == AiDetail.DETAILED ? detailedInstruction : conciseInstruction;

        String userPrompt = buildEvidenceBlock(evidence) + "\n\n" + instruction;

        String content = AiPromptSupport.callModel(
                chatClient,
                userPrompt,
                "incident:" + evidence.incidentId(),
                kind
        );

        return new IncidentAiResponse(
                UUID.fromString(evidence.incidentId()),
                kind,
                content,
                modelName,
                OffsetDateTime.now()
        );
    }

    /*
     * ============================================================
     * EVIDENCE -> PROMPT TEXT
     * ============================================================
     *
     * The exact same block is used for all three operations - only the
     * task instruction appended after it differs. Every value here is
     * read directly off IncidentEvidence/AlertEvidence with no
     * transformation beyond sanitization/formatting, so nothing is added
     * that wasn't already computed elsewhere in SentinelFlow, and nothing
     * legitimate is dropped.
     *
     * Everything that ultimately traces back to attacker-controllable
     * input - eventType, the auto-generated incident summary, ML
     * attackType/reason, and alert factors, all of which flow from the
     * PUBLIC, unauthenticated POST /api/v1/events endpoint - is treated as
     * untrusted: sanitized (sanitizeField) and wrapped in explicit
     * <<<EVIDENCE>>> / <<<END EVIDENCE>>> delimiters that SYSTEM_PROMPT
     * rule 7 tells the model never to treat as instructions.
     */
    private String buildEvidenceBlock(IncidentEvidence evidence) {

        StringBuilder sb = new StringBuilder();

        sb.append("<<<EVIDENCE>>>\n");

        sb.append("INCIDENT\n");
        sb.append("  id: ").append(AiPromptSupport.sanitizeField(evidence.incidentId())).append('\n');
        sb.append("  key: ").append(AiPromptSupport.sanitizeField(evidence.incidentKey())).append('\n');
        sb.append("  entity: ").append(AiPromptSupport.sanitizeField(evidence.entityId())).append('\n');
        sb.append("  status: ").append(AiPromptSupport.sanitizeField(evidence.incidentStatus())).append('\n');
        sb.append("  summary: ").append(AiPromptSupport.sanitizeField(evidence.summary())).append('\n');
        sb.append("  created_at: ").append(AiPromptSupport.sanitizeField(evidence.createdAt())).append('\n');
        sb.append("  updated_at: ").append(AiPromptSupport.sanitizeField(evidence.updatedAt())).append('\n');
        sb.append("  closed_at: ")
                .append(evidence.closedAt() == null ? "not closed" : AiPromptSupport.sanitizeField(evidence.closedAt()))
                .append('\n');

        List<AlertEvidence> alerts = evidence.alerts();

        sb.append("\nLINKED ALERTS (").append(alerts.size()).append(")\n");

        if (alerts.isEmpty()) {
            sb.append("  (no alerts are linked to this incident)\n");
        }

        int index = 1;

        for (AlertEvidence alert : alerts) {

            sb.append("  [").append(index++).append("]\n");
            sb.append("      alert_id: ").append(AiPromptSupport.sanitizeField(alert.alertId())).append('\n');
            sb.append("      event_id: ").append(AiPromptSupport.sanitizeField(alert.eventId())).append('\n');
            sb.append("      event_type: ").append(AiPromptSupport.sanitizeField(alert.eventType())).append('\n');
            sb.append("      event_occurred_at: ").append(AiPromptSupport.sanitizeField(alert.eventOccurredAt())).append('\n');
            sb.append("      decision: ").append(AiPromptSupport.sanitizeField(alert.decision())).append('\n');
            sb.append("      severity: ").append(AiPromptSupport.sanitizeField(alert.severity())).append('\n');
            sb.append("      status: ").append(AiPromptSupport.sanitizeField(alert.status())).append('\n');
            sb.append("      anomaly_score: ").append(AiPromptSupport.sanitizeField(alert.anomalyScore())).append('\n');
            sb.append("      confidence: ").append(AiPromptSupport.sanitizeField(alert.confidence())).append('\n');
            sb.append("      fused_score: ").append(AiPromptSupport.sanitizeField(alert.fusedScore())).append('\n');
            sb.append("      policy_version: ").append(AiPromptSupport.sanitizeField(alert.policyVersion())).append('\n');
            sb.append("      attack_type: ").append(AiPromptSupport.sanitizeField(alert.attackType())).append('\n');
            sb.append("      ml_reason: ").append(AiPromptSupport.sanitizeField(alert.mlReason())).append('\n');
            sb.append("      factors: ")
                    .append(AiPromptSupport.factors(alert.factors()))
                    .append('\n');
            sb.append("      created_at: ").append(AiPromptSupport.sanitizeField(alert.createdAt())).append('\n');
        }

        sb.append("<<<END EVIDENCE>>>\n");

        return sb.toString();
    }
}
