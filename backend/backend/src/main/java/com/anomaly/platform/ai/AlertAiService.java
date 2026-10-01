package com.anomaly.platform.ai;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.UUID;

/*
 * ================================================================
 * ALERT ANALYST-ASSISTANCE (AI-1) - SAME ARCHITECTURE RULE AS INCIDENTS
 * ================================================================
 *
 * Explains, in plain English, WHY an alert fired, over evidence the ML model
 * and the alert policy already produced. Like IncidentAiService it has no
 * repository, ML client, AlertService or IncidentService dependency - its
 * constructor takes only a ChatClient.Builder and a model name - so it
 * structurally cannot change a score, decision, severity or status, and
 * cannot create or close an alert or incident. Its one input is the
 * immutable AlertAiEvidence snapshot.
 *
 * Grounding, prompt-injection protection, sanitization and provider-failure
 * handling are shared with the incident assistant through AiPromptSupport.
 */
@Service
public class AlertAiService {

    /*
     * Default: 1-3 sentences that name only the strongest evidence.
     */
    private static final String EXPLANATION_CONCISE = """
            In 1 to 3 sentences of plain prose (no bullets, no headings, no
            introduction), explain why this alert fired. Use only the strongest
            evidence: lead with the model's attack type / reason and the top ranked
            factors, and mention scores or severity only if they add something. Do
            not list every field. Attribute model output to the model ("The model
            classified this as...") and word your own reading tentatively ("which
            may indicate..."). If the evidence does not say why the alert fired,
            say that the reason is unknown rather than guessing.
            """;

    /*
     * Opt-in ("Show detailed analysis"). Same evidence, more room.
     */
    private static final String EXPLANATION_DETAILED = """
            Explain why this alert fired in about 150 words or fewer, using these
            headed sections in this order, with short bullets under each:
            "Observed" (facts present in the evidence: entity, event, timing),
            "Model-derived" (what the ML model and alert policy reported: attack
            type, reason, ranked factors, scores, decision, severity),
            "Assessment" (your own reasoning, worded tentatively) and "Unknown"
            (what the evidence does not cover). Cite the specific evidence behind
            each claim, and include the incident context only if the alert belongs
            to one.
            """;

    private final ChatClient chatClient;
    private final String modelName;

    public AlertAiService(
            ChatClient.Builder chatClientBuilder,
            @Value("${spring.ai.openai.chat.options.model:gpt-4o-mini}") String modelName
    ) {
        this.chatClient = chatClientBuilder
                .defaultSystem(AiPromptSupport.SYSTEM_PROMPT)
                .build();
        this.modelName = modelName;
    }

    public AlertAiResponse explain(AlertAiEvidence evidence) {
        return explain(evidence, AiDetail.CONCISE);
    }

    public AlertAiResponse explain(AlertAiEvidence evidence, AiDetail detail) {

        String instruction = detail == AiDetail.DETAILED ? EXPLANATION_DETAILED : EXPLANATION_CONCISE;

        String userPrompt = buildEvidenceBlock(evidence) + "\n\n" + instruction;

        String content = AiPromptSupport.callModel(
                chatClient,
                userPrompt,
                "alert:" + evidence.alert().alertId(),
                "EXPLANATION"
        );

        return new AlertAiResponse(
                UUID.fromString(evidence.alert().alertId()),
                "EXPLANATION",
                content,
                modelName,
                OffsetDateTime.now()
        );
    }

    /*
     * Evidence -> prompt text. Same untrusted-data treatment as the incident
     * block: every value is sanitized (control characters stripped, length
     * capped, null -> "unknown") and the whole block sits between the
     * <<<EVIDENCE>>> / <<<END EVIDENCE>>> markers that SYSTEM_PROMPT rule 7
     * tells the model never to treat as instructions.
     */
    private String buildEvidenceBlock(AlertAiEvidence evidence) {

        AlertEvidence alert = evidence.alert();

        StringBuilder sb = new StringBuilder();

        sb.append("<<<EVIDENCE>>>\n");

        sb.append("ALERT\n");
        sb.append("  id: ").append(AiPromptSupport.sanitizeField(alert.alertId())).append('\n');
        sb.append("  entity: ").append(AiPromptSupport.sanitizeField(evidence.entityId())).append('\n');
        sb.append("  status: ").append(AiPromptSupport.sanitizeField(alert.status())).append('\n');
        sb.append("  decision: ").append(AiPromptSupport.sanitizeField(alert.decision())).append('\n');
        sb.append("  severity: ").append(AiPromptSupport.sanitizeField(alert.severity())).append('\n');
        sb.append("  anomaly_score: ").append(AiPromptSupport.sanitizeField(alert.anomalyScore())).append('\n');
        sb.append("  confidence: ").append(AiPromptSupport.sanitizeField(alert.confidence())).append('\n');
        sb.append("  fused_score: ").append(AiPromptSupport.sanitizeField(alert.fusedScore())).append('\n');
        sb.append("  policy_version: ").append(AiPromptSupport.sanitizeField(alert.policyVersion())).append('\n');
        sb.append("  created_at: ").append(AiPromptSupport.sanitizeField(alert.createdAt())).append('\n');

        sb.append("\nEVENT\n");
        sb.append("  event_id: ").append(AiPromptSupport.sanitizeField(alert.eventId())).append('\n');
        sb.append("  event_type: ").append(AiPromptSupport.sanitizeField(alert.eventType())).append('\n');
        sb.append("  occurred_at: ").append(AiPromptSupport.sanitizeField(alert.eventOccurredAt())).append('\n');
        sb.append("  source: ").append(AiPromptSupport.sanitizeField(evidence.eventSource())).append('\n');

        sb.append("\nML OUTPUT\n");
        sb.append("  attack_type: ").append(AiPromptSupport.sanitizeField(alert.attackType())).append('\n');
        sb.append("  ml_reason: ").append(AiPromptSupport.sanitizeField(alert.mlReason(), AiPromptSupport.MAX_REASON_LENGTH)).append('\n');
        sb.append("  ranked_factors: ").append(AiPromptSupport.factors(alert.factors())).append('\n');

        sb.append("\nINCIDENT\n");

        if (evidence.incidentId() == null) {
            sb.append("  (this alert is not linked to an incident)\n");
        } else {
            sb.append("  key: ").append(AiPromptSupport.sanitizeField(evidence.incidentKey())).append('\n');
            sb.append("  status: ").append(AiPromptSupport.sanitizeField(evidence.incidentStatus())).append('\n');
            sb.append("  summary: ").append(AiPromptSupport.sanitizeField(evidence.incidentSummary())).append('\n');
            sb.append("  linked_alerts: ").append(AiPromptSupport.sanitizeField(evidence.incidentAlertCount())).append('\n');
        }

        sb.append("<<<END EVIDENCE>>>\n");

        return sb.toString();
    }
}
