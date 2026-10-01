package com.anomaly.platform.ai;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.chat.client.ChatClient;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * AI-1: the incident assistant is concise by default and detailed only on
 * request. Added alongside (not into) IncidentAiServiceTest so that suite -
 * grounding, injection hardening, provider failure - stays exactly as it was.
 */
@ExtendWith(MockitoExtension.class)
class IncidentAiConciseModeTest {

    @Mock
    private ChatClient.Builder builder;

    @Mock
    private ChatClient chatClient;

    @Mock
    private ChatClient.ChatClientRequestSpec requestSpec;

    @Mock
    private ChatClient.CallResponseSpec callResponseSpec;

    private IncidentAiService service;

    @BeforeEach
    void setUp() {
        when(builder.defaultSystem(any(String.class))).thenReturn(builder);
        when(builder.build()).thenReturn(chatClient);
        service = new IncidentAiService(builder, "gpt-4o-mini-test");
    }

    private void stubCall(String content) {
        when(chatClient.prompt()).thenReturn(requestSpec);
        when(requestSpec.user(any(String.class))).thenReturn(requestSpec);
        when(requestSpec.call()).thenReturn(callResponseSpec);
        when(callResponseSpec.content()).thenReturn(content);
    }

    private String capturedPrompt() {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(requestSpec).user(captor.capture());
        return captor.getValue();
    }

    private IncidentEvidence evidence() {
        AlertEvidence alert = new AlertEvidence(
                "alert-1", "EV-1", "LOGIN", OffsetDateTime.parse("2026-09-18T16:10:00Z"),
                "KNOWN_ANOMALY", "CRITICAL", "OPEN",
                BigDecimal.valueOf(1.0), BigDecimal.valueOf(0.996), BigDecimal.valueOf(1.0),
                "v2-ml-ensemble", List.of("unseen device fingerprint"),
                "device_spoofing", "Risk 100.0 - likely device spoofing.",
                OffsetDateTime.parse("2026-09-18T16:10:01Z")
        );
        return new IncidentEvidence(
                UUID.randomUUID().toString(), "U0001:LOGIN", "U0001", "OPEN", "summary",
                OffsetDateTime.parse("2026-09-18T16:10:01Z"), OffsetDateTime.parse("2026-09-18T16:10:01Z"),
                null, List.of(alert)
        );
    }

    // -------------------------------------------------------------- incident summary (explanation)

    @Test
    void summary_defaultsToThreeToFiveShortBullets() {

        stubCall("- one\n- two\n- three");

        service.explain(evidence());

        assertThat(capturedPrompt())
                .contains("3 to 5 short bullet points")
                .contains("what happened, the")
                .contains("strongest evidence")
                .contains("current situation")
                .contains("Likely: ")
                .doesNotContain("headed");
    }

    @Test
    void summary_detailedIsOptIn_withObservedModelAssessmentUnknownSections() {

        stubCall("ok");

        service.explain(evidence(), AiDetail.DETAILED);

        assertThat(capturedPrompt())
                .contains("detailed analysis")
                .contains("\"Observed\"")
                .contains("\"Model-derived\"")
                .contains("\"Assessment\"")
                .contains("\"Unknown\"")
                .doesNotContain("3 to 5 short bullet points");
    }

    @Test
    void summary_stillKeepsTheApiShape_andKind() {

        stubCall("- a");

        IncidentAiResponse response = service.explain(evidence());

        assertThat(response.kind()).isEqualTo("EXPLANATION");
        assertThat(response.model()).isEqualTo("gpt-4o-mini-test");
        assertThat(response.content()).isEqualTo("- a");
    }

    // -------------------------------------------------------------- evidence summary

    @Test
    void evidenceSummary_defaultsToConciseFactsOnlyBullets() {

        stubCall("ok");

        service.summarizeEvidence(evidence());

        assertThat(capturedPrompt())
                .contains("3 to 5 short")
                .contains("State facts only");
    }

    @Test
    void evidenceSummary_detailedIsOptIn() {

        stubCall("ok");

        service.summarizeEvidence(evidence(), AiDetail.DETAILED);

        assertThat(capturedPrompt())
                .contains("about 250 words or fewer")
                .doesNotContain("3 to 5 short");
    }

    // -------------------------------------------------------------- investigation guidance

    @Test
    void guidance_defaultsToTwoToFourAdvisoryRecommendations() {

        stubCall("1. Verify the device.");

        IncidentAiResponse response = service.recommendInvestigation(evidence());

        assertThat(response.kind()).isEqualTo("INVESTIGATION_RECOMMENDATIONS");

        assertThat(capturedPrompt())
                .contains("2 to 4 numbered investigation recommendations")
                .contains("ADVISORY")
                .contains("never word them as though any action has")
                .contains("do not recommend destructive, irreversible or")
                .contains("Give recommendations only");
    }

    @Test
    void guidance_detailedIsOptIn_andStillAdvisoryOnly() {

        stubCall("ok");

        service.recommendInvestigation(evidence(), AiDetail.DETAILED);

        assertThat(capturedPrompt())
                .contains("about 250 words or fewer")
                .contains("ADVISORY ONLY")
                .contains("recommend destructive, irreversible or automated remediation")
                .doesNotContain("2 to 4 numbered");
    }

    @Test
    void systemPrompt_forbidsClaimingActionsWereTaken_andDestructiveRecommendations() {

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(builder).defaultSystem(captor.capture());

        assertThat(captor.getValue())
                .contains("Never state that an action")
                .contains("never")
                .contains("Never recommend irreversible or automated actions")
                .contains("never word any action as already done");
    }

    // -------------------------------------------------------------- failure handling

    @Test
    void emptyProviderResponse_isTreatedAsUnavailable() {

        stubCall("");

        assertThatThrownBy(() -> service.explain(evidence()))
                .isInstanceOf(AiProviderUnavailableException.class);
    }
}
