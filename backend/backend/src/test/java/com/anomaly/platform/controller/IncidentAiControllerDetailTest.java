package com.anomaly.platform.controller;

import com.anomaly.platform.ai.AiDetail;
import com.anomaly.platform.ai.IncidentAiResponse;
import com.anomaly.platform.ai.IncidentAiService;
import com.anomaly.platform.ai.IncidentEvidence;
import com.anomaly.platform.ai.IncidentEvidenceService;
import com.anomaly.platform.config.SecurityConfig;
import com.anomaly.platform.config.SecurityUsersProperties;
import com.anomaly.platform.security.RestSecurityErrorHandler;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * AI-1: the optional `detail` parameter on the existing incident AI
 * endpoints. Kept separate from IncidentAiControllerTest so that suite (auth,
 * 404, 503 contract) still runs untouched. The default - no parameter - must
 * keep calling the original single-argument service methods.
 */
@WebMvcTest(controllers = IncidentAiController.class)
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class IncidentAiControllerDetailTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private IncidentEvidenceService evidenceService;

    @MockBean
    private IncidentAiService aiService;

    private RequestPostProcessor asAnalyst() {
        return httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword());
    }

    private IncidentEvidence evidence(UUID id) {
        return new IncidentEvidence(
                id.toString(), "U0001:LOGIN", "U0001", "OPEN", "summary",
                OffsetDateTime.now(), OffsetDateTime.now(), null, List.of()
        );
    }

    private IncidentAiResponse response(UUID id, String kind) {
        return new IncidentAiResponse(id, kind, "generated text", "gpt-4o-mini", OffsetDateTime.now());
    }

    @Test
    void noDetailParameter_usesTheOriginalConciseCall_andKeepsTheResponseShape() throws Exception {

        UUID id = UUID.randomUUID();
        IncidentEvidence evidence = evidence(id);
        when(evidenceService.gather(id)).thenReturn(evidence);
        when(aiService.explain(evidence)).thenReturn(response(id, "EXPLANATION"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").value(id.toString()))
                .andExpect(jsonPath("$.kind").value("EXPLANATION"))
                .andExpect(jsonPath("$.content").value("generated text"))
                .andExpect(jsonPath("$.length()").value(5));

        verify(aiService, never()).explain(any(IncidentEvidence.class), any(AiDetail.class));
    }

    @Test
    void detailedExplanation_isOptIn() throws Exception {

        UUID id = UUID.randomUUID();
        IncidentEvidence evidence = evidence(id);
        when(evidenceService.gather(id)).thenReturn(evidence);
        when(aiService.explain(evidence, AiDetail.DETAILED)).thenReturn(response(id, "EXPLANATION"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation?detail=detailed", id).with(asAnalyst()))
                .andExpect(status().isOk());

        verify(aiService).explain(evidence, AiDetail.DETAILED);
    }

    @Test
    void detailedEvidenceSummary_isOptIn() throws Exception {

        UUID id = UUID.randomUUID();
        IncidentEvidence evidence = evidence(id);
        when(evidenceService.gather(id)).thenReturn(evidence);
        when(aiService.summarizeEvidence(evidence, AiDetail.DETAILED)).thenReturn(response(id, "EVIDENCE_SUMMARY"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/evidence-summary?detail=detailed", id).with(asAnalyst()))
                .andExpect(status().isOk());

        verify(aiService).summarizeEvidence(evidence, AiDetail.DETAILED);
    }

    @Test
    void detailedInvestigation_isOptIn_andExplicitConciseIsTheDefaultCall() throws Exception {

        UUID id = UUID.randomUUID();
        IncidentEvidence evidence = evidence(id);
        when(evidenceService.gather(id)).thenReturn(evidence);
        when(aiService.recommendInvestigation(evidence, AiDetail.DETAILED))
                .thenReturn(response(id, "INVESTIGATION_RECOMMENDATIONS"));
        when(aiService.recommendInvestigation(evidence))
                .thenReturn(response(id, "INVESTIGATION_RECOMMENDATIONS"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/investigation?detail=detailed", id).with(asAnalyst()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/incidents/{id}/ai/investigation?detail=concise", id).with(asAnalyst()))
                .andExpect(status().isOk());

        verify(aiService).recommendInvestigation(evidence, AiDetail.DETAILED);
        verify(aiService).recommendInvestigation(evidence);
    }

    @Test
    void unknownDetailValue_isABadRequest() throws Exception {

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation?detail=novel", UUID.randomUUID()).with(asAnalyst()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

        verifyNoInteractions(aiService);
    }
}
