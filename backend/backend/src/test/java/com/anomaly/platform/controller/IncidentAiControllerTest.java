package com.anomaly.platform.controller;

import com.anomaly.platform.ai.AiProviderUnavailableException;
import com.anomaly.platform.ai.IncidentAiResponse;
import com.anomaly.platform.ai.IncidentAiService;
import com.anomaly.platform.ai.IncidentEvidence;
import com.anomaly.platform.ai.IncidentEvidenceService;
import com.anomaly.platform.config.SecurityConfig;
import com.anomaly.platform.config.SecurityUsersProperties;
import com.anomaly.platform.exception.NotFoundException;
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
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * Phase 6: proves the AI endpoints are wired into the real Phase 5
 * SecurityConfig filter chain (not a re-description of it), and that
 * missing-incident / AI-provider-failure map to the right HTTP status
 * using the application's own ErrorResponse shape.
 */
@WebMvcTest(controllers = IncidentAiController.class)
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class IncidentAiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private IncidentEvidenceService evidenceService;

    @MockBean
    private IncidentAiService aiService;

    private RequestPostProcessor asAdmin() {
        return httpBasic(users.getAdmin().getUsername(), users.getAdmin().getPassword());
    }

    private RequestPostProcessor asAnalyst() {
        return httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword());
    }

    private IncidentEvidence sampleEvidence(UUID id) {
        return new IncidentEvidence(
                id.toString(), "U0001:LOGIN", "U0001", "OPEN", "summary",
                OffsetDateTime.now(), OffsetDateTime.now(), null, List.of()
        );
    }

    private IncidentAiResponse sampleResponse(UUID id, String kind) {
        return new IncidentAiResponse(id, kind, "generated text", "gpt-4o-mini", OffsetDateTime.now());
    }

    @Test
    void explanation_withoutCredentials_isUnauthorized() throws Exception {

        UUID id = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation", id))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void explanation_asAnalyst_isAllowed() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(sampleEvidence(id));
        when(aiService.explain(any())).thenReturn(sampleResponse(id, "EXPLANATION"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("EXPLANATION"))
                .andExpect(jsonPath("$.content").value("generated text"));
    }

    @Test
    void explanation_asAdmin_isAllowed() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(sampleEvidence(id));
        when(aiService.explain(any())).thenReturn(sampleResponse(id, "EXPLANATION"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation", id).with(asAdmin()))
                .andExpect(status().isOk());
    }

    @Test
    void evidenceSummary_asAnalyst_isAllowed() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(sampleEvidence(id));
        when(aiService.summarizeEvidence(any())).thenReturn(sampleResponse(id, "EVIDENCE_SUMMARY"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/evidence-summary", id).with(asAnalyst()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("EVIDENCE_SUMMARY"));
    }

    @Test
    void investigation_asAnalyst_isAllowed() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(sampleEvidence(id));
        when(aiService.recommendInvestigation(any())).thenReturn(sampleResponse(id, "INVESTIGATION_RECOMMENDATIONS"));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/investigation", id).with(asAnalyst()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("INVESTIGATION_RECOMMENDATIONS"));
    }

    @Test
    void explanation_nonexistentIncident_returnsNotFound() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenThrow(new NotFoundException("Incident not found: " + id));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));

        org.mockito.Mockito.verifyNoInteractions(aiService);
    }

    @Test
    void explanation_aiProviderFailure_returnsControlledServiceUnavailable() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(sampleEvidence(id));
        when(aiService.explain(any()))
                .thenThrow(new AiProviderUnavailableException("boom", new RuntimeException("connection refused")));

        mockMvc.perform(post("/api/v1/incidents/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("AI_PROVIDER_UNAVAILABLE"))
                .andExpect(jsonPath("$.message").value(
                        "The AI analyst-assistance service is currently unavailable. Please try again later."
                ));
    }
}
