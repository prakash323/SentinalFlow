package com.anomaly.platform.controller;

import com.anomaly.platform.ai.AiDetail;
import com.anomaly.platform.ai.AiProviderUnavailableException;
import com.anomaly.platform.ai.AlertAiEvidence;
import com.anomaly.platform.ai.AlertAiEvidenceService;
import com.anomaly.platform.ai.AlertAiResponse;
import com.anomaly.platform.ai.AlertAiService;
import com.anomaly.platform.ai.AlertEvidence;
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

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * AI-1: the alert AI endpoint is wired into the real SecurityConfig filter
 * chain, keeps the incident endpoints' error contract (404 / controlled 503),
 * honours the optional `detail` parameter and rejects unknown values.
 */
@WebMvcTest(controllers = AlertAiController.class)
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class AlertAiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private AlertAiEvidenceService evidenceService;

    @MockBean
    private AlertAiService aiService;

    private RequestPostProcessor asAdmin() {
        return httpBasic(users.getAdmin().getUsername(), users.getAdmin().getPassword());
    }

    private RequestPostProcessor asAnalyst() {
        return httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword());
    }

    private AlertAiEvidence evidence(UUID id) {
        return new AlertAiEvidence(
                new AlertEvidence(
                        id.toString(), "EV-1", "LOGIN", OffsetDateTime.now(),
                        "KNOWN_ANOMALY", "CRITICAL", "OPEN",
                        BigDecimal.ONE, BigDecimal.ONE, BigDecimal.ONE,
                        "v2-ml-ensemble", List.of(), "device_spoofing", "reason", OffsetDateTime.now()
                ),
                "U0001", "web-portal", null, null, null, null, null
        );
    }

    private AlertAiResponse response(UUID id) {
        return new AlertAiResponse(id, "EXPLANATION", "generated text", "gpt-4o-mini", OffsetDateTime.now());
    }

    @Test
    void explanation_withoutCredentials_isUnauthorized() throws Exception {

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation", UUID.randomUUID()))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(evidenceService, aiService);
    }

    @Test
    void explanation_asAnalyst_returnsTheExactResponseShape() throws Exception {

        UUID id = UUID.randomUUID();
        AlertAiEvidence evidence = evidence(id);
        when(evidenceService.gather(id)).thenReturn(evidence);
        when(aiService.explain(any(AlertAiEvidence.class), any(AiDetail.class))).thenReturn(response(id));

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alertId").value(id.toString()))
                .andExpect(jsonPath("$.kind").value("EXPLANATION"))
                .andExpect(jsonPath("$.content").value("generated text"))
                .andExpect(jsonPath("$.model").value("gpt-4o-mini"))
                .andExpect(jsonPath("$.generatedAt").exists())
                // exactly these five fields: nothing that looks like a score/decision/severity/status
                .andExpect(jsonPath("$.length()").value(5));

        // no `detail` => the concise default
        verify(aiService).explain(evidence, AiDetail.CONCISE);
    }

    @Test
    void explanation_asAdmin_isAllowed() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(evidence(id));
        when(aiService.explain(any(AlertAiEvidence.class), any(AiDetail.class))).thenReturn(response(id));

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation", id).with(asAdmin()))
                .andExpect(status().isOk());
    }

    @Test
    void explanation_detailedIsPassedThroughOnlyWhenAskedFor() throws Exception {

        UUID id = UUID.randomUUID();
        AlertAiEvidence evidence = evidence(id);
        when(evidenceService.gather(id)).thenReturn(evidence);
        when(aiService.explain(any(AlertAiEvidence.class), any(AiDetail.class))).thenReturn(response(id));

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation?detail=detailed", id).with(asAnalyst()))
                .andExpect(status().isOk());

        verify(aiService).explain(evidence, AiDetail.DETAILED);
    }

    @Test
    void explanation_unknownDetailValue_isABadRequest_andNothingIsGenerated() throws Exception {

        UUID id = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation?detail=everything", id).with(asAnalyst()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

        verifyNoInteractions(aiService);
    }

    @Test
    void explanation_malformedId_isABadRequest() throws Exception {

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation", "not-a-uuid").with(asAnalyst()))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(aiService);
    }

    @Test
    void explanation_nonexistentAlert_returnsNotFound_withoutCallingTheModel() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenThrow(new NotFoundException("Alert not found: " + id));

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));

        verifyNoInteractions(aiService);
    }

    @Test
    void explanation_aiProviderFailure_returnsTheFixedServiceUnavailableMessage() throws Exception {

        UUID id = UUID.randomUUID();
        when(evidenceService.gather(id)).thenReturn(evidence(id));
        when(aiService.explain(any(AlertAiEvidence.class), any(AiDetail.class)))
                .thenThrow(new AiProviderUnavailableException(
                        "boom", new RuntimeException("401 invalid api key sk-SECRET-VALUE at https://provider.internal/v1")));

        mockMvc.perform(post("/api/v1/alerts/{id}/ai/explanation", id).with(asAnalyst()))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("AI_PROVIDER_UNAVAILABLE"))
                .andExpect(jsonPath("$.message").value(
                        "The AI analyst-assistance service is currently unavailable. Please try again later."
                ))
                // the provider's own text, key and URL never reach the client
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                        .string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("sk-SECRET-VALUE"))))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                        .string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("provider.internal"))));
    }

    @Test
    void aiEndpoint_isPostOnly_soItCannotBeTriggeredByAGet() throws Exception {

        mockMvc.perform(get("/api/v1/alerts/{id}/ai/explanation", UUID.randomUUID()).with(asAnalyst()))
                .andExpect(status().isMethodNotAllowed());

        verifyNoInteractions(aiService);
    }
}
