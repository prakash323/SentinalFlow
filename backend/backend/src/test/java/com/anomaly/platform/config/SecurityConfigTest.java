package com.anomaly.platform.config;

import com.anomaly.platform.controller.AlertController;
import com.anomaly.platform.controller.AuditLogController;
import com.anomaly.platform.controller.DashboardController;
import com.anomaly.platform.controller.EntityController;
import com.anomaly.platform.controller.EventController;
import com.anomaly.platform.controller.IncidentController;
import com.anomaly.platform.controller.PredictionController;
import com.anomaly.platform.controller.ReplayRunController;
import com.anomaly.platform.security.RestSecurityErrorHandler;
import com.anomaly.platform.service.AlertService;
import com.anomaly.platform.service.AuditLogService;
import com.anomaly.platform.service.DashboardService;
import com.anomaly.platform.service.EntityService;
import com.anomaly.platform.service.EventService;
import com.anomaly.platform.service.IncidentService;
import com.anomaly.platform.service.PredictionService;
import com.anomaly.platform.service.ReplayRunService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * Phase 5 focused tests. These run through MockMvc against the REAL
 * SecurityConfig filter chain and the real controllers (with only their
 * services mocked) - this proves the actual bean-defined authorization
 * rules behave as intended, rather than re-describing them in a separate
 * test-only copy that could silently drift from the real config.
 *
 * Where a test only needs to prove "security let this request through"
 * (as opposed to testing the endpoint's business logic, which is covered
 * elsewhere), it asserts the response is neither 401 nor 403 rather than
 * a specific success status - a 400 from bean validation on an empty body
 * is an equally valid proof that the request reached the controller.
 */
@WebMvcTest(controllers = {
        com.anomaly.platform.controller.HealthController.class,
        EventController.class,
        EntityController.class,
        AlertController.class,
        IncidentController.class,
        ReplayRunController.class,
        AuditLogController.class,
        PredictionController.class,
        DashboardController.class
})
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private EventService eventService;

    @MockBean
    private EntityService entityService;

    @MockBean
    private AlertService alertService;

    @MockBean
    private IncidentService incidentService;

    @MockBean
    private ReplayRunService replayRunService;

    @MockBean
    private AuditLogService auditLogService;

    @MockBean
    private PredictionService predictionService;

    @MockBean
    private DashboardService dashboardService;

    private RequestPostProcessor asAdmin() {
        return httpBasic(users.getAdmin().getUsername(), users.getAdmin().getPassword());
    }

    private RequestPostProcessor asAnalyst() {
        return httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword());
    }

    private void assertNotBlockedBySecurity(int status) {
        assertThat(status).isNotEqualTo(401).isNotEqualTo(403);
    }

    @Test
    void health_isPublic_noAuthRequired() throws Exception {

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk());
    }

    @Test
    void createEvent_isPublic_forTheUnmodifiableSimulator() throws Exception {

        // The Python simulator posts here with no auth support at all
        // (verified in its source) - this must stay public.
        var result = mockMvc.perform(post("/api/v1/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn();

        assertNotBlockedBySecurity(result.getResponse().getStatus());
    }

    @Test
    void listEvents_withoutCredentials_isUnauthorized() throws Exception {

        mockMvc.perform(get("/api/v1/events"))
                .andExpect(status().isUnauthorized());

        org.mockito.Mockito.verifyNoInteractions(eventService);
    }

    @Test
    void listEvents_withWrongPassword_isUnauthorized() throws Exception {

        mockMvc.perform(get("/api/v1/events")
                        .with(httpBasic(users.getAnalyst().getUsername(), "not-the-real-password")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listEvents_asAnalyst_isAllowed() throws Exception {

        mockMvc.perform(get("/api/v1/events").with(asAnalyst()))
                .andExpect(status().isOk());
    }

    @Test
    void listEvents_asAdmin_isAllowed() throws Exception {

        mockMvc.perform(get("/api/v1/events").with(asAdmin()))
                .andExpect(status().isOk());
    }

    @Test
    void createEntity_asAnalyst_isForbidden() throws Exception {

        mockMvc.perform(post("/api/v1/entities").with(asAnalyst())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());

        org.mockito.Mockito.verifyNoInteractions(entityService);
    }

    @Test
    void createEntity_asAdmin_isNotBlockedBySecurity() throws Exception {

        var result = mockMvc.perform(post("/api/v1/entities").with(asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn();

        assertNotBlockedBySecurity(result.getResponse().getStatus());
    }

    @Test
    void updateAlertStatus_asAnalyst_isNotBlockedBySecurity() throws Exception {

        // Investigation actions (alert/incident status updates) are exactly
        // the day-to-day analyst work the example in the task description
        // calls out - must NOT require ADMIN.
        var result = mockMvc.perform(patch("/api/v1/alerts/{id}/status", UUID.randomUUID())
                        .with(asAnalyst())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"ACKNOWLEDGED\"}"))
                .andReturn();

        assertNotBlockedBySecurity(result.getResponse().getStatus());
    }

    @Test
    void updateIncidentStatus_asAnalyst_isNotBlockedBySecurity() throws Exception {

        var result = mockMvc.perform(patch("/api/v1/incidents/{id}/status", UUID.randomUUID())
                        .with(asAnalyst())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"INVESTIGATING\"}"))
                .andReturn();

        assertNotBlockedBySecurity(result.getResponse().getStatus());
    }

    @Test
    void triggerReplayRun_asAnalyst_isForbidden() throws Exception {

        mockMvc.perform(post("/api/v1/replay-runs").with(asAnalyst())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());

        org.mockito.Mockito.verifyNoInteractions(replayRunService);
    }

    @Test
    void triggerReplayRun_asAdmin_isNotBlockedBySecurity() throws Exception {

        var result = mockMvc.perform(post("/api/v1/replay-runs").with(asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn();

        assertNotBlockedBySecurity(result.getResponse().getStatus());
    }

    @Test
    void createPrediction_asAnalyst_isForbidden() throws Exception {

        mockMvc.perform(post("/api/v1/predictions").with(asAnalyst())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void auditLogs_asAnalyst_isForbidden() throws Exception {

        mockMvc.perform(get("/api/v1/audit-logs").with(asAnalyst()))
                .andExpect(status().isForbidden());

        org.mockito.Mockito.verifyNoInteractions(auditLogService);
    }

    @Test
    void auditLogs_asAdmin_isAllowed() throws Exception {

        mockMvc.perform(get("/api/v1/audit-logs").with(asAdmin()))
                .andExpect(status().isOk());
    }

    @Test
    void dashboard_asAnalyst_isAllowed() throws Exception {

        mockMvc.perform(get("/api/v1/dashboard/summary").with(asAnalyst()))
                .andExpect(status().isOk());
    }

    @Test
    void unauthorizedResponse_matchesApplicationErrorShape_notSpringSecurityDefault() throws Exception {

        mockMvc.perform(get("/api/v1/events"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void forbiddenResponse_matchesApplicationErrorShape_notSpringSecurityDefault() throws Exception {

        mockMvc.perform(get("/api/v1/audit-logs").with(asAnalyst()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }
}
