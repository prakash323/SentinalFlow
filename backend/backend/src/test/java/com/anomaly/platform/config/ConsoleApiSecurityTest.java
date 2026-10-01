package com.anomaly.platform.config;

import com.anomaly.platform.controller.AuthController;
import com.anomaly.platform.controller.EntityController;
import com.anomaly.platform.controller.EventController;
import com.anomaly.platform.controller.SystemController;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.security.RestSecurityErrorHandler;
import com.anomaly.platform.service.EntityService;
import com.anomaly.platform.service.EventService;
import com.anomaly.platform.service.SystemStatusService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * Endpoints added for the operations console: /auth/me, /system/status,
 * GET /entities, GET /events/{id}/trail - plus CORS. Runs against the real
 * SecurityConfig filter chain, like SecurityConfigTest.
 */
@WebMvcTest(controllers = {
        AuthController.class,
        SystemController.class,
        EntityController.class,
        EventController.class
})
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class ConsoleApiSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private SystemStatusService systemStatusService;

    @MockBean
    private EntityService entityService;

    @MockBean
    private EventService eventService;

    @Test
    void me_requiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_reportsAnalystRolesWithoutAdmin() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me")
                        .with(httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(users.getAnalyst().getUsername()))
                .andExpect(jsonPath("$.admin").value(false))
                .andExpect(jsonPath("$.roles[0]").value("ANALYST"));
    }

    @Test
    void me_reportsAdminFlagForAdministrator() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me")
                        .with(httpBasic(users.getAdmin().getUsername(), users.getAdmin().getPassword())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.admin").value(true));
    }

    @Test
    void systemStatus_isNotPublic() throws Exception {
        mockMvc.perform(get("/api/v1/system/status"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void systemStatus_isAvailableToAnalysts() throws Exception {
        mockMvc.perform(get("/api/v1/system/status")
                        .with(httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword())))
                .andExpect(status().isOk());
    }

    @Test
    void entityList_isAvailableToAnalysts() throws Exception {
        when(entityService.list(any(), anyInt(), anyInt()))
                .thenReturn(new PageResponse<>(List.of(), 0, 20, 0, 0));

        mockMvc.perform(get("/api/v1/entities")
                        .with(httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void eventTrail_requiresAuthentication_unlikeEventIngestion() throws Exception {
        mockMvc.perform(get("/api/v1/events/EV-1/trail"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cors_preflightFromConfiguredOrigin_isAllowedWithoutCredentials() throws Exception {
        mockMvc.perform(options("/api/v1/alerts")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }

    @Test
    void cors_preflightFromUnknownOrigin_isRejected() throws Exception {
        mockMvc.perform(options("/api/v1/alerts")
                        .header("Origin", "http://evil.example")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());
    }
}
