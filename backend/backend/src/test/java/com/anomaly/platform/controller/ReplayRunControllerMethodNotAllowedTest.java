package com.anomaly.platform.controller;

import com.anomaly.platform.config.SecurityConfig;
import com.anomaly.platform.config.SecurityUsersProperties;
import com.anomaly.platform.security.RestSecurityErrorHandler;
import com.anomaly.platform.service.ReplayRunService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * Phase 7A follow-up: an unsupported HTTP method on a mapped path used to
 * fall through GlobalExceptionHandler's generic Exception.class handler and
 * come back as a 500 INTERNAL_ERROR (originally found via a bare GET before
 * the list endpoint existed). ReplayRunController now serves GET (list),
 * POST (create) and GET/{runKey}; DELETE is deliberately unsupported (replay
 * runs are an append-only history), so this proves it maps to a proper 405.
 */
@WebMvcTest(controllers = ReplayRunController.class)
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class ReplayRunControllerMethodNotAllowedTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private ReplayRunService replayRunService;

    @Test
    void deleteOnReplayRuns_returnsMethodNotAllowed_notInternalError() throws Exception {

        mockMvc.perform(
                        delete("/api/v1/replay-runs")
                                .with(httpBasic(users.getAdmin().getUsername(), users.getAdmin().getPassword()))
                )
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.code").value("METHOD_NOT_ALLOWED"));
    }
}
