package com.anomaly.platform.controller;

import com.anomaly.platform.config.SecurityConfig;
import com.anomaly.platform.config.SecurityUsersProperties;
import com.anomaly.platform.security.RestSecurityErrorHandler;
import com.anomaly.platform.service.EventService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*
 * Client mistakes that Spring MVC itself rejects (unknown path, wrong
 * Content-Type) used to fall through
 * GlobalExceptionHandler's generic Exception.class handler and come back
 * as 500 INTERNAL_ERROR - looking like a server bug. They must keep their
 * real 4xx status, in the API's usual ErrorResponse shape.
 */
@WebMvcTest(controllers = EventController.class)
@Import({SecurityConfig.class, RestSecurityErrorHandler.class})
class FrameworkErrorMappingTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityUsersProperties users;

    @MockBean
    private EventService eventService;

    @Test
    void unknownApiPath_returnsNotFound_notInternalError() throws Exception {

        mockMvc.perform(
                        get("/api/v1/no-such-resource")
                                .with(httpBasic(users.getAnalyst().getUsername(), users.getAnalyst().getPassword()))
                )
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }

    @Test
    void wrongContentType_returnsUnsupportedMediaType_notInternalError() throws Exception {

        mockMvc.perform(
                        post("/api/v1/events")
                                .contentType(MediaType.TEXT_PLAIN)
                                .content("eventId=x")
                )
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
    }
}
