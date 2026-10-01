package com.anomaly.platform.security;

import com.anomaly.platform.config.CorrelationIdFilter;
import com.anomaly.platform.dto.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.List;

/*
 * Authentication/authorization failures happen inside the security filter
 * chain, before the request ever reaches a controller - GlobalExceptionHandler
 * (a @RestControllerAdvice) never sees them. This produces the exact same
 * ErrorResponse JSON shape as every other error in this API instead of
 * Spring Security's default plain-text/empty body, and never includes a
 * stack trace or any internal detail.
 */
@Component
public class RestSecurityErrorHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public RestSecurityErrorHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {

        write(
                response,
                HttpStatus.UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication is required to access this resource"
        );
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException
    ) throws IOException {

        write(
                response,
                HttpStatus.FORBIDDEN,
                "FORBIDDEN",
                "You do not have permission to access this resource"
        );
    }

    private void write(
            HttpServletResponse response,
            HttpStatus status,
            String code,
            String message
    ) throws IOException {

        String requestId = MDC.get(CorrelationIdFilter.HEADER);

        ErrorResponse body = new ErrorResponse(
                code,
                message,
                List.of(),
                (requestId == null || requestId.isBlank()) ? null : requestId,
                OffsetDateTime.now()
        );

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
