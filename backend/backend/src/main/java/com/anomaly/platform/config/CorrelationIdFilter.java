package com.anomaly.platform.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
public class CorrelationIdFilter implements Filter {

    public static final String HEADER = "X-Correlation-Id";

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain
    ) throws IOException, ServletException {

        HttpServletRequest httpRequest =
                (HttpServletRequest) request;

        HttpServletResponse httpResponse =
                (HttpServletResponse) response;

        String correlationId =
                httpRequest.getHeader(HEADER);

        if (correlationId == null
                || correlationId.isBlank()) {

            correlationId =
                    UUID.randomUUID().toString();
        }

        MDC.put(
                HEADER,
                correlationId
        );

        httpResponse.setHeader(
                HEADER,
                correlationId
        );

        try {

            chain.doFilter(
                    request,
                    response
            );

        } finally {

            MDC.remove(HEADER);
        }
    }
}