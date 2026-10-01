package com.anomaly.platform.config;

import com.anomaly.platform.security.RestSecurityErrorHandler;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/*
 * ================================================================
 * PHASE 5 - SECURITY LAYER
 * ================================================================
 *
 * Design: HTTP Basic auth over a stateless filter chain, two in-memory
 * roles (ADMIN, ANALYST). No OAuth2/Keycloak - not warranted for this
 * project's current size, and the phase instructions explicitly say not
 * to add one unless genuinely required.
 *
 * Endpoint tiers (least-privilege, based on what each endpoint actually
 * does - see the Phase 5 report for the full reasoning):
 *
 *   PUBLIC
 *     GET  /api/v1/health                    - liveness check
 *     GET  /actuator/health                  - liveness check
 *     POST /api/v1/events                    - the Python simulator posts
 *                                               here with NO auth support
 *                                               at all (verified in its
 *                                               source); it cannot be
 *                                               modified this phase, so
 *                                               this stays public. See
 *                                               "remaining risks" in the
 *                                               report.
 *
 *   ADMIN only (system setup / administrative / operational-trigger
 *   actions - not routine analyst investigation work)
 *     POST /api/v1/entities                  - defines new monitored entities
 *     POST /api/v1/predictions               - manual/direct prediction
 *                                               insertion, bypasses the
 *                                               real ML pipeline entirely
 *     /api/v1/replay-runs/**                 - triggers bulk reprocessing
 *     GET  /api/v1/audit-logs                - system-wide audit trail
 *     /actuator/** (except health)           - info/metrics
 *     swagger-ui / v3/api-docs               - API surface disclosure
 *
 *   ANALYST or ADMIN (everything else under /api/v1/**)
 *     read events/predictions/alerts/incidents/dashboard, GET a single
 *     entity, and the two investigation actions (PATCH alert/incident
 *     status) - exactly what a SOC analyst does day to day.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SecurityUsersProperties.class)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(
            SecurityUsersProperties props,
            PasswordEncoder encoder
    ) {

        UserDetails admin = User.withUsername(props.getAdmin().getUsername())
                .password(encoder.encode(props.getAdmin().getPassword()))
                .roles("ADMIN", "ANALYST")
                .build();

        UserDetails analyst = User.withUsername(props.getAnalyst().getUsername())
                .password(encoder.encode(props.getAnalyst().getPassword()))
                .roles("ANALYST")
                .build();

        return new InMemoryUserDetailsManager(admin, analyst);
    }

    /*
     * CORS for a separately hosted frontend. Local development goes
     * through the Vite proxy and never needs this. Applied inside the
     * security chain (http.cors below) so pre-flight OPTIONS requests are
     * answered before authentication is demanded - a browser never sends
     * the Authorization header on a pre-flight.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origins:}") String allowedOrigins
    ) {

        List<String> origins = Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(o -> !o.isEmpty())
                .toList();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Correlation-Id"));
        config.setExposedHeaders(List.of("X-Correlation-Id"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            RestSecurityErrorHandler errorHandler
    ) throws Exception {

        http
                .cors(cors -> { })
                /*
                 * Stateless HTTP Basic API, no browser session/cookie is
                 * ever issued, so there is no ambient credential for a
                 * malicious site to ride on - CSRF protection (designed
                 * for cookie-based session auth) does not apply here.
                 */
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth

                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/health").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/events").permitAll()

                        .requestMatchers(HttpMethod.POST, "/api/v1/entities").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/predictions").hasRole("ADMIN")
                        .requestMatchers("/api/v1/replay-runs/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/audit-logs").hasRole("ADMIN")
                        .requestMatchers("/actuator/**").hasRole("ADMIN")
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**"
                        ).hasRole("ADMIN")

                        .requestMatchers("/api/v1/**").hasAnyRole("ADMIN", "ANALYST")

                        .anyRequest().denyAll()
                )
                .httpBasic(basic -> basic.authenticationEntryPoint(errorHandler))
                .exceptionHandling(ex -> ex.accessDeniedHandler(errorHandler));

        return http.build();
    }
}
