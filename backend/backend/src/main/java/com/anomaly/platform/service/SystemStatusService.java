package com.anomaly.platform.service;

import com.anomaly.platform.config.AlertPolicyProperties;
import com.anomaly.platform.dto.SystemStatusResponse;
import com.anomaly.platform.dto.SystemStatusResponse.Component;
import com.anomaly.platform.ml.MlServiceProperties;
import com.anomaly.platform.repository.EventRepository;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/*
 * Probes the platform's real dependencies (PostgreSQL, Kafka, the ML
 * service) with short timeouts, so the dashboard reports actual state
 * instead of static "Operational" labels. The three probes run in
 * parallel, so the endpoint answers in roughly the slowest probe's
 * timeout even when everything is down.
 *
 * This is deliberately separate from /api/v1/health (public liveness) and
 * Actuator readiness: it is authenticated, richer, and shaped for the UI.
 */
@Service
public class SystemStatusService {

    private static final Logger log = LoggerFactory.getLogger(SystemStatusService.class);

    private static final int PROBE_TIMEOUT_MS = 2500;

    private final JdbcTemplate jdbc;
    private final KafkaAdmin kafkaAdmin;
    private final EventRepository eventRepository;
    private final AlertPolicyProperties policy;
    private final RestClient mlHealthClient;

    public SystemStatusService(
            JdbcTemplate jdbc,
            KafkaAdmin kafkaAdmin,
            EventRepository eventRepository,
            AlertPolicyProperties policy,
            MlServiceProperties mlProps
    ) {
        this.jdbc = jdbc;
        this.kafkaAdmin = kafkaAdmin;
        this.eventRepository = eventRepository;
        this.policy = policy;

        /*
         * A dedicated short-timeout client: the scoring client tolerates
         * an 8s read timeout, which would make a status page hang.
         */
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(PROBE_TIMEOUT_MS);
        factory.setReadTimeout(PROBE_TIMEOUT_MS);

        this.mlHealthClient = RestClient.builder()
                .baseUrl(mlProps.getUrl())
                .requestFactory(factory)
                .build();
    }

    public SystemStatusResponse status() {

        CompletableFuture<Component> db = CompletableFuture.supplyAsync(this::probeDatabase);
        CompletableFuture<Component> kafka = CompletableFuture.supplyAsync(this::probeKafka);
        CompletableFuture<Component> ml = CompletableFuture.supplyAsync(this::probeMlService);

        List<Component> components = new ArrayList<>();
        components.add(new Component("Spring Boot API", "UP", 0L, "Serving requests"));
        components.add(await(db, "PostgreSQL"));
        components.add(await(kafka, "Kafka"));
        components.add(await(ml, "ML service"));

        long down = components.stream().filter(c -> !"UP".equals(c.status())).count();

        boolean dbDown = components.stream()
                .anyMatch(c -> "PostgreSQL".equals(c.name()) && !"UP".equals(c.status()));

        String overall = down == 0 ? "UP" : dbDown ? "DOWN" : "DEGRADED";

        Map<String, Long> pipeline = new LinkedHashMap<>();
        pipeline.put("PENDING", 0L);
        pipeline.put("PROCESSED", 0L);
        pipeline.put("FAILED", 0L);

        try {
            for (Object[] row : eventRepository.countGroupedByProcessingStatus()) {
                pipeline.put(String.valueOf(row[0]), ((Number) row[1]).longValue());
            }
        } catch (Exception e) {
            log.warn("Pipeline counts unavailable: {}", e.getMessage());
        }

        return new SystemStatusResponse(
                overall,
                OffsetDateTime.now(),
                components,
                pipeline,
                new SystemStatusResponse.Policy(
                        policy.getPolicyVersion(),
                        policy.getAlertThreshold(),
                        policy.getSeverity().getMedium(),
                        policy.getSeverity().getHigh(),
                        policy.getSeverity().getCritical()
                )
        );
    }

    private Component await(CompletableFuture<Component> future, String name) {

        try {
            return future.get(PROBE_TIMEOUT_MS * 2L, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            future.cancel(true);
            return new Component(name, "DOWN", null, "Probe timed out");
        }
    }

    private Component probeDatabase() {

        return timed("PostgreSQL", () -> {
            jdbc.queryForObject("SELECT 1", Integer.class);
            return "Query round-trip OK";
        });
    }

    private Component probeKafka() {

        return timed("Kafka", () -> {

            Map<String, Object> props = new java.util.HashMap<>(kafkaAdmin.getConfigurationProperties());
            props.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, PROBE_TIMEOUT_MS);
            props.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, PROBE_TIMEOUT_MS);

            try (AdminClient client = AdminClient.create(props)) {

                int nodes = client.describeCluster()
                        .nodes()
                        .get(PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                        .size();

                return nodes + (nodes == 1 ? " broker" : " brokers") + " reachable";
            }
        });
    }

    private Component probeMlService() {

        return timed("ML service", () -> {

            Map<?, ?> body = mlHealthClient.get()
                    .uri("/health")
                    .retrieve()
                    .body(Map.class);

            Object status = body == null ? null : body.get("status");

            if ("warming".equalsIgnoreCase(String.valueOf(status))) {
                throw new IllegalStateException("Model is still warming up");
            }

            if (status == null || !"ok".equalsIgnoreCase(String.valueOf(status))) {
                throw new IllegalStateException("Unexpected health response: " + body);
            }

            return "Model loaded and scoring";
        });
    }

    /*
     * Runs a probe and converts success/failure into a Component with the
     * measured latency. The failure detail is the exception's own message,
     * never a stack trace.
     */
    private Component timed(String name, ThrowingSupplier<String> probe) {

        long start = System.nanoTime();

        try {

            String detail = probe.get();

            return new Component(name, "UP", elapsedMs(start), detail);

        } catch (Exception e) {

            Throwable root = e;
            while (root.getCause() != null && root.getCause() != root) {
                root = root.getCause();
            }

            String message = root.getMessage() == null
                    ? root.getClass().getSimpleName()
                    : root.getMessage();

            log.debug("Health probe for {} failed: {}", name, message);

            return new Component(name, "DOWN", elapsedMs(start), truncate(message));
        }
    }

    private static long elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    private static String truncate(String s) {
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }
}
