package com.anomaly.platform.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/*
 * PendingEventReconciler: re-publishes events that were stored by the REST
 * API but never reached Kafka (publish failure after commit, or a crash in
 * between). See that class for the eligibility rules.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "anomaly.reconciler")
public class ReconcilerProperties {

    private boolean enabled = true;

    /** Delay between reconciliation runs. */
    private Duration interval = Duration.ofMinutes(1);

    /**
     * Minimum age before a PENDING event is treated as unpublished. Must stay
     * well above the normal publish path (post-commit send can block up to the
     * producer's max.block.ms, then retry up to delivery.timeout.ms) and the
     * normal consumer processing time, so a merely slow event is not re-sent.
     */
    private Duration staleAfter = Duration.ofMinutes(10);

    /** Older events are left alone (needs an operator: admin replay). */
    private Duration maxAge = Duration.ofHours(24);

    /** Republish attempts per event before giving up. */
    private int maxAttempts = 6;

    /** Minimum gap between two republish attempts for the same event. */
    private Duration retryInterval = Duration.ofMinutes(10);

    /** Most events re-published in one run. */
    private int batchSize = 50;

    /** How long to wait for the broker to acknowledge one re-publish. */
    private Duration sendTimeout = Duration.ofSeconds(15);
}
