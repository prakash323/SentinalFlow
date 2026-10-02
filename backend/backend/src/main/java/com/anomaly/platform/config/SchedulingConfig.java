package com.anomaly.platform.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/*
 * Enables @Scheduled for PendingEventReconciler (the only scheduled job).
 * Spring's default scheduler is single-threaded, so runs within one backend
 * instance never overlap; across instances the reconciler's row locks
 * (FOR UPDATE SKIP LOCKED) keep two runs from claiming the same event.
 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(ReconcilerProperties.class)
public class SchedulingConfig {
}
