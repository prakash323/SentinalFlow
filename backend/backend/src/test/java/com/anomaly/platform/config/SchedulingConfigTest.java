package com.anomaly.platform.config;

import com.anomaly.platform.kafka.EventKafkaProducer;
import com.anomaly.platform.repository.AuditLogRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.service.AuditLogService;
import com.anomaly.platform.service.PendingEventReconciler;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/*
 * Regression: application.yml once set anomaly.reconciler.interval to "1m",
 * which binds fine into ReconcilerProperties (a Duration) but is not a value
 * @Scheduled accepts (milliseconds or ISO-8601 only) - the application
 * context failed to start. Unit tests that build the reconciler directly
 * cannot see that, so this boots the real scheduling configuration against
 * the real application.yml.
 */
class SchedulingConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())   // loads application.yml
            .withUserConfiguration(SchedulingConfig.class)
            .withBean(EventRepository.class, () -> mock(EventRepository.class))
            .withBean(AuditLogRepository.class, () -> mock(AuditLogRepository.class))
            .withBean(AuditLogService.class, () -> mock(AuditLogService.class))
            .withBean(EventKafkaProducer.class, () -> mock(EventKafkaProducer.class))
            .withBean(PlatformTransactionManager.class, () -> mock(PlatformTransactionManager.class))
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(PendingEventReconciler.class);

    @Test
    void reconcilerScheduleFromApplicationYml_isAcceptedBySpringScheduling() {

        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PendingEventReconciler.class);
            assertThat(context.getBean(ReconcilerProperties.class).getInterval()).isEqualTo(Duration.ofMinutes(1));
        });
    }
}
