package com.anomaly.platform.detection.config;

import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.RuleRegistry;
import com.anomaly.platform.detection.rules.AccountEnumerationRule;
import com.anomaly.platform.detection.rules.AuthBurstRule;
import com.anomaly.platform.detection.rules.BruteForceSuccessRule;
import com.anomaly.platform.detection.rules.ImpossibleTravelRule;
import com.anomaly.platform.detection.rules.MultiStageAttackChainRule;
import com.anomaly.platform.detection.rules.NetworkConnectionBurstRule;
import com.anomaly.platform.detection.rules.NewProcessExternalConnectionRule;
import com.anomaly.platform.detection.rules.PasswordSprayRule;
import com.anomaly.platform.detection.rules.PrivilegeEscalationChainRule;
import com.anomaly.platform.detection.rules.ProcessNetworkBurstRule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;

import java.util.List;

/*
 * ============================================================
 * WIRING THE DETECTION ENGINE
 * ============================================================
 *
 * THE ONE PLACE A RULE IS TURNED ON.
 *
 * Adding rule N+1 is two edits: write the rule class, then add one line to
 * ruleRegistry() below. Nothing is discovered by classpath scanning or
 * reflection - a reader can see the complete, ordered set of active rules here,
 * and a rule that is not in this list does not run, however many annotations it
 * carries.
 *
 * Rule ORDER in this list does not change any outcome (each rule is evaluated
 * independently against the same event and window, and none can see another's
 * result); it is simply the order the catalog and the logs present them in.
 */
@Configuration
@EnableConfigurationProperties(DetectionProperties.class)
public class DetectionConfig {

    private static final Logger log = LoggerFactory.getLogger(DetectionConfig.class);

    @Bean
    public RuleRegistry ruleRegistry() {
        List<DetectionRule> rules = List.of(
                // R001-R002: the original deterministic rules, re-implemented on this
                // framework with their matching contracts and thresholds unchanged.
                new AuthBurstRule(),
                new NewProcessExternalConnectionRule(),

                // R003-R006: identity and authentication correlation.
                new PasswordSprayRule(),
                new AccountEnumerationRule(),
                new BruteForceSuccessRule(),
                new ImpossibleTravelRule(),

                // R007-R009: endpoint and network correlation.
                new PrivilegeEscalationChainRule(),
                new ProcessNetworkBurstRule(),
                new NetworkConnectionBurstRule(),

                // R010: higher-level correlation over the signals above. Adds an
                // alert; never replaces or suppresses the underlying ones.
                new MultiStageAttackChainRule()
        );
        return new RuleRegistry(rules);
    }

    /*
     * Fail fast on a misconfigured threshold.
     *
     * A detection rule that silently never fires because its window is zero or
     * its thresholds are inverted is worse than one that is explicitly disabled:
     * the dashboard looks calm and nobody knows detection is off. Validating at
     * startup turns that into a refusal to boot, with the offending property
     * named.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void validateDetectionConfiguration(ApplicationReadyEvent ignored) {
        // Resolved through the context so the listener sees the bound instance.
        DetectionProperties properties = ignored.getApplicationContext().getBean(DetectionProperties.class);
        properties.validate();

        RuleRegistry registry = ignored.getApplicationContext().getBean(RuleRegistry.class);
        long enabled = registry.all().stream().filter(r -> r.isEnabled(properties)).count();

        log.info("Deterministic detection engine ready: {} rules registered, {} enabled, event types {}",
                registry.size(), enabled, registry.consumedEventTypes().stream().sorted().toList());

        if (!properties.isEnabled()) {
            log.warn("detection.enabled=false - NO deterministic rule will run. "
                    + "The ML detection path is unaffected.");
        }
        registry.all().stream()
                .filter(r -> !r.isEnabled(properties))
                .forEach(r -> log.warn("Detection rule {} ({}) is DISABLED by configuration", r.id(), r.name()));
    }
}
