package com.anomaly.platform.controller;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.config.DetectionConfig;
import com.anomaly.platform.detection.config.DetectionProperties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/*
 * The rule catalog endpoint. It is read-only and returns exactly what the
 * registry knows, so the behaviour worth pinning down is what it must NOT leak
 * and that it cannot be used to change anything.
 *
 * Authorisation itself needs no test of its own here: SecurityConfig's catch-all
 * already requires ADMIN or ANALYST for every /api/v1/** path that is not
 * explicitly opened, and SecurityConfigTest covers that rule.
 */
class DetectionRuleControllerTest {

    private DetectionRuleController controller(DetectionProperties properties) {
        DetectionEngine engine = new DetectionEngine(
                new DetectionConfig().ruleRegistry(),
                new CorrelationWindowService(null),
                properties,
                null, null, null, null, null
        );
        return new DetectionRuleController(engine);
    }

    @Test
    @DisplayName("returns every registered rule with its identity and inputs")
    void listsEveryRule() {
        var rules = controller(DetectionProperties.defaults()).rules();

        assertThat(rules).hasSize(10);
        assertThat(rules).extracting("id").containsExactly(
                "AUTH_BURST", "NEW_PROCESS_EXTERNAL_CONNECTION", "PASSWORD_SPRAY", "ACCOUNT_ENUMERATION",
                "BRUTE_FORCE_SUCCESS", "IMPOSSIBLE_TRAVEL", "PRIVILEGE_ESCALATION_CHAIN",
                "PROCESS_NETWORK_BURST", "NETWORK_CONNECTION_BURST", "MULTI_STAGE_ATTACK_CHAIN");

        assertThat(rules).allSatisfy(r -> {
            assertThat(r.name()).isNotBlank();
            assertThat(r.description()).isNotBlank();
            assertThat(r.eventTypes()).isNotEmpty();
            assertThat(r.severities()).isNotEmpty();
            assertThat(r.tactic()).isNotBlank();
            assertThat(r.technique()).isNotBlank();
            assertThat(r.windowSeconds()).isPositive();
        });
    }

    @Test
    @DisplayName("reports a disabled rule as disabled rather than hiding it")
    void reportsDisabledRules() {
        DetectionProperties props = DetectionProperties.defaults();
        props.getRules().getImpossibleTravel().setEnabled(false);

        var rules = controller(props).rules();

        assertThat(rules).filteredOn(r -> r.id().equals("IMPOSSIBLE_TRAVEL"))
                .singleElement()
                .satisfies(r -> assertThat(r.enabled()).isFalse());
        assertThat(rules).filteredOn(r -> !r.id().equals("IMPOSSIBLE_TRAVEL"))
                .allSatisfy(r -> assertThat(r.enabled()).isTrue());
    }

    @Test
    @DisplayName("leaks no threshold, cooldown or other operational configuration")
    void leaksNoConfiguration() {
        String serialised = controller(DetectionProperties.defaults()).rules().toString();

        // The configured numbers that tell an attacker where the bar is.
        for (String leak : List.of("mediumThreshold", "highThreshold", "criticalThreshold",
                "distinctTargetThreshold", "attemptThreshold", "connectionThreshold",
                "failureThreshold", "maxSuccessRatio", "cooldown", "escalate", "minSpeedKmph")) {
            assertThat(serialised).as("response leaks %s", leak).doesNotContain(leak);
        }

        // And the record simply has no component that could carry one.
        List<String> components = java.util.Arrays.stream(
                        com.anomaly.platform.detection.RuleDescriptor.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName).toList();
        assertThat(components).containsExactly(
                "id", "name", "description", "enabled", "eventTypes",
                "severities", "tactic", "technique", "windowSeconds");
    }

    @Test
    @DisplayName("is read-only: the controller exposes no way to change a rule")
    void isReadOnly() {
        var methods = DetectionRuleController.class.getDeclaredMethods();

        assertThat(methods).allSatisfy(m -> {
            assertThat(m.getAnnotation(org.springframework.web.bind.annotation.PostMapping.class)).isNull();
            assertThat(m.getAnnotation(org.springframework.web.bind.annotation.PutMapping.class)).isNull();
            assertThat(m.getAnnotation(org.springframework.web.bind.annotation.PatchMapping.class)).isNull();
            assertThat(m.getAnnotation(org.springframework.web.bind.annotation.DeleteMapping.class)).isNull();
        });
    }
}
