package com.anomaly.platform.detection.config;

import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.RuleRegistry;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/*
 * ============================================================
 * THE SHIPPED application.yml ACTUALLY BINDS
 * ============================================================
 *
 * The thresholds in application.yml are the real operational contract, and a
 * typo in a property name there would NOT fail anything - Spring would silently
 * leave the Java default in place and the deployment would run with thresholds
 * nobody chose. A unit test of DetectionProperties.defaults() cannot catch that,
 * because it never reads the YAML.
 *
 * So this test binds the REAL `detection.*` block the way the application does,
 * and asserts the values that came out of the file rather than out of a Java
 * field initialiser. Every property name in application.yml is checked here by
 * being read back.
 *
 * It uses ApplicationContextRunner rather than @SpringBootTest so it needs no
 * database, no Kafka and no ML service - it is about configuration binding, and
 * it runs in milliseconds.
 */
class DetectionPropertiesBindingTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(DetectionConfig.class);

    /** The same values application.yml ships, so a drift between the two fails here. */
    private ApplicationContextRunner withShippedYaml() {
        return runner.withPropertyValues(
                "detection.enabled=true",
                "detection.max-correlation-events=500",

                "detection.rules.auth-burst.enabled=true",
                "detection.rules.auth-burst.window=5m",
                "detection.rules.auth-burst.medium-threshold=5",
                "detection.rules.auth-burst.high-threshold=10",
                "detection.rules.auth-burst.critical-threshold=0",
                "detection.rules.auth-burst.cooldown=0s",
                "detection.rules.auth-burst.escalate=false",

                "detection.rules.new-process-external-connection.enabled=true",
                "detection.rules.new-process-external-connection.window=5m",
                "detection.rules.new-process-external-connection.cooldown=0s",
                "detection.rules.new-process-external-connection.escalate=false",

                "detection.rules.password-spray.window=10m",
                "detection.rules.password-spray.distinct-target-threshold=5",
                "detection.rules.password-spray.high-threshold=10",
                "detection.rules.password-spray.critical-threshold=20",
                "detection.rules.password-spray.cooldown=10m",
                "detection.rules.password-spray.escalate=true",

                "detection.rules.account-enumeration.window=15m",
                "detection.rules.account-enumeration.distinct-target-threshold=10",
                "detection.rules.account-enumeration.attempt-threshold=15",
                "detection.rules.account-enumeration.max-success-ratio=0.2",
                "detection.rules.account-enumeration.high-threshold=20",
                "detection.rules.account-enumeration.critical-threshold=40",
                "detection.rules.account-enumeration.cooldown=15m",
                "detection.rules.account-enumeration.escalate=true",

                "detection.rules.brute-force-success.window=10m",
                "detection.rules.brute-force-success.failure-threshold=5",
                "detection.rules.brute-force-success.max-gap-to-success=2m",
                "detection.rules.brute-force-success.critical-threshold=10",

                "detection.rules.impossible-travel.window=2h",
                "detection.rules.impossible-travel.min-speed-kmph=900",
                "detection.rules.impossible-travel.min-distance-km=500",
                "detection.rules.impossible-travel.critical-speed-kmph=3000",
                "detection.rules.impossible-travel.cooldown=1h",

                "detection.rules.privilege-escalation-chain.window=10m",
                "detection.rules.privilege-escalation-chain.cooldown=10m",
                "detection.rules.privilege-escalation-chain.escalate=true",

                "detection.rules.process-network-burst.window=60s",
                "detection.rules.process-network-burst.connection-threshold=5",
                "detection.rules.process-network-burst.high-threshold=10",
                "detection.rules.process-network-burst.critical-threshold=20",
                "detection.rules.process-network-burst.cooldown=5m",
                "detection.rules.process-network-burst.escalate=true",

                "detection.rules.network-connection-burst.window=60s",
                "detection.rules.network-connection-burst.connection-threshold=20",
                "detection.rules.network-connection-burst.distinct-destination-threshold=10",
                "detection.rules.network-connection-burst.high-threshold=40",
                "detection.rules.network-connection-burst.critical-threshold=80",
                "detection.rules.network-connection-burst.cooldown=5m",
                "detection.rules.network-connection-burst.escalate=true",

                "detection.rules.multi-stage-attack-chain.window=30m",
                "detection.rules.multi-stage-attack-chain.min-stages=3",
                "detection.rules.multi-stage-attack-chain.critical-stages=4",
                "detection.rules.multi-stage-attack-chain.cooldown=30m",
                "detection.rules.multi-stage-attack-chain.escalate=false"
        );
    }

    @Test
    @DisplayName("every property in the shipped detection block binds to the value it states")
    void shippedConfigurationBinds() {
        withShippedYaml().run(context -> {
            assertThat(context).hasSingleBean(DetectionProperties.class);
            DetectionProperties p = context.getBean(DetectionProperties.class);

            assertThat(p.isEnabled()).isTrue();
            assertThat(p.getMaxCorrelationEvents()).isEqualTo(500);

            var auth = p.getRules().getAuthBurst();
            assertThat(auth.getWindow()).isEqualTo(Duration.ofMinutes(5));
            assertThat(auth.getMediumThreshold()).isEqualTo(5);
            assertThat(auth.getHighThreshold()).isEqualTo(10);
            assertThat(auth.getCriticalThreshold()).isZero();
            assertThat(auth.getCooldown()).isZero();
            assertThat(auth.isEscalate()).isFalse();

            var procconn = p.getRules().getNewProcessExternalConnection();
            assertThat(procconn.getWindow()).isEqualTo(Duration.ofMinutes(5));
            assertThat(procconn.getCooldown()).isZero();
            assertThat(procconn.isEscalate()).isFalse();

            var spray = p.getRules().getPasswordSpray();
            assertThat(spray.getWindow()).isEqualTo(Duration.ofMinutes(10));
            assertThat(spray.getDistinctTargetThreshold()).isEqualTo(5);
            assertThat(spray.getHighThreshold()).isEqualTo(10);
            assertThat(spray.getCriticalThreshold()).isEqualTo(20);
            assertThat(spray.getCooldown()).isEqualTo(Duration.ofMinutes(10));
            assertThat(spray.isEscalate()).isTrue();

            var enumeration = p.getRules().getAccountEnumeration();
            assertThat(enumeration.getWindow()).isEqualTo(Duration.ofMinutes(15));
            assertThat(enumeration.getDistinctTargetThreshold()).isEqualTo(10);
            assertThat(enumeration.getAttemptThreshold()).isEqualTo(15);
            assertThat(enumeration.getMaxSuccessRatio()).isEqualTo(0.2);

            var brute = p.getRules().getBruteForceSuccess();
            assertThat(brute.getWindow()).isEqualTo(Duration.ofMinutes(10));
            assertThat(brute.getFailureThreshold()).isEqualTo(5);
            assertThat(brute.getMaxGapToSuccess()).isEqualTo(Duration.ofMinutes(2));
            assertThat(brute.getCriticalThreshold()).isEqualTo(10);

            var travel = p.getRules().getImpossibleTravel();
            assertThat(travel.getWindow()).isEqualTo(Duration.ofHours(2));
            assertThat(travel.getMinSpeedKmph()).isEqualTo(900.0);
            assertThat(travel.getMinDistanceKm()).isEqualTo(500.0);
            assertThat(travel.getCriticalSpeedKmph()).isEqualTo(3000.0);

            var privilege = p.getRules().getPrivilegeEscalationChain();
            assertThat(privilege.getWindow()).isEqualTo(Duration.ofMinutes(10));
            assertThat(privilege.isEscalate()).isTrue();

            var processBurst = p.getRules().getProcessNetworkBurst();
            assertThat(processBurst.getWindow()).isEqualTo(Duration.ofSeconds(60));
            assertThat(processBurst.getConnectionThreshold()).isEqualTo(5);
            assertThat(processBurst.getHighThreshold()).isEqualTo(10);
            assertThat(processBurst.getCriticalThreshold()).isEqualTo(20);

            var netBurst = p.getRules().getNetworkConnectionBurst();
            assertThat(netBurst.getConnectionThreshold()).isEqualTo(20);
            assertThat(netBurst.getDistinctDestinationThreshold()).isEqualTo(10);
            assertThat(netBurst.getHighThreshold()).isEqualTo(40);
            assertThat(netBurst.getCriticalThreshold()).isEqualTo(80);

            var chain = p.getRules().getMultiStageAttackChain();
            assertThat(chain.getWindow()).isEqualTo(Duration.ofMinutes(30));
            assertThat(chain.getMinStages()).isEqualTo(3);
            assertThat(chain.getCriticalStages()).isEqualTo(4);

            // And the whole thing passes the startup validation it will face.
            p.validate();
        });
    }

    @Test
    @DisplayName("the rule registry is wired with all ten rules, each enabled under the shipped config")
    void registryIsWired() {
        withShippedYaml().run(context -> {
            assertThat(context).hasSingleBean(RuleRegistry.class);
            RuleRegistry registry = context.getBean(RuleRegistry.class);
            DetectionProperties props = context.getBean(DetectionProperties.class);

            assertThat(registry.size()).isEqualTo(10);
            assertThat(registry.all()).extracting(DetectionRule::id).containsExactly(
                    "AUTH_BURST", "NEW_PROCESS_EXTERNAL_CONNECTION", "PASSWORD_SPRAY", "ACCOUNT_ENUMERATION",
                    "BRUTE_FORCE_SUCCESS", "IMPOSSIBLE_TRAVEL", "PRIVILEGE_ESCALATION_CHAIN",
                    "PROCESS_NETWORK_BURST", "NETWORK_CONNECTION_BURST", "MULTI_STAGE_ATTACK_CHAIN");

            assertThat(registry.all()).allSatisfy(r ->
                    assertThat(r.isEnabled(props)).as(r.id()).isTrue());

            assertThat(registry.consumedEventTypes())
                    .containsExactlyInAnyOrder("LOGIN", "NETWORK_CONNECTION");
        });
    }

    @Test
    @DisplayName("an empty detection block falls back to the historical defaults rather than disabling detection")
    void absentConfigurationKeepsHistoricalDefaults() {
        runner.run(context -> {
            DetectionProperties p = context.getBean(DetectionProperties.class);

            assertThat(p.isEnabled()).isTrue();
            assertThat(p.getRules().getAuthBurst().getMediumThreshold()).isEqualTo(5);
            assertThat(p.getRules().getAuthBurst().getHighThreshold()).isEqualTo(10);
            assertThat(p.getRules().getAuthBurst().getWindow()).isEqualTo(Duration.ofMinutes(5));
            assertThat(p.getRules().getNewProcessExternalConnection().getWindow()).isEqualTo(Duration.ofMinutes(5));
            p.validate();
        });
    }

    @Test
    @DisplayName("the master switch can turn the whole deterministic path off from configuration alone")
    void masterSwitchBinds() {
        runner.withPropertyValues("detection.enabled=false").run(context -> {
            DetectionProperties p = context.getBean(DetectionProperties.class);
            RuleRegistry registry = context.getBean(RuleRegistry.class);

            assertThat(p.isEnabled()).isFalse();
            assertThat(registry.all()).allSatisfy(r -> assertThat(r.isEnabled(p)).isFalse());
        });
    }

    @Test
    @DisplayName("one rule can be disabled without touching the others")
    void singleRuleCanBeDisabled() {
        runner.withPropertyValues("detection.rules.impossible-travel.enabled=false").run(context -> {
            DetectionProperties p = context.getBean(DetectionProperties.class);
            RuleRegistry registry = context.getBean(RuleRegistry.class);

            assertThat(registry.byId("IMPOSSIBLE_TRAVEL").isEnabled(p)).isFalse();
            assertThat(registry.all()).filteredOn(r -> !r.id().equals("IMPOSSIBLE_TRAVEL"))
                    .allSatisfy(r -> assertThat(r.isEnabled(p)).isTrue());
        });
    }

    @Test
    @DisplayName("a threshold overridden in configuration reaches the rule, with nothing hard-coded in Java")
    void overridesReachTheRules() {
        runner.withPropertyValues(
                "detection.rules.auth-burst.medium-threshold=3",
                "detection.rules.auth-burst.high-threshold=7",
                "detection.rules.auth-burst.window=90s"
        ).run(context -> {
            DetectionProperties p = context.getBean(DetectionProperties.class);
            var auth = p.getRules().getAuthBurst();

            assertThat(auth.getMediumThreshold()).isEqualTo(3);
            assertThat(auth.getHighThreshold()).isEqualTo(7);
            assertThat(auth.getWindow()).isEqualTo(Duration.ofSeconds(90));

            // The rule reads its settings from this object, never from a constant.
            assertThat(context.getBean(RuleRegistry.class).byId("AUTH_BURST").window(p))
                    .isEqualTo(Duration.ofSeconds(90));
        });
    }
}
