package com.anomaly.platform.config;
import lombok.Getter; import lombok.Setter; import org.springframework.boot.context.properties.ConfigurationProperties;
@Getter @Setter @ConfigurationProperties(prefix="anomaly.alert-policy")
public class AlertPolicyProperties {
    private String policyVersion;
    private double alertThreshold;
    private SeverityThreshold severity = new SeverityThreshold();
    @Getter @Setter public static class SeverityThreshold {
        private double medium;
        private double high;
        private double critical;
    }
}
