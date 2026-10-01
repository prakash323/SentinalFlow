package com.anomaly.platform.config;
import org.springframework.boot.context.properties.EnableConfigurationProperties; import org.springframework.context.annotation.Configuration;
@Configuration @EnableConfigurationProperties(AlertPolicyProperties.class)
public class AppConfig {}
