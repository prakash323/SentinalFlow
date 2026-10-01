package com.anomaly.platform.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/*
 * Externalized credentials for the two in-memory accounts (Phase 5). No
 * defaults live here on purpose - the dev-only fallback values are in
 * application.yml (security.users.*), mirroring how DB_USERNAME/DB_PASSWORD
 * already work in this project: overridable via environment variables,
 * with a clearly-labelled placeholder for local development only.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "security.users")
public class SecurityUsersProperties {

    private Account admin = new Account();

    private Account analyst = new Account();

    @Getter
    @Setter
    public static class Account {
        private String username;
        private String password;
    }
}
