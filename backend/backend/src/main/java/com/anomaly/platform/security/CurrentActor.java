package com.anomaly.platform.security;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/*
 * Resolves who is performing the current action for audit purposes.
 *
 * Analyst/admin actions arrive through an authenticated HTTP request, so
 * the audit trail should name that person. Background work (Kafka
 * consumer, replay runs, automatic incident creation) has no
 * authenticated principal and stays attributed to "system".
 */
public final class CurrentActor {

    public static final String SYSTEM = "system";

    private CurrentActor() {
    }

    public static String name() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null
                || !auth.isAuthenticated()
                || auth instanceof AnonymousAuthenticationToken
                || auth.getName() == null
                || auth.getName().isBlank()) {

            return SYSTEM;
        }

        return auth.getName();
    }
}
