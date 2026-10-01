package com.anomaly.platform.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/*
 * Identity of the caller, so the frontend can validate a login against the
 * real backend and show or hide admin-only screens. Any authenticated
 * ANALYST/ADMIN reaches this through the /api/v1/** catch-all rule; no
 * credentials or other user data are returned.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {

        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(a -> a.startsWith("ROLE_") ? a.substring("ROLE_".length()) : a)
                .sorted()
                .toList();

        return Map.of(
                "username", authentication.getName(),
                "roles", roles,
                "admin", roles.contains("ADMIN")
        );
    }
}
