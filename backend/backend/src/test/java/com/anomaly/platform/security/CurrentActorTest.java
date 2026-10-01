package com.anomaly.platform.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

class CurrentActorTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void noAuthentication_isAttributedToSystem() {
        SecurityContextHolder.clearContext();

        assertThat(CurrentActor.name()).isEqualTo("system");
    }

    @Test
    void anonymousUser_isAttributedToSystem() {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken(
                        "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
                )
        );

        assertThat(CurrentActor.name()).isEqualTo("system");
    }

    @Test
    void authenticatedUser_isAttributedByUsername() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        "analyst", "n/a", AuthorityUtils.createAuthorityList("ROLE_ANALYST")
                )
        );

        assertThat(CurrentActor.name()).isEqualTo("analyst");
    }
}
