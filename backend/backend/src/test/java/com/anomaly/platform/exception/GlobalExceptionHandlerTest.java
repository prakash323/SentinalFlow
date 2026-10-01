package com.anomaly.platform.exception;

import com.anomaly.platform.dto.ErrorResponse;
import com.anomaly.platform.entity.Alert;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/*
 * Concurrency hardening: the CONCURRENT_MODIFICATION mapping this handler
 * exists for was proven necessary live (two concurrent PATCH /alerts/{id}
 * /status requests both returned a false 200 before Alert.version and this
 * handler existed - see AlertServiceTest's own concurrency test). This
 * confirms the handler itself, in isolation, turns that exception into a
 * clean 409 rather than leaking a raw 500/stack trace to the client.
 */
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void concurrentModification_mapsTo409_withNoInternalDetailsLeaked() {

        ObjectOptimisticLockingFailureException conflict =
                new ObjectOptimisticLockingFailureException(Alert.class, UUID.randomUUID());

        ResponseEntity<ErrorResponse> response = handler.handleConcurrentModification(conflict);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().code()).isEqualTo("CONCURRENT_MODIFICATION");
        assertThat(response.getBody().message()).doesNotContain("ObjectOptimisticLockingFailureException");
        assertThat(response.getBody().details()).isEmpty();
    }
}
