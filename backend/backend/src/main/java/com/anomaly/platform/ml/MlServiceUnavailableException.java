package com.anomaly.platform.ml;

/*
 * The ML service could not answer right now: connection refused/reset,
 * connect or read timeout, any HTTP 5xx - including its documented warm-up
 * response (503 "ML scorer is still warming up", ml-service api.py).
 * Retrying the same event later can succeed, so KafkaErrorHandlingConfig
 * retries it with exponential backoff before dead-lettering it.
 */
public class MlServiceUnavailableException extends RuntimeException {

    private final boolean warmingUp;

    public MlServiceUnavailableException(String message, boolean warmingUp, Throwable cause) {
        super(message, cause);
        this.warmingUp = warmingUp;
    }

    public boolean isWarmingUp() {
        return warmingUp;
    }
}
