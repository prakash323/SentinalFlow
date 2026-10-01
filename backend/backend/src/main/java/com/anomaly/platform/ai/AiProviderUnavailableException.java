package com.anomaly.platform.ai;

/*
 * Thrown when the external LLM provider call fails for any reason
 * (network error, timeout, auth failure, rate limit, malformed response).
 * Mapped to a controlled 503 by GlobalExceptionHandler - never leaks the
 * provider's raw exception message to the client.
 */
public class AiProviderUnavailableException extends RuntimeException {

    public AiProviderUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
