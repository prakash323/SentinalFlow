package com.anomaly.platform.ml;

/*
 * The ML service answered, but the answer can never become a valid
 * prediction for this event: an HTTP 4xx (the request itself was rejected)
 * or a 2xx whose body is unreadable or fails validation. Sending the same
 * event again yields the same result, so KafkaErrorHandlingConfig sends it
 * straight to the dead-letter topic without retrying.
 */
public class MlResponseRejectedException extends RuntimeException {

    public MlResponseRejectedException(String message) {
        super(message);
    }

    public MlResponseRejectedException(String message, Throwable cause) {
        super(message, cause);
    }
}
