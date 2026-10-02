package com.anomaly.platform.exception;

public class PayloadTooLargeException
        extends RuntimeException {

    public PayloadTooLargeException(
            String message
    ) {
        super(message);
    }
}
