package com.anomaly.platform.exception;
public class InvalidStatusTransitionException extends RuntimeException {
    public InvalidStatusTransitionException(String message){
        super(message);
    }
}
