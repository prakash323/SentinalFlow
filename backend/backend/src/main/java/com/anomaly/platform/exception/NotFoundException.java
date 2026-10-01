package com.anomaly.platform.exception;
public class NotFoundException extends RuntimeException {
    public NotFoundException(String message){
        super(message);
    }
}
