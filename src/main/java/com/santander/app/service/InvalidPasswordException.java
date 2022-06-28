package com.santander.app.service;

public class InvalidPasswordException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidPasswordException(final String message) {
        super(message);
    }
}
