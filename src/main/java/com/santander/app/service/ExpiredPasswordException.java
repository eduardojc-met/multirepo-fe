package com.santander.app.service;

public class ExpiredPasswordException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ExpiredPasswordException() {
        super("Your password has expired. Contact your system administrator.");
    }
}
