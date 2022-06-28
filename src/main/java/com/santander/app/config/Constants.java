package com.santander.app.config;

/**
 * Application constants.
 */
public final class Constants {

    // Regex for acceptable logins
    public static final String LOGIN_REGEX = "^(?>[a-zA-Z0-9!$&*+=?^_`{|}~.-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*)|(?>[_.@A-Za-z0-9-]+)$";
    public static final String PASSWORD_REGEX = "/(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])/";
    public static final int PASSWORD_MIN_LENGTH = 8;
    public static final int PASSWORD_MAX_LENGTH = 100;

    public static final String SYSTEM = "system";
    public static final String DEFAULT_LANGUAGE = "es";

    public static final String PASSWORD_EXPIRED_MESSAGE = "Your password will be expired in {days} days. Please, reset the password.";

    private Constants() {}
}
