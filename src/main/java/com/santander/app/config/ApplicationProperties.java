package com.santander.app.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Properties specific to Test 1.
 * <p>
 * Properties are configured in the {@code application.yml} file.
 * See {@link tech.jhipster.config.JHipsterProperties} for a good example.
 */
@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class ApplicationProperties {

    private long passwordLockTimeDurationMillis;
    private int passwordMaxFailedAttempts;

    public long getPasswordLockTimeDurationMillis() {
        return passwordLockTimeDurationMillis;
    }

    public void setPasswordLockTimeDurationMillis(long passwordLockTimeDurationMillis) {
        this.passwordLockTimeDurationMillis = passwordLockTimeDurationMillis;
    }

    public int getPasswordMaxFailedAttempts() {
        return passwordMaxFailedAttempts;
    }

    public void setPasswordMaxFailedAttempts(int passwordMaxFailedAttempts) {
        this.passwordMaxFailedAttempts = passwordMaxFailedAttempts;
    }
}
