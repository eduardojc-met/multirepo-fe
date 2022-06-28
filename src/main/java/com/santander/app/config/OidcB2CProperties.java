package com.santander.app.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Properties specific to Test 1.
 * <p>
 * Properties are configured in the {@code application.yml} file.
 * See {@link tech.jhipster.config.JHipsterProperties} for a good example.
 */
@ConfigurationProperties(prefix = "spring.cloud.azure.active-directory.b2c", ignoreUnknownFields = true)
public class OidcB2CProperties {
    private String loginFlow;
    private String nonce;
    private String audience;
    private String issuer;
    private String discoveryUrl;
    private String roleAssignmentUrl;
    private OAuth oAuth = new OAuth();

    public String getLoginFlow() {
        return loginFlow;
    }

    public void setLoginFlow(String loginFlow) {
        this.loginFlow = loginFlow;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getDiscoveryUrl() {
        return discoveryUrl;
    }

    public void setDiscoveryUrl(String discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public String getRoleAssignmentUrl() {
        return roleAssignmentUrl;
    }

    public void setRoleAssignmentUrl(String roleAssignmentUrl) {
        this.roleAssignmentUrl = roleAssignmentUrl;
    }

    public OAuth getoAuth() {
        return oAuth;
    }

    public void setoAuth(OAuth oAuth) {
        this.oAuth = oAuth;
    }

    public class OAuth {


        private String clientId;
        private String clientSecret;
        private String scope;
        private String server;
        private Cache cache = new Cache();

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getServer() {
            return server;
        }

        public void setServer(String server) {
            this.server = server;
        }

        public Cache getCache() {
            return cache;
        }

        public void setCache(Cache cache) {
            this.cache = cache;
        }
    }

    public class Cache {


        private int timeToLiveSeconds = 3600;
        private long maxEntries = 100L;

        public int getTimeToLiveSeconds() {
            return timeToLiveSeconds;
        }

        public void setTimeToLiveSeconds(int timeToLiveSeconds) {
            this.timeToLiveSeconds = timeToLiveSeconds;
        }

        public long getMaxEntries() {
            return maxEntries;
        }
        public void setMaxEntries(long maxEntries) {
            this.maxEntries = maxEntries;
        }
    }
}
