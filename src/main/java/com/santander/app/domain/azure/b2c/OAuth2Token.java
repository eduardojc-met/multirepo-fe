package com.santander.app.domain.azure.b2c;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OAuth2Token {

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private int expiresIn;

    @JsonProperty("ext_expires_in")
    private int extExpiresIn;

    @JsonProperty("access_token")
    private String accessToken;

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public int getExtExpiresIn() {
        return extExpiresIn;
    }

    public void setExtExpiresIn(int extExpiresIn) {
        this.extExpiresIn = extExpiresIn;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public String toString() {
        return (
            "OAuth2Token{" +
            "tokenType='" +
            tokenType +
            '\'' +
            ", expiresIn=" +
            expiresIn +
            ", extExpiresIn=" +
            extExpiresIn +
            ", accessToken='" +
            accessToken +
            '\'' +
            '}'
        );
    }
}
