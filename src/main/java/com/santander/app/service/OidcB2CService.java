package com.santander.app.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.santander.app.config.OidcB2CProperties;
import com.santander.app.security.jwt.TokenProvider;
import java.util.Calendar;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
public class OidcB2CService {

    private final Logger log = LoggerFactory.getLogger(OidcB2CService.class);

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final TokenProvider tokenProvider;

    private final OidcB2CProperties oidcB2CProperties;

    public OidcB2CService(
        AuthenticationManagerBuilder authenticationManagerBuilder,
        TokenProvider tokenProvider,
        OidcB2CProperties oidcB2CProperties
    ) {
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.tokenProvider = tokenProvider;
        this.oidcB2CProperties = oidcB2CProperties;
    }

    public String authorizeOidcIdToken(String token) {
        final DecodedJWT decodedJWT = getDecodedJWT(token);
        Assert.notNull(decodedJWT, "Token received is not well formed.");
        validateToken(decodedJWT);

        final Authentication authenticationToken = new UsernamePasswordAuthenticationToken(
            decodedJWT.getSubject(),
            decodedJWT.getToken(),
            null
        );
        final Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return tokenProvider.createTokenFromAzureB2C(decodedJWT, authentication);
    }

    private DecodedJWT getDecodedJWT(final String token) {
        DecodedJWT decodedJWT = null;
        try {
            decodedJWT = JWT.decode(token);
        } catch (JWTDecodeException e) {
            log.error("Error occurred during token decoding. Maybe token is not valid. ", e);
        }
        return decodedJWT;
    }

    private void validateToken(final DecodedJWT decodedJWT) {
        validateExpiration(decodedJWT);
        validateApplication(decodedJWT);
    }

    private void validateApplication(final DecodedJWT decodedJWT) {
        Assert.isTrue(decodedJWT.getClaim("nonce").asString().equalsIgnoreCase(oidcB2CProperties.getNonce()), "Nonce is not correct");
        Assert.isTrue(
            decodedJWT.getAudience().stream().collect(Collectors.joining(",")).equalsIgnoreCase(oidcB2CProperties.getAudience()),
            "Audience is not correct"
        );
        Assert.isTrue(decodedJWT.getIssuer().equalsIgnoreCase(oidcB2CProperties.getIssuer()), "Issuer is not correct");
        Assert.isTrue(decodedJWT.getClaim("acr").asString().equalsIgnoreCase(oidcB2CProperties.getLoginFlow()), "ACR is not correct");
    }

    private void validateExpiration(DecodedJWT decodedJWT) {
        Assert.isTrue(!decodedJWT.getExpiresAt().before(Calendar.getInstance().getTime()), "Token is expired!");
        Assert.isTrue(!decodedJWT.getIssuedAt().after(Calendar.getInstance().getTime()), "Token is not valid yet!");
    }
}
