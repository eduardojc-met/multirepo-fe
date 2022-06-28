package com.santander.app.web.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.santander.app.security.jwt.JWTFilter;
import com.santander.app.service.OidcB2CService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OidcB2CController {

    private final Logger log = LoggerFactory.getLogger(OidcB2CController.class);

    private final OidcB2CService oidcB2CService;

    public OidcB2CController(OidcB2CService oidcB2CService) {
        this.oidcB2CService = oidcB2CService;
    }

    @GetMapping("/auth/oidc")
    public ResponseEntity<UserJWTController.JWTToken> authorizeOidcIdToken(@RequestParam("id_token") final String token)
        throws JsonProcessingException {
        log.info("Token received apparently from Azure AD B2C");
        final String jwt = oidcB2CService.authorizeOidcIdToken(token);
        Assert.notNull(jwt, "Token not authenticated");

        final HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        return new ResponseEntity<>(new UserJWTController.JWTToken(jwt), httpHeaders, HttpStatus.OK);
    }
}
