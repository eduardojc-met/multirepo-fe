package com.santander.app.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.santander.app.config.OidcB2CProperties;
import com.santander.app.domain.azure.b2c.*;
import com.santander.app.repository.OidcRoleRepository;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import javax.cache.CacheManager;
import org.apache.commons.lang3.BooleanUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Component
public class OidcAuthenticationProvider implements AuthenticationProvider {

    private final Logger log = LoggerFactory.getLogger(OidcAuthenticationProvider.class);

    private final List<OidcRole> bbddRoles;

    private final OidcB2CProperties oidcB2CProperties;

    public static final String OIDC_TOKEN_CACHE = "oidc_token_cache";

    private final CacheManager cacheManager;

    public OidcAuthenticationProvider(
        OidcRoleRepository oidcRoleRepository,
        OidcB2CProperties oidcB2CProperties,
        CacheManager cacheManager
    ) {
        this.bbddRoles = oidcRoleRepository.findAll();
        this.oidcB2CProperties = oidcB2CProperties;
        this.cacheManager = cacheManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            final DecodedJWT decodedJWT = getDecodedJWT((String) authentication.getCredentials());
            validateSignature(decodedJWT);
            final Collection<GrantedAuthority> authorities = obtainUserRoles(decodedJWT);
            return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), authorities);
        } catch (Exception e) {
            log.warn("No valid authentication received");
        }
        return null;
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

    private void validateSignature(final DecodedJWT decodedJWT) {
        final List<Key> keys = discoverKeys();
        Assert.notEmpty(keys, "Not keys discovered to validate token");
        final Optional<Key> found = keys.stream().filter(key -> key.getKid().equals(decodedJWT.getKeyId())).findFirst();
        Assert.isTrue(found.isPresent(), "Not key found to validate token");
        log.info("Key found for kid {}", decodedJWT.getHeaderClaim("kid"));
        final boolean isValid = validateSignature(decodedJWT, found.get());
        log.info("JWT signature " + (BooleanUtils.toString(isValid, "is valid", "is NOT valid")));
        Assert.isTrue(isValid, "JWT signature is NOT valid");
    }

    private boolean validateSignature(final DecodedJWT decodedJWT, final Key key) {
        boolean result = false;
        try {
            final byte[] modulusByte = Base64.getUrlDecoder().decode(key.getN());
            final BigInteger modulusAsBigInt = new BigInteger(1, modulusByte);
            final byte[] exponentByte = Base64.getUrlDecoder().decode(key.getE());
            final BigInteger exponentAsBigInt = new BigInteger(1, exponentByte);

            final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulusAsBigInt, exponentAsBigInt);
            final KeyFactory factory = KeyFactory.getInstance("RSA");
            final PublicKey pub = factory.generatePublic(spec);
            final Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) pub, null);
            algorithm.verify(decodedJWT);
            result = true;
        } catch (Exception e) {
            log.error("Obtained token is invalid. ", e);
        }
        return result;
    }

    private List<Key> discoverKeys() {
        List<Key> keys = null;
        try {
            log.info("Obtaining keys from discovery service");
            final RestTemplate restTemplate = new RestTemplate();
            final ResponseEntity<AuthorizeResponse> response = restTemplate.getForEntity(
                oidcB2CProperties.getDiscoveryUrl(),
                AuthorizeResponse.class
            );
            if (
                response != null &&
                response.getStatusCode().equals(HttpStatus.OK) &&
                response.getBody() != null &&
                response.getBody().getKeys() != null
            ) {
                keys = response.getBody().getKeys();
                log.info("{} keys discovered", keys.size());
            } else {
                log.error(
                    "Discovery keys service returns " + response != null && response.getStatusCode() != null
                        ? response.getStatusCode().toString()
                        : "NULL"
                );
            }
        } catch (Exception e) {
            log.error("Error occurred during discovery keys process. ", e);
        }
        return keys;
    }

    private Collection<GrantedAuthority> obtainUserRoles(DecodedJWT decodedJWT) {
        log.info("Obtaining user app roles assignments");
        final Collection<GrantedAuthority> authorities = new ArrayList<>();
        final String url = oidcB2CProperties.getRoleAssignmentUrl() + "/" + decodedJWT.getSubject() + "/appRoleAssignments";

        final String token = obtainToken();
        Assert.notNull(token, "Application can not obtain OAuth2 token to validate App Role Assignments");

        final RestTemplate restTemplate = new RestTemplate();
        final HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        final HttpEntity request = new HttpEntity(headers);
        final ResponseEntity<AppRoleAssignments> response = restTemplate.exchange(url, HttpMethod.GET, request, AppRoleAssignments.class);

        if (response != null && response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            final RoleAssignment[] roles = response.getBody().getRoleAssignments();
            Assert.isTrue(roles.length > 0, "No App roles assigned");
            authorities.addAll(getSimpleGrantedAuthorities(roles));
        } else {
            log.error(
                "Application role assignments service returns " + response != null && response.getStatusCode() != null
                    ? response.getStatusCode().toString()
                    : "NULL"
            );
        }
        return authorities;
    }

    private List<SimpleGrantedAuthority> getSimpleGrantedAuthorities(RoleAssignment[] roles) {
        final List<String> rolesId = Arrays.stream(roles).map(rol -> rol.getAppRoleId()).collect(Collectors.toList());
        final List<SimpleGrantedAuthority> list = bbddRoles
            .stream()
            .filter(rol -> rolesId.contains(rol.getProviderId()))
            .map(r -> new SimpleGrantedAuthority(r.getName()))
            .collect(Collectors.toList());
        return list;
    }

    private String obtainToken() {
        String token = null;
        if (cacheManager.getCache(OIDC_TOKEN_CACHE).containsKey("token")) {
            log.info("OIDC OAuth token found in cache...");
            token = String.valueOf(cacheManager.getCache(OIDC_TOKEN_CACHE).get("token"));
        } else {
            log.info("No OIDC Auth token was found in cache");
            final RestTemplate restTemplate = new RestTemplate();

            final ResponseEntity<OAuth2Token> response = restTemplate.exchange(
                oidcB2CProperties.getoAuth().getServer(),
                HttpMethod.POST,
                performTokenRequest(),
                OAuth2Token.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                token = response.getBody().getAccessToken();
                if (!cacheManager.getCache(OIDC_TOKEN_CACHE).containsKey("token")) {
                    cacheManager.getCache(OIDC_TOKEN_CACHE).put("token", token);
                }
            } else {
                log.error(
                    "Obtain token service returns " + response != null && response.getStatusCode() != null
                        ? response.getStatusCode().toString()
                        : "NULL"
                );
            }
        }
        return token;
    }

    private HttpEntity<MultiValueMap<String, String>> performTokenRequest() {
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        final MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", oidcB2CProperties.getoAuth().getClientId());
        map.add("client_secret", oidcB2CProperties.getoAuth().getClientSecret());
        map.add("scope", oidcB2CProperties.getoAuth().getScope());
        map.add("grant_type", "client_credentials");

        final HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        return entity;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
