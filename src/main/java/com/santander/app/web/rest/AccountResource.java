package com.santander.app.web.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.santander.app.config.Constants;
import com.santander.app.domain.User;
import com.santander.app.repository.UserRepository;
import com.santander.app.security.SecurityUtils;
import com.santander.app.service.MailService;
import com.santander.app.service.UserService;
import com.santander.app.service.dto.AdminUserDTO;
import com.santander.app.service.dto.PasswordChangeDTO;
import com.santander.app.service.utils.PasswordUtils;
import com.santander.app.web.rest.errors.EmailAlreadyUsedException;
import com.santander.app.web.rest.errors.InvalidPasswordException;
import com.santander.app.web.rest.vm.KeyAndPasswordVM;
import java.security.Principal;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for managing the current user's account.
 */
@RestController
@RequestMapping("/api")
public class AccountResource {

    private static class AccountResourceException extends RuntimeException {

        private AccountResourceException(String message) {
            super(message);
        }
    }

    private final Logger log = LoggerFactory.getLogger(AccountResource.class);

    private final UserRepository userRepository;

    private final UserService userService;

    private final MailService mailService;

    public AccountResource(UserRepository userRepository, UserService userService, MailService mailService) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.mailService = mailService;
    }

    /**
     * {@code GET  /activate} : activate the registered user.
     *
     * @param key the activation key.
     * @throws RuntimeException {@code 500 (Internal Server Error)} if the user couldn't be activated.
     */
    @GetMapping("/activate")
    public void activateAccount(@RequestParam(value = "key") String key) {
        Optional<User> user = userService.activateRegistration(key);
        if (!user.isPresent()) {
            throw new AccountResourceException("No user was found for this activation key");
        }
    }

    /**
     * {@code GET  /authenticate} : check if the user is authenticated, and return its login.
     *
     * @param request the HTTP request.
     * @return the login if the user is authenticated.
     */
    @GetMapping("/authenticate")
    public String isAuthenticated(HttpServletRequest request) {
        log.debug("REST request to check if the current user is authenticated");
        return request.getRemoteUser();
    }

    /**
     * {@code GET  /account} : get the current user.
     *
     * @return the current user.
     * @throws RuntimeException {@code 500 (Internal Server Error)} if the user couldn't be returned.
     */
    @GetMapping("/account")
    @SuppressWarnings("unchecked")
    public AdminUserDTO getAccount(Principal principal) {
        if (principal instanceof AbstractAuthenticationToken) {
            return getUserFromAuthentication((AbstractAuthenticationToken) principal);
        } else {
            throw new AccountResourceException("User could not be found");
        }
    }

    public AdminUserDTO getUserFromAuthentication(final AbstractAuthenticationToken authToken) {
        final AdminUserDTO user = new AdminUserDTO();
        if (authToken instanceof UsernamePasswordAuthenticationToken) {
            if (authToken.getCredentials() != null && authToken.getCredentials() instanceof String) {
                obtainClaimsFromCredentials(authToken, user);
            }
            user.setLogin(authToken.getName());
            user.setActivated(true);
            final Set<String> authorities = authToken
                .getAuthorities()
                .stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.toSet());
            user.setAuthorities(authorities);
            user.setLangKey(Constants.DEFAULT_LANGUAGE);
        }
        return user;
    }

    private void obtainClaimsFromCredentials(final AbstractAuthenticationToken authToken, final AdminUserDTO user) {
        final DecodedJWT decodedJWT = getDecodedJWT((String) authToken.getCredentials());
        if (!decodedJWT.getClaim("emails").isNull()) {
            final Optional<String> email = Arrays.stream(decodedJWT.getClaim("emails").asArray(String.class)).findFirst();
            if (email.isPresent()) {
                user.setEmail(email.get());
            }
        }
        if (!decodedJWT.getClaim("name").isNull()) {
            user.setFirstName(decodedJWT.getClaim("name").asString());
        }
        user.setCreatedBy(decodedJWT.getClaim("acr").asString());
        //user.setCreatedDate(decodedJWT.getNotBefore().toInstant());
        user.setId(decodedJWT.getSubject());
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

    /**
     * {@code POST  /account} : update the current user information.
     *
     * @param userDTO the current user information.
     * @throws EmailAlreadyUsedException {@code 400 (Bad Request)} if the email is already used.
     * @throws RuntimeException {@code 500 (Internal Server Error)} if the user login wasn't found.
     */
    @PostMapping("/account")
    public void saveAccount(@Valid @RequestBody AdminUserDTO userDTO) {
        String userLogin = SecurityUtils
            .getCurrentUserLogin()
            .orElseThrow(() -> new AccountResourceException("Current user login not found"));
        Optional<User> existingUser = userRepository.findOneByEmailIgnoreCase(userDTO.getEmail());
        if (existingUser.isPresent() && (!existingUser.get().getLogin().equalsIgnoreCase(userLogin))) {
            throw new EmailAlreadyUsedException();
        }
        Optional<User> user = userRepository.findOneByLogin(userLogin);
        if (!user.isPresent()) {
            throw new AccountResourceException("User could not be found");
        }
        userService.updateUser(
            userDTO.getFirstName(),
            userDTO.getLastName(),
            userDTO.getEmail(),
            userDTO.getLangKey(),
            userDTO.getImageUrl()
        );
    }

    /**
     * {@code POST  /account/change-password} : changes the current user's password.
     *
     * @param passwordChangeDto current and new password.
     * @throws InvalidPasswordException {@code 400 (Bad Request)} if the new password is incorrect.
     */
    @PostMapping(path = "/account/change-password")
    public void changePassword(@RequestBody PasswordChangeDTO passwordChangeDto) {
        if (
            PasswordUtils.isPasswordLengthInvalid(passwordChangeDto.getNewPassword()) ||
            !PasswordUtils.checkStrength(passwordChangeDto.getNewPassword())
        ) {
            log.warn("Password strength or password length invalid");
            throw new InvalidPasswordException("Password strength or password length invalid");
        }
        userService.changePassword(passwordChangeDto.getCurrentPassword(), passwordChangeDto.getNewPassword());
    }

    /**
     * {@code POST   /account/reset-password/init} : Send an email to reset the password of the user.
     *
     * @param mail the mail of the user.
     */
    @PostMapping(path = "/account/reset-password/init")
    public void requestPasswordReset(@RequestBody String mail) {
        Optional<User> user = userService.requestPasswordReset(mail);
        if (user.isPresent()) {
            mailService.sendPasswordResetMail(user.get());
        } else {
            // Pretend the request has been successful to prevent checking which emails really exist
            // but log that an invalid attempt has been made
            log.warn("Password reset requested for non existing mail");
        }
    }

    /**
     * {@code POST   /account/reset-password/finish} : Finish to reset the password of the user.
     *
     * @param keyAndPassword the generated key and the new password.
     * @throws InvalidPasswordException {@code 400 (Bad Request)} if the password is incorrect.
     * @throws RuntimeException {@code 500 (Internal Server Error)} if the password could not be reset.
     */
    @PostMapping(path = "/account/reset-password/finish")
    public void finishPasswordReset(@RequestBody KeyAndPasswordVM keyAndPassword) {
        if (
            PasswordUtils.isPasswordLengthInvalid(keyAndPassword.getNewPassword()) ||
            !PasswordUtils.checkStrength(keyAndPassword.getNewPassword())
        ) {
            log.warn("Password strength or password length invalid");
            throw new InvalidPasswordException("Password strength or password length invalid");
        }
        Optional<User> user = userService.completePasswordReset(keyAndPassword.getNewPassword(), keyAndPassword.getKey());

        if (!user.isPresent()) {
            throw new AccountResourceException("No user was found for this reset key");
        }
    }
}
