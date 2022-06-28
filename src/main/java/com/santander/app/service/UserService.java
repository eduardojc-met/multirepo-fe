package com.santander.app.service;

import com.santander.app.config.ApplicationProperties;
import com.santander.app.config.Constants;
import com.santander.app.domain.Authority;
import com.santander.app.domain.User;
import com.santander.app.domain.UserPasswordHistory;
import com.santander.app.repository.AuthorityRepository;
import com.santander.app.repository.UserPasswordBlacklistRepository;
import com.santander.app.repository.UserPasswordHistoryRepository;
import com.santander.app.repository.UserRepository;
import com.santander.app.security.AuthoritiesConstants;
import com.santander.app.security.SecurityUtils;
import com.santander.app.service.dto.AdminUserDTO;
import com.santander.app.service.dto.UserDTO;
import com.santander.app.service.mapper.UserPasswordHistoryMapper;
import com.santander.app.service.utils.PasswordUtils;
import java.time.Instant;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.jhipster.security.RandomUtil;

/**
 * Service class for managing users.
 */
@Service
@Transactional
public class UserService {

    private final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthorityRepository authorityRepository;

    private final UserPasswordHistoryRepository userPasswordHistoryRepository;

    private final UserPasswordBlacklistRepository userPasswordBlacklistRepository;

    private final UserPasswordHistoryMapper userPasswordHistoryMapper;

    private final ApplicationProperties applicationProperties;

    public UserService(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder,
        AuthorityRepository authorityRepository,
        UserPasswordHistoryRepository userPasswordHistoryRepository,
        UserPasswordBlacklistRepository userPasswordBlacklistRepository,
        UserPasswordHistoryMapper userPasswordHistoryMapper,
        ApplicationProperties applicationProperties
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityRepository = authorityRepository;
        this.userPasswordHistoryRepository = userPasswordHistoryRepository;
        this.userPasswordBlacklistRepository = userPasswordBlacklistRepository;
        this.userPasswordHistoryMapper = userPasswordHistoryMapper;
        this.applicationProperties = applicationProperties;
    }

    public Optional<User> activateRegistration(String key) {
        log.debug("Activating user for activation key {}", key);
        return userRepository
            .findOneByActivationKey(key)
            .map(user -> {
                // activate given user for the registration key.
                user.setActivated(true);
                user.setActivationKey(null);
                log.debug("Activated user: {}", user);
                return user;
            });
    }

    public Optional<User> completePasswordReset(String newPassword, String key) {
        log.debug("Reset user password for reset key {}", key);
        return userRepository
            .findOneByResetKey(key)
            .filter(user -> user.getResetDate().isAfter(Instant.now().minus(1, ChronoUnit.DAYS)))
            .map(user -> {
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setResetKey(null);
                user.setResetDate(Instant.now());
                if (passwordIsInBlacklist(user.getPassword())) {
                    log.warn("Password not valid. Common used password");
                    throw new InvalidPasswordException("Password not valid. Common used password");
                } else if (!userPasswordHistoryRepository.passwordNotAlreadyUsed(user.getId(), user.getPassword())) {
                    log.warn("Password already used");
                    throw new InvalidPasswordException("Password already used");
                } else {
                    log.info("Password not used yet for user {} " + user.getId());
                    userPasswordHistoryRepository.saveAndFlush(userPasswordHistoryMapper.userToUserPasswordHistory(user));
                }
                return user;
            });
    }

    public Optional<User> requestPasswordReset(String mail) {
        return userRepository
            .findOneByEmailIgnoreCase(mail)
            .filter(User::isActivated)
            .map(user -> {
                user.setResetKey(RandomUtil.generateResetKey());
                user.setResetDate(Instant.now());
                return user;
            });
    }

    public User registerUser(AdminUserDTO userDTO, String password) {
        userRepository
            .findOneByLogin(userDTO.getLogin().toLowerCase())
            .ifPresent(existingUser -> {
                boolean removed = removeNonActivatedUser(existingUser);
                if (!removed) {
                    throw new UsernameAlreadyUsedException();
                }
            });
        userRepository
            .findOneByEmailIgnoreCase(userDTO.getEmail())
            .ifPresent(existingUser -> {
                boolean removed = removeNonActivatedUser(existingUser);
                if (!removed) {
                    throw new EmailAlreadyUsedException();
                }
            });
        User newUser = new User();
        String encryptedPassword = passwordEncoder.encode(password);
        newUser.setLogin(userDTO.getLogin().toLowerCase());
        // new user gets initially a generated password
        newUser.setPassword(encryptedPassword);
        newUser.setFirstName(userDTO.getFirstName());
        newUser.setLastName(userDTO.getLastName());
        if (userDTO.getEmail() != null) {
            newUser.setEmail(userDTO.getEmail().toLowerCase());
        }
        newUser.setImageUrl(userDTO.getImageUrl());
        newUser.setLangKey(userDTO.getLangKey());
        // new user is not active
        newUser.setActivated(false);
        // new user gets registration key
        newUser.setActivationKey(RandomUtil.generateActivationKey());
        newUser.setResetDate(Instant.now());
        Set<Authority> authorities = new HashSet<>();
        authorityRepository.findById(AuthoritiesConstants.USER).ifPresent(authorities::add);
        newUser.setAuthorities(authorities);
        userRepository.save(newUser);
        log.debug("Created Information for User: {}", newUser);
        return newUser;
    }

    private boolean removeNonActivatedUser(User existingUser) {
        if (existingUser.isActivated()) {
            return false;
        }
        deleteUserPasswordHistory(existingUser);
        userRepository.delete(existingUser);
        userRepository.flush();
        return true;
    }

    public User createUser(AdminUserDTO userDTO) {
        User user = new User();
        user.setLogin(userDTO.getLogin().toLowerCase());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        if (userDTO.getEmail() != null) {
            user.setEmail(userDTO.getEmail().toLowerCase());
        }
        user.setImageUrl(userDTO.getImageUrl());
        if (userDTO.getLangKey() == null) {
            user.setLangKey(Constants.DEFAULT_LANGUAGE); // default language
        } else {
            user.setLangKey(userDTO.getLangKey());
        }
        String encryptedPassword = passwordEncoder.encode(RandomUtil.generatePassword());
        user.setPassword(encryptedPassword);
        user.setResetKey(RandomUtil.generateResetKey());
        user.setResetDate(Instant.now());
        user.setActivated(true);
        if (userDTO.getAuthorities() != null) {
            Set<Authority> authorities = userDTO
                .getAuthorities()
                .stream()
                .map(authorityRepository::findById)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toSet());
            user.setAuthorities(authorities);
        }
        userRepository.save(user);
        log.debug("Created Information for User: {}", user);
        return user;
    }

    /**
     * Update all information for a specific user, and return the modified user.
     *
     * @param userDTO user to update.
     * @return updated user.
     */
    public Optional<AdminUserDTO> updateUser(AdminUserDTO userDTO) {
        return Optional
            .of(userRepository.findById(Long.valueOf(userDTO.getId())))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .map(user -> {
                user.setLogin(userDTO.getLogin().toLowerCase());
                user.setFirstName(userDTO.getFirstName());
                user.setLastName(userDTO.getLastName());
                if (userDTO.getEmail() != null) {
                    user.setEmail(userDTO.getEmail().toLowerCase());
                }
                user.setImageUrl(userDTO.getImageUrl());
                user.setActivated(userDTO.isActivated());
                user.setLangKey(userDTO.getLangKey());
                Set<Authority> managedAuthorities = user.getAuthorities();
                managedAuthorities.clear();
                userDTO
                    .getAuthorities()
                    .stream()
                    .map(authorityRepository::findById)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .forEach(managedAuthorities::add);
                log.debug("Changed Information for User: {}", user);
                return user;
            })
            .map(AdminUserDTO::new);
    }

    public void deleteUser(String login) {
        userRepository
            .findOneByLogin(login)
            .ifPresent(user -> {
                deleteUserPasswordHistory(user);
                userRepository.delete(user);
                log.debug("Deleted User: {}", user);
            });
    }

    /**
     * Update basic information (first name, last name, email, language) for the current user.
     *
     * @param firstName first name of user.
     * @param lastName  last name of user.
     * @param email     email id of user.
     * @param langKey   language key.
     * @param imageUrl  image URL of user.
     */
    public void updateUser(String firstName, String lastName, String email, String langKey, String imageUrl) {
        SecurityUtils
            .getCurrentUserLogin()
            .flatMap(userRepository::findOneByLogin)
            .ifPresent(user -> {
                user.setFirstName(firstName);
                user.setLastName(lastName);
                if (email != null) {
                    user.setEmail(email.toLowerCase());
                }
                user.setLangKey(langKey);
                user.setImageUrl(imageUrl);
                log.debug("Changed Information for User: {}", user);
            });
    }

    private void deleteUserPasswordHistory(User user) {
        List<UserPasswordHistory> found = userPasswordHistoryRepository.findAllByUserId(user.getId());
        userPasswordHistoryRepository.deleteAll(found);
        log.debug("Historic passwords deleted: {}", found);
    }

    @Transactional
    public void changePassword(String currentClearTextPassword, String newPassword) {
        SecurityUtils
            .getCurrentUserLogin()
            .flatMap(userRepository::findOneByLogin)
            .ifPresent(user -> {
                String currentEncryptedPassword = user.getPassword();
                if (passwordEncoder.matches(newPassword, currentEncryptedPassword)) {
                    log.warn("Password already used");
                    throw new InvalidPasswordException("Password already used");
                } else if (!PasswordUtils.isStringDistanceMetricValid(currentClearTextPassword, newPassword)) {
                    log.warn("New password is similar to the current one");
                    throw new InvalidPasswordException("New password is similar to the current one");
                } else if (isPasswordAlreadyUsed(newPassword, user)) {
                    log.warn("Password already used for user {} ", user.getId());
                    throw new InvalidPasswordException("Password already used");
                } else if (passwordIsInBlacklist(newPassword)) {
                    log.warn("Password not valid. Common used password");
                    throw new InvalidPasswordException("Password not valid. Common used password");
                }
                String encryptedPassword = passwordEncoder.encode(newPassword);
                user.setPassword(encryptedPassword);

                userPasswordHistoryRepository.saveAndFlush(userPasswordHistoryMapper.userToUserPasswordHistory(user));

                user.setResetDate(Instant.now());
                log.debug("Changed password for User: {}", user);
            });
    }

    private boolean isPasswordAlreadyUsed(String newPassword, User user) {
        final List<String> passUsed = userPasswordHistoryRepository.findAllPasswordHashesByUserLastYear(user.getId());
        for (final String passwordUsed : passUsed) {
            if (passwordEncoder.matches(newPassword, passwordUsed)) {
                return true;
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public Page<AdminUserDTO> getAllManagedUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(AdminUserDTO::new);
    }

    @Transactional(readOnly = true)
    public Page<UserDTO> getAllPublicUsers(Pageable pageable) {
        return userRepository.findAllByIdNotNullAndActivatedIsTrue(pageable).map(UserDTO::new);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthoritiesByLogin(String login) {
        return userRepository.findOneWithAuthoritiesByLogin(login);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities() {
        return SecurityUtils.getCurrentUserLogin().flatMap(userRepository::findOneWithAuthoritiesByLogin);
    }

    /**
     * Not activated users should be automatically deleted after 3 days.
     * <p>
     * This is scheduled to get fired everyday, at 01:00 (am).
     */
    @Scheduled(cron = "0 0 1 * * ?")
    public void removeNotActivatedUsers() {
        userRepository
            .findAllByActivatedIsFalseAndActivationKeyIsNotNullAndCreatedDateBefore(Instant.now().minus(3, ChronoUnit.DAYS))
            .forEach(user -> {
                log.debug("Deleting not activated user {}", user.getLogin());
                deleteUserPasswordHistory(user);
                userRepository.delete(user);
            });
    }

    /**
     * Gets a list of all the authorities.
     * @return a list of all the authorities.
     */
    @Transactional(readOnly = true)
    public List<String> getAuthorities() {
        return authorityRepository.findAll().stream().map(Authority::getName).collect(Collectors.toList());
    }

    @Transactional(noRollbackFor = { LockedException.class })
    public void manageFailedAttempts(String login) {
        userRepository
            .findOneByLogin(login)
            .ifPresent(user -> {
                if (user.isActivated() && user.isAccountNonLocked()) {
                    log.warn("User " + login + " failed attempt");
                    if (user.getFailedAttempt() < (applicationProperties.getPasswordMaxFailedAttempts() - 1)) {
                        log.warn("User " + login + " failed attempts is going to be increased: " + (user.getFailedAttempt() + 1));
                        userRepository.updateFailedAttempts(user.getFailedAttempt() + 1, user.getLogin());
                    } else {
                        log.warn("User account " + login + " is going to be locked.");
                        user.setAccountNonLocked(false);
                        user.setLockTime(Instant.now());
                        user.setLastModifiedBy("failedAttempts");
                        userRepository.save(user);
                        throw new LockedException(
                            "Your account has been locked due to " +
                            applicationProperties.getPasswordMaxFailedAttempts() +
                            " failed attempts." +
                            " It will be unlocked after " +
                            (applicationProperties.getPasswordLockTimeDurationMillis() / (60 * 60 * 1000)) +
                            " hours."
                        );
                    }
                } else if (!user.isAccountNonLocked()) {
                    if (unlockWhenTimeExpired(user)) {
                        log.info("User account " + login + " is going to be unlocked.");
                        throw new LockedException("Your account has been unlocked. Please try to login again.");
                    } else {
                        log.warn(
                            "User account " +
                            login +
                            " has been locked due to" +
                            applicationProperties.getPasswordMaxFailedAttempts() +
                            " failed attempts."
                        );
                        throw new LockedException(
                            "Your account has been locked due to " +
                            applicationProperties.getPasswordMaxFailedAttempts() +
                            " failed attempts." +
                            " It will be unlocked after " +
                            (applicationProperties.getPasswordLockTimeDurationMillis() / (60 * 60 * 1000)) +
                            " hours."
                        );
                    }
                }
            });
    }

    public void resetFailedAttempts(String login) {
        userRepository.updateFailedAttempts(0, login);
    }

    public void lock(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(Instant.now());
        userRepository.save(user);
    }

    public boolean unlockWhenTimeExpired(User user) {
        long lockTimeInMillis = user.getLockTime().toEpochMilli();
        long currentTimeInMillis = System.currentTimeMillis();

        if (lockTimeInMillis + applicationProperties.getPasswordLockTimeDurationMillis() < currentTimeInMillis) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedAttempt(0);
            user.setLastModifiedBy("failedAttempts");
            return true;
        }
        return false;
    }

    public String getPasswordExpired(String username) {
        String result = null;
        final Optional<User> user = userRepository.findOneByLogin(username);
        if (user.isPresent()) {
            if (null == user.get().getResetDate()) {
                user.get().setResetDate(Instant.now());
            }
            final Instant resetDate = user.get().getResetDate().plus(45, ChronoUnit.DAYS);
            long daysLeft = TimeUnit.SECONDS.toDays(resetDate.minusSeconds(Instant.now().getEpochSecond()).getEpochSecond());
            if (daysLeft < 0) {
                user.get().setActivated(false);
                throw new ExpiredPasswordException();
            } else if (daysLeft <= 15) {
                result = Constants.PASSWORD_EXPIRED_MESSAGE.replace("{days}", String.valueOf(daysLeft));
            }
        }
        return result;
    }

    private boolean passwordIsInBlacklist(final String password) {
        final List<String> blacklist = userPasswordBlacklistRepository
            .findAll()
            .stream()
            .map(item -> item.getWord())
            .collect(Collectors.toList());
        return stringContainsItemFromList(password.toLowerCase(), blacklist);
    }

    private static boolean stringContainsItemFromList(final String inputStr, final List<String> items) {
        return items.stream().anyMatch(inputStr::contains);
    }
}
