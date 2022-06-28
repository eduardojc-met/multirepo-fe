package com.santander.app.repository;

import com.santander.app.domain.UserPasswordBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for the {@link UserPasswordBlacklist} entity.
 */
public interface UserPasswordBlacklistRepository extends JpaRepository<UserPasswordBlacklist, String> {}
