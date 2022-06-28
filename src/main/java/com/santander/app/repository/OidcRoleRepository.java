package com.santander.app.repository;

import com.santander.app.domain.azure.b2c.OidcRole;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for the {@link OidcRole} entity.
 */
public interface OidcRoleRepository extends JpaRepository<OidcRole, String> {}
