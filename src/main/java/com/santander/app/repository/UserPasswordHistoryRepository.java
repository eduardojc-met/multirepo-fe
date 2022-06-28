package com.santander.app.repository;

import com.santander.app.domain.UserPasswordHistory;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Spring Data JPA repository for the {@link UserPasswordHistory} entity.
 */
public interface UserPasswordHistoryRepository extends JpaRepository<UserPasswordHistory, Long> {
    List<UserPasswordHistory> findAllByUserId(Long userId);

    @Query(
        value = "select not exists (select from public.jhi_user_password_history " +
        "where jhi_user_password_history.user_id = :userId " +
        "and jhi_user_password_history.password_hash = :password " +
        "and date(jhi_user_password_history.reset_date) >= current_date - 365)",
        nativeQuery = true
    )
    boolean passwordNotAlreadyUsed(@Param(value = "userId") Long userId, @Param(value = "password") String password);

    @Query(
        value = "select password_hash from public.jhi_user_password_history " +
        "where jhi_user_password_history.user_id = :userId " +
        "and date(jhi_user_password_history.reset_date) >= current_date - 365",
        nativeQuery = true
    )
    List<String> findAllPasswordHashesByUserLastYear(@Param(value = "userId") Long userId);
}
