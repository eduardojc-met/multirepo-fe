package com.santander.app.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.io.Serializable;
import java.time.Instant;
import javax.persistence.*;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "jhi_user_password_history")
public class UserPasswordHistory extends AbstractAuditingEntity implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
        foreignKey = @ForeignKey(name = "fk_user_id_user_password_history"),
        name = "user_id",
        insertable = false,
        updatable = false,
        referencedColumnName = "id"
    )
    private User user;

    @NotNull
    @Column(name = "user_id", length = 50, nullable = false)
    private Long userId;

    @JsonIgnore
    @NotNull
    @Column(name = "password_hash", length = 60, nullable = false)
    private String password;

    @Column(name = "reset_date")
    private Instant resetDate = null;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Instant getResetDate() {
        return resetDate;
    }

    public void setResetDate(Instant resetDate) {
        this.resetDate = resetDate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserPasswordHistory)) {
            return false;
        }
        return id != null && id.equals(((UserPasswordHistory) o).id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
