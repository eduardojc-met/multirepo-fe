package com.santander.app.domain;

import java.io.Serializable;
import java.util.Objects;
import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * A Password blacklist element.
 */
@Entity
@Table(name = "jhi_password_blacklist")
public class UserPasswordBlacklist implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @NotNull
    @Size(max = 50)
    @Column(name = "word", length = 50, nullable = false)
    private String word;

    public String getWord() {
        return word;
    }

    public void setWord(String word) {
        this.word = word;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserPasswordBlacklist)) {
            return false;
        }
        return Objects.equals(word, ((UserPasswordBlacklist) o).word);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(word);
    }

    // prettier-ignore
    @Override
    public String toString() {
        return "UserPasswordBlacklist{" +
            "word='" + word + '\'' +
            "}";
    }
}
