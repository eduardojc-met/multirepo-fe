package com.santander.app.domain.azure.b2c;

import java.io.Serializable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "jhi_oidc_b2c_roles")
public class OidcRole implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotNull
    @Id
    private long id;

    @NotNull
    @Size(max = 50)
    @Column(length = 50, name = "provider_id")
    private String providerId;

    @NotNull
    @Size(max = 50)
    @Column(length = 50, name = "role_name")
    private String name;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getProviderId() {
        return providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        OidcRole oidcRole = (OidcRole) o;

        if (id != oidcRole.id) return false;
        if (providerId != null ? !providerId.equals(oidcRole.providerId) : oidcRole.providerId != null) return false;
        return name != null ? name.equals(oidcRole.name) : oidcRole.name == null;
    }

    @Override
    public int hashCode() {
        int result = (int) (id ^ (id >>> 32));
        result = 31 * result + (providerId != null ? providerId.hashCode() : 0);
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "OidcRole{" + "id=" + id + ", providerId='" + providerId + '\'' + ", name='" + name + '\'' + '}';
    }
}
