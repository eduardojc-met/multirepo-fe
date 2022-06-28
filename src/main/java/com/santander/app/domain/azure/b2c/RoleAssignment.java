package com.santander.app.domain.azure.b2c;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RoleAssignment {

    private String id;
    private String appRoleId;
    private String principalId;
    private String resourceId;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAppRoleId() {
        return appRoleId;
    }

    public void setAppRoleId(String appRoleId) {
        this.appRoleId = appRoleId;
    }

    public String getPrincipalId() {
        return principalId;
    }

    public void setPrincipalId(String principalId) {
        this.principalId = principalId;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    @Override
    public String toString() {
        return (
            "RoleAssignment{" +
            "id='" +
            id +
            '\'' +
            ", appRoleId='" +
            appRoleId +
            '\'' +
            ", principalId='" +
            principalId +
            '\'' +
            ", resourceId='" +
            resourceId +
            '\'' +
            '}'
        );
    }
}
