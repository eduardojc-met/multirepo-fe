package com.santander.app.domain.azure.b2c;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Arrays;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AppRoleAssignments {

    @JsonProperty("value")
    private RoleAssignment[] roleAssignments;

    public RoleAssignment[] getRoleAssignments() {
        return roleAssignments;
    }

    public void setRoleAssignments(RoleAssignment[] roleAssignments) {
        this.roleAssignments = roleAssignments;
    }

    @Override
    public String toString() {
        return "AppRoleAssignments{" + "roleAssignments=" + Arrays.toString(roleAssignments) + '}';
    }
}
