/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.authz.jacc;

import static jakarta.security.jacc.PolicyContext.PRINCIPAL_MAPPER;
import static org.wildfly.security.authz.jacc.ElytronMessages.log;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import jakarta.security.jacc.EJBMethodPermission;
import jakarta.security.jacc.EJBRoleRefPermission;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PrincipalMapper;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;
import jakarta.security.jacc.WebUserDataPermission;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * <p>A {@link Policy} implementation that knows how to process JACC permissions.
 *
 * <p>Elytron's JakartaAuthorization implementation is fully integrated with the Permission Mapping API, which allows users to specify custom permissions
 * for a {@link SecurityDomain} and its identities by configuring a {@link org.wildfly.security.authz.PermissionMapper}. In this case,
 * the permissions are evaluated considering both JACC-specific permissions (as defined by the specs) and also the ones associated with the current
 * and authorized {@link SecurityIdentity}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronPolicy implements Policy {

    private static final String ANY_AUTHENTICATED_USER_ROLE = "**";
    private final Set<Class<? extends Permission>> supportedPermissionTypes = new HashSet<>();

    /**
     * Create a new instance.
     *
     */
    public ElytronPolicy() {
        this.supportedPermissionTypes.add(WebResourcePermission.class);
        this.supportedPermissionTypes.add(WebRoleRefPermission.class);
        this.supportedPermissionTypes.add(WebUserDataPermission.class);
        this.supportedPermissionTypes.add(EJBMethodPermission.class);
        this.supportedPermissionTypes.add(EJBRoleRefPermission.class);
    }

    @Override
    public boolean implies(Permission permission, Subject subject) {
        PrincipalMapper principalMapper = PolicyContext.get(PRINCIPAL_MAPPER);
        Principal principal = principalMapper.getCallerPrincipal(subject);

        if (principal == null) {
            return false;
        }

        try {
            if (isJaccPermission(permission)) {
                ElytronPolicyConfiguration policyConfiguration = ElytronPolicyConfigurationFactory.getCurrentPolicyConfiguration();

                if (impliesExcludedPermission(permission, policyConfiguration)) {
                    return false;
                }

                if (impliesUncheckedPermission(permission, policyConfiguration)) {
                    return true;
                }

                if (impliesRolePermission(subject, permission, policyConfiguration)) {
                    return true;
                }
            }

            // We can now check all permissions here as we are no longer intercepting
            // SecurityManager permission checks.
            if (impliesIdentityPermission(permission)) {
                return true;
            }

        } catch (Exception e) {
            log.authzFailedToCheckPermission(principal, permission, e);
        }

        return false;
    }

    @Override
    public PermissionCollection getPermissionCollection(Subject subject) {
        return new PermissionCollection() {
            @Override
            public void add(Permission permission) {
                throw ElytronMessages.log.readOnlyPermissionCollection();
            }

            @Override
            public boolean implies(Permission permission) {
                return ElytronPolicy.this.implies(permission, subject);
            }

            @Override
            public Enumeration<Permission> elements() {
                return Collections.emptyEnumeration();
            }
        };
    }

    private boolean impliesIdentityPermission(Permission permission) {
        SecurityIdentity actualIdentity = getCurrentSecurityIdentity();
        return actualIdentity != null && actualIdentity.implies(permission);
    }

    private SecurityIdentity getCurrentSecurityIdentity() {
        try {
            return (SecurityIdentity) PolicyContext.getContext(SecurityIdentityHandler.KEY);
        } catch (Exception cause) {
            log.authzCouldNotObtainSecurityIdentity(cause);
        }

        return null;
    }

    private boolean impliesRolePermission(Subject subject, Permission permission, ElytronPolicyConfiguration policyConfiguration) throws PolicyContextException, ClassNotFoundException {
        PrincipalMapper principalMapper = PolicyContext.get(PRINCIPAL_MAPPER);
        Set<String> roles = principalMapper.getMappedRoles(subject);

        roles.add(ANY_AUTHENTICATED_USER_ROLE);

        Map<String, PermissionCollection> rolePermissions = policyConfiguration.getPerRolePermissions();

        synchronized (rolePermissions) {
            for (String roleName : roles) {
                PermissionCollection permissions = rolePermissions.get(roleName);

                if (permissions != null) {
                    if (permissions.implies(permission)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private boolean impliesUncheckedPermission(Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        PermissionCollection uncheckedPermissions = policyConfiguration.getUncheckedPermissions();

        synchronized (uncheckedPermissions) {
            return uncheckedPermissions.implies(permission);
        }
    }

    private boolean impliesExcludedPermission(Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        PermissionCollection excludedPermissions = policyConfiguration.getExcludedPermissions();

        synchronized (excludedPermissions) {
            return excludedPermissions.implies(permission);
        }
    }

    private boolean isJaccPermission(Permission permission) {
        return this.supportedPermissionTypes.contains(permission.getClass());
    }
}

