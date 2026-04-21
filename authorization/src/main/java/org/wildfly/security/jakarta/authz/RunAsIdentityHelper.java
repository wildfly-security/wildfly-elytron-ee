/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.authz.jacc.ElytronEEMessages;

/**
 * Helper utility for resolving and loading RunAs identities in Jakarta EE environments.
 * <p>
 * Jakarta EE 11 implementation - returns new instance per call to enable per-deployment
 * state tracking (warn-once pattern, future caching).
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RunAsIdentityHelper {

    private static final String ANONYMOUS_PRINCIPAL = "anonymous";

    /**
     * Tracks principals that have already been warned about (warn-once pattern).
     * Resets on deployment reload (new helper instance).
     */
    private final Set<String> warnedPrincipals = ConcurrentHashMap.newKeySet();

    /**
     * Package-private constructor for per-deployment instance creation.
     */
    RunAsIdentityHelper() {
    }

    /**
     * Obtain a RunAsIdentityHelper instance.
     * <p>
     * Jakarta EE 11 implementation returns a NEW instance for each call,
     * enabling per-deployment state tracking (warn-once, future caching).
     *
     * @return a new helper instance
     */
    public static RunAsIdentityHelper getInstance() {
        return new RunAsIdentityHelper();
    }

    /**
     * Resolve the effective principal name for a @RunAs annotation.
     * <p>
     * Jakarta EE 11 specification default: role name = principal name when no explicit override.
     *
     * @param runAsRoleName The role name from @RunAs annotation
     * @param explicitPrincipal Explicit principal from @RunAsPrincipal or deployment descriptor (nullable)
     * @return The principal name to use for identity loading
     */
    public String resolveRunAsPrincipal(String runAsRoleName, String explicitPrincipal) {
        // If explicit principal is configured, use it
        if (explicitPrincipal != null && !explicitPrincipal.isEmpty()) {
            return explicitPrincipal;
        }

        // Jakarta EE 11 spec default: role name = principal name
        return runAsRoleName;
    }

    /**
     * Load a SecurityIdentity from the security domain for RunAs.
     * <p>
     * Jakarta EE 11 implementation: Loads complete identity from security domain with all roles,
     * then adds the persona role for backward compatibility. If principal doesn't exist,
     * creates ad-hoc identity with persona role and warns once per deployment.
     *
     * @param securityDomain The current security domain
     * @param principalName The principal name to load
     * @param runAsRoleName The role name from @RunAs (persona designation)
     * @return SecurityIdentity for the RunAs principal with all domain roles + persona role
     * @throws RealmUnavailableException if the realm is not available
     */
    public SecurityIdentity loadRunAsIdentity(
            SecurityDomain securityDomain,
            String principalName,
            String runAsRoleName) throws RealmUnavailableException {

        // Handle anonymous special case
        if (ANONYMOUS_PRINCIPAL.equals(principalName)) {
            return securityDomain.getCurrentSecurityIdentity().createRunAsAnonymous();
        }

        SecurityIdentity currentIdentity = securityDomain.getCurrentSecurityIdentity();

        // Check if principal exists in security domain
        if (principalExists(securityDomain, principalName)) {
            // Principal exists - load complete identity with all domain roles
            // createRunAsIdentity internally uses ServerAuthenticationContext to load from realm
            SecurityIdentity loadedIdentity = currentIdentity.createRunAsIdentity(principalName, false);

            // Add persona role for backward compatibility (union with domain roles)
            return addPersonaRole(loadedIdentity, runAsRoleName);
        } else {
            // Principal doesn't exist - warn ONCE per deployment, then create ad-hoc + persona role
            if (warnedPrincipals.add(principalName)) {
                ElytronEEMessages.eeLog.runAsPrincipalNotFoundInDomain(principalName, runAsRoleName);
            }

            // Create ad-hoc identity (has principal name, no domain roles)
            SecurityIdentity adHocIdentity = securityDomain.createAdHocIdentity(principalName);

            // Add persona role for basic authorization
            return addPersonaRole(adHocIdentity, runAsRoleName);
        }
    }

    /**
     * Check if a principal exists in the security domain.
     *
     * @param securityDomain The security domain to check
     * @param principalName The principal name to check
     * @return true if the principal exists in the security domain
     * @throws RealmUnavailableException if the realm is not available
     */
    private boolean principalExists(SecurityDomain securityDomain, String principalName)
            throws RealmUnavailableException {
        RealmIdentity realmIdentity = null;
        try {
            realmIdentity = securityDomain.getIdentity(principalName);
            return realmIdentity.exists();
        } finally {
            if (realmIdentity != null) {
                realmIdentity.dispose();
            }
        }
    }

    /**
     * Add the persona role to a SecurityIdentity for backward compatibility.
     * <p>
     * The persona role (from @RunAs annotation) is added to the identity's roles
     * in addition to any roles loaded from the security domain. If the role already
     * exists, it is not duplicated (union operation).
     *
     * @param baseIdentity The identity to add the role to
     * @param runAsRoleName The persona role name
     * @return Identity with persona role added (union with existing roles)
     */
    private SecurityIdentity addPersonaRole(SecurityIdentity baseIdentity, String runAsRoleName) {
        // Check if persona role already present in loaded identity
        if (baseIdentity.getRoles().contains(runAsRoleName)) {
            // Already present, no need to add
            return baseIdentity;
        }

        // Create role mapper that adds persona role to existing roles
        // constant() creates mapper that returns only the persona role
        RoleMapper personaRoleMapper = RoleMapper.constant(Roles.of(runAsRoleName));

        // Combine with identity mapper (preserves existing roles) using OR (union)
        // withDefaultRoleMapper() wraps the default roles with additional mapping
        return baseIdentity.withDefaultRoleMapper(
            personaRoleMapper.or(RoleMapper.IDENTITY_ROLE_MAPPER)
        );
    }
}
