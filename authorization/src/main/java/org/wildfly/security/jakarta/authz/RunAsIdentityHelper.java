/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.AuthorizationFailureException;

/**
 * Helper utility for resolving and loading RunAs identities in Jakarta EE environments.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RunAsIdentityHelper {

    private static final String ANONYMOUS_PRINCIPAL = "anonymous";

    /**
     * Singleton instance.
     */
    private static final RunAsIdentityHelper INSTANCE = new RunAsIdentityHelper();

    /**
     * Private constructor for singleton pattern.
     */
    private RunAsIdentityHelper() {
    }

    /**
     * Obtain a RunAsIdentityHelper instance.
     *
     * @return the helper instance
     */
    public static RunAsIdentityHelper getInstance() {
        return INSTANCE;
    }

    /**
     * Resolve the effective principal name for a @RunAs annotation.
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

        // Default to "anonymous" when no explicit principal
        return ANONYMOUS_PRINCIPAL;
    }

    /**
     * Load a SecurityIdentity from the security domain for RunAs.
     *
     * @param securityDomain The current security domain
     * @param principalName The principal name to load
     * @param runAsRoleName The role name from @RunAs
     * @return SecurityIdentity for the RunAs principal
     * @throws RealmUnavailableException if the realm is not available
     */
    public SecurityIdentity loadRunAsIdentity(
            SecurityDomain securityDomain,
            String principalName,
            String runAsRoleName) throws RealmUnavailableException {

        SecurityIdentity currentIdentity = securityDomain.getCurrentSecurityIdentity();

        // Handle anonymous special case
        if (ANONYMOUS_PRINCIPAL.equals(principalName)) {
            // Try with authorization check first, fall back to skipping check if not authorized
            // This maintains backwards compatibility with environments that don't have authorization configured
            try {
                return currentIdentity.createRunAsAnonymous();
            } catch (AuthorizationFailureException ex) {
                return currentIdentity.createRunAsAnonymous(false);
            }
        }

        // Check if principal exists, create ad-hoc identity if not, otherwise switch principal
        if (!principalExists(securityDomain, principalName)) {
            return securityDomain.createAdHocIdentity(principalName);
        }

        return currentIdentity.createRunAsIdentity(principalName, false);
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
}
