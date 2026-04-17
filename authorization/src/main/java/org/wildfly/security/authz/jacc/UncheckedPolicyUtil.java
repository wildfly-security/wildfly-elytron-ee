/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.authz.jacc;

import java.security.Permission;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyFactory;
import org.jboss.logging.Logger;

/**
 * Utility for checking if a permission is unchecked according to Jakarta Authorization 3.0 Policy.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class UncheckedPolicyUtil {

    private static final Logger log = Logger.getLogger(UncheckedPolicyUtil.class);
    private static final UncheckedPolicyUtil INSTANCE = new UncheckedPolicyUtil();

    private UncheckedPolicyUtil() {
    }

    /**
     * Get the singleton instance.
     *
     * @return the instance for Jakarta EE 11 (Authorization 3.0 supports isUnchecked)
     */
    public static UncheckedPolicyUtil getInstance() {
        return INSTANCE;
    }

    /**
     * Check if the given permission is unchecked according to the currently active Policy.
     *
     * Note: This method calls PolicyFactory.getPolicyFactory().getPolicy() on each invocation
     * to respect runtime Policy changes (e.g., TCK tests that swap Policy implementations).
     *
     * @param permission the permission to check
     * @return true if the permission is unchecked (grants access to unauthenticated callers), false otherwise
     */
    public boolean isUnchecked(Permission permission) {
        PolicyFactory policyFactory = null;
        try {
            policyFactory = PolicyFactory.getPolicyFactory();
        } catch (Exception e) {
            log.warnf(e, "Unable to obtain Jakarta Authorization PolicyFactory instance");
            return false; // Fail closed
        }

        if (policyFactory == null) {
            log.debugf("PolicyFactory not available, treating permission as checked: %s", permission);
            return false; // Fail closed
        }

        Policy policy = null;
        try {
            policy = policyFactory.getPolicy();
        } catch (Exception e) {
            log.warnf(e, "Unable to obtain Jakarta Authorization Policy instance");
            return false; // Fail closed
        }

        if (policy == null) {
            log.debugf("Policy not available, treating permission as checked: %s", permission);
            return false; // Fail closed
        }

        try {
            return policy.isUnchecked(permission);
        } catch (Exception e) {
            log.warnf(e, "Error checking if permission is unchecked: %s", permission);
            return false; // Fail closed - require authentication on error
        }
    }
}
