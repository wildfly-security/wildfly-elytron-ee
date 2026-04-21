/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.authz.jacc;

import java.security.Permission;

/**
 * Utility for checking if a permission is unchecked according to Jakarta Authorization Policy.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class UncheckedPolicyUtil {

    private UncheckedPolicyUtil() {
        // Not available in Jakarta EE 10 / Jakarta Authorization 2.x
    }

    /**
     * Get the singleton instance.
     *
     * @return null for Jakarta EE 10 (Authorization 2.x does not support isUnchecked)
     */
    public static UncheckedPolicyUtil getInstance() {
        return null;
    }

    /**
     * Not supported in this version.
     *
     * @throws UnsupportedOperationException always
     */
    public boolean isUnchecked(Permission permission) {
        throw new UnsupportedOperationException("Policy.isUnchecked() not available in Jakarta Authorization 2.x");
    }
}
