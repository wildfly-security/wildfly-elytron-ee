/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

/**
 * Utility to enable registration for Jakarta Authorization.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthorizationRegistration {

    /**
     * Perform any static registration for Jakarta Authorization.
     *
     * @return {@code true} if this method supports dynamic registration and completes it successfully,
     * {@code false} if this method does not support dynamic registration.
     * @throws {@code SecurityException} if dynamic registration is attempted but fails.
     */
    public static boolean register() throws SecurityException {
        // By default we do not support dynamic registration.
        return false;
    }

}
