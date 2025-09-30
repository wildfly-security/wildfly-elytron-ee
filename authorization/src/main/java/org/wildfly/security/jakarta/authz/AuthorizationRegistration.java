/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import java.security.GeneralSecurityException;

/**
 * Utility to enable registration for Jakarta Authorization.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthorizationRegistration {

    /**
     * Check if this implementation supports self registration.
     *
     * This is required as an application server may depend on different versions
     * of this library, some of which do support self registration and others that
     * do not.
     *
     * @return {@code true} if this supports self registration, false otherwise.
     */
    public static boolean supportsSelfRegistration() {
        // By default we do not support dynamic registration.
        return false;
    }

    /**
     * Perform any static registration for Jakarta Authorization.
     *
     * If this method is called and the implementation does not support self registration
     * this method should return without error.
     *
     * @throws {@code GeneralSecurityException} if dynamic registration is attempted but fails.
     */
    public static void register() throws GeneralSecurityException {}

}
