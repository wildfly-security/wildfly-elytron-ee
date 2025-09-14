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
public class AuthorizarionRegistration {

    /**
     * Perform any static registration for Jakarta Authorization.
     *
     * @return {@code true} if successful, {@code false} otherwise.
     */
    public static boolean register() {
        return true;
    }

}
