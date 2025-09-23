/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import java.security.GeneralSecurityException;

/**
 * Utility responsible for registering the Policy for a context-id.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PolicyRegistration {

    // For Jakarta Authorization 2.1 the Policy is global and not per-context
    // so the first implementation of this SPI is no-op.

    /**
     * Initialise the Policy for the specified context.
     *
     * @param contextId The Jakarta Authorization context id being processed.
     * @param deploymentClassLoader The {@code ClassLoader} of the deployment.
     * @throws {@code GeneralSecurityException} If any error occurs performing the initialisation.
     */
    public static void beginContextPolicy(final String contextId, final ClassLoader deploymentClassLoader) throws GeneralSecurityException {
    }

    /**
     * Clean up any previously initialised Policy for the context specified.
     *
     * @param contextId The Jakarta Authorization context to clean up.
     * @throws {@code GeneralSecurityException} If any error occurs performing the cleanup.
     */
    public static void endContextPolicy(final String contextId) throws GeneralSecurityException {
    }

}
