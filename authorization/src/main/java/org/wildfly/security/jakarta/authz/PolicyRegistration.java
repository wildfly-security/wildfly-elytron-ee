/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

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
     * @throws SecurityException If any error occurs performing the initialsiation.
     */
    public static void beginContextPolicy(final String contextId, final ClassLoader deploymentClassLoader) throws SecurityException {
    }

    /**
     * Clean up any previously initialised Policy for the context specified.
     *
     * @param contextId The Jakarta Authorization context to clean up.
     * @throws SecurityException If any error occurs performing the cleanup.
     */
    public static void endContextPolicy(final String contextId) throws SecurityException {
    }

}
