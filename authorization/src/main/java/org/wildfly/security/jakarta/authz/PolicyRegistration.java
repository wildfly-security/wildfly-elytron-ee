/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import java.security.GeneralSecurityException;

import jakarta.security.jacc.PolicyFactory;

/**
 * Utility responsible for registering the Policy for a context-id.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PolicyRegistration {

    /**
     * Initialise the Policy for the specified context.
     *
     * @param contextId The Jakarta Authorization context id being processed.
     * @param deploymentClassLoader The {@code ClassLoader} of the deployment.
     * @throws {@code GeneralSecurityException} If any error occurs performing the initialisation.
     */
    public static void beginContextPolicy(final String contextId, final ClassLoader deploymentClassLoader) throws GeneralSecurityException {
        // By default allow all contexts to fall back to the default Policy.
    }

    /**
     * Clean up any previously initialised Policy for the context specified.
     *
     * @param contextId The Jakarta Authorization context to clean up.
     * @throws {@code GeneralSecurityException} If any error occurs performing the cleanup.
     */
    public static void endContextPolicy(final String contextId) throws GeneralSecurityException {
        // Always clear the Policy
        PolicyFactory.getPolicyFactory().setPolicy(contextId, null);
    }

}
