/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import static org.wildfly.security.authz.jacc.ElytronEEMessages.eeLog;

import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyFactory;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.authz.jacc.ElytronPolicy;

/**
 * Utility responsible for registering the Policy for a context-id.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PolicyRegistration {

    private static final String POLICY_PROVIDER = "jakarta.security.jacc.policy.provider";

    /**
     * A {@code SecurityFactory} to supply the context specific {@code Policy} instance.
     */
    private static final SecurityFactory<Policy> policyFactory;

    static {
        // We know no SecurityManager as EE 11.
        String policyProvider = System.getProperty(POLICY_PROVIDER);
        policyFactory = policyProvider == null ? new OneTimeSecurityFactory<>(ElytronPolicy::new) : () -> newPolicy(policyProvider);
    }

    private static Policy newPolicy(final String policyProvider) throws GeneralSecurityException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        try {
            Object policyInstance = classLoader.loadClass(policyProvider)
                .getDeclaredConstructor()
                .newInstance();

            if (policyInstance instanceof Policy) {
                return (Policy) policyInstance;
            }

        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
                | NoSuchMethodException | SecurityException | ClassNotFoundException e) {
            throw eeLog.unableToCreatePolicy(e);
        }

        throw eeLog.invalidPolicyClass(policyProvider, Policy.class.getName());
    }

    /**
     * Initialise the Policy for the specified context.
     *
     * @param contextId The Jakarta Authorization context id being processed.
     * @param deploymentClassLoader The {@code ClassLoader} of the deployment.
     * @throws {@code GeneralSecurityException} If any error occurs performing the initialisation.
     */
    public static void beginContextPolicy(final String contextId, final ClassLoader deploymentClassLoader) throws GeneralSecurityException {
        PolicyFactory.getPolicyFactory().setPolicy(contextId, policyFactory.create());
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
