/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import static jakarta.security.jacc.PolicyConfigurationFactory.setPolicyConfigurationFactory;
import static jakarta.security.jacc.PolicyContext.registerHandler;
import static org.wildfly.security.authz.jacc.ElytronEEMessages.eeLog;
import static org.wildfly.security.authz.jacc.ElytronPolicyContextHandlerFactory.getPolicyContextHandlers;

import java.security.GeneralSecurityException;
import java.util.List;

import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PolicyContextHandler;
import jakarta.security.jacc.PolicyFactory;
import org.wildfly.security.authz.jacc.ElytronPolicyConfigurationFactory;
import org.wildfly.security.authz.jacc.ElytronPolicyFactory;

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
     * @throws {@code GeneralSecurityException} if dynamic registration is attempted but fails.
     */
    public static boolean register() throws GeneralSecurityException {
        // Registration tasks to perform.

        // This registration does not need to handle Policy creation,
        // ElytronPolicyFactory will have a default impl and PolicyRegistration
        // will enable a System property defined Policy to be loaded from the
        // deployment's ClassLoader.

        ///////////////////
        // PolicyFactory //
        ///////////////////

        PolicyFactory.setPolicyFactory(new ElytronPolicyFactory());

        //////////////////////////
        // PolicyContextHandler //
        //////////////////////////

        // Although the current code in WildFly also supports ServiceLoader discovery we don't
        // seem to use it for now so lets simplify and just register the handlers we know about.
        List<PolicyContextHandler> policyContextHandlers = getPolicyContextHandlers();
        for (PolicyContextHandler current : policyContextHandlers) {
            try {
                for (String currentKey : current.getKeys()) {
                    registerHandler(currentKey, current, true);
                }
            } catch (PolicyContextException e) {
                throw eeLog.unableToCompletePolicyContextHandlerRegistration(e);
            }
        }


        ////////////////////////////////
        // PolicyConfigurationFactory //
        ////////////////////////////////

        setPolicyConfigurationFactory(new ElytronPolicyConfigurationFactory());

        return true;
    }

}
