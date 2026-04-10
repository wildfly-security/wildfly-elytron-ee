/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.authz.jacc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyFactory;

/**
 * The Elytron {@code PolicyFactory} implementation.
 *
 * This is a very simple implementation with no Policy instantiation
 * as we will be expecting that to be handled by {@code AuthorizationRegistration}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronPolicyFactory extends PolicyFactory {

    private volatile Policy defaultPolicy;
    private final Map<String, Policy> contextPolicyMap = new ConcurrentHashMap<>();

    public ElytronPolicyFactory(final Policy defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    @Override
    public Policy getPolicy(String contextId) {
        Policy policy = contextPolicyMap.get(contextId);

        return policy != null ? policy : defaultPolicy;
    }

    @Override
    public void setPolicy(String contextId, Policy policy) {
        if (contextId != null) {
            if (policy == null) {
                contextPolicyMap.remove(contextId);
            } else {
                contextPolicyMap.put(contextId, policy);
            }
        } else {
            // If the contextId is null we are setting the default.
            defaultPolicy = policy;
        }
    }

}
