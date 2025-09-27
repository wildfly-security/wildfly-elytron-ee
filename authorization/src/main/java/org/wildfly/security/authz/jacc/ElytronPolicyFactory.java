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
 * as we will be expecting that to be handled by {@code PolicyRegistration}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronPolicyFactory extends PolicyFactory {

    private Map<String, Policy> contextPolicyMap = new ConcurrentHashMap<>();

    @Override
    public Policy getPolicy(String contextId) {
        return contextPolicyMap.get(contextId);
    }

    @Override
    public void setPolicy(String contextId, Policy policy) {
        if (policy == null) {
            contextPolicyMap.remove(contextId);
        } else {
            contextPolicyMap.put(contextId, policy);
        }
    }

}
