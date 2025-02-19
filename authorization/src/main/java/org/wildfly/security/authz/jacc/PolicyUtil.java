/*
 * Copyright 2024 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.authz.jacc;

import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;

/**
 * Utility for setting and using the underlying Policy.
 *
 * This class does not include any doPrivileged calls as the caller is
 * expected to have the required permissions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class PolicyUtil {

    static final Boolean SM_SUPPORTED = Runtime.version().feature() < 24;

    private static final ThreadLocal<Policy> CURRENT_POLICY = new ThreadLocal<>();

    public static void setPolicy(final Policy policy) {
        if (SM_SUPPORTED) {
            Policy.setPolicy(policy);
        } else {
            if (policy == null) {
                CURRENT_POLICY.remove();
            } else {
                CURRENT_POLICY.set(policy);
            }
        }
    }

    public static Policy getPolicy() {
        if (SM_SUPPORTED) {
            return Policy.getPolicy();
        } else {
            return CURRENT_POLICY.get();
        }
    }

    public static PolicyUtil getPolicyUtil() {
        return new PolicyUtil(getPolicy());
    }

    private final Policy policy;

    PolicyUtil(final Policy policy) {
        this.policy = policy;
    }

    public boolean implies(final ProtectionDomain domain, final Permission permission) {
        return policy != null && policy.implies(domain, permission);
    }

    public void refresh() {
        if (policy != null) {
            policy.refresh();
        }
    }

}
