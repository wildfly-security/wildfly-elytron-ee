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

import static jakarta.security.jacc.PolicyContext.SUBJECT;
import static org.wildfly.security.authz.jacc.ElytronEEMessages.eeLog;

import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;

import javax.security.auth.Subject;

import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyFactory;

/**
 * Utility for passing policy checks to the appropriate Policy instance.
 *
 * In Jakarta EE 10 this class did maintain the Policy reference, however now this
 * class uses the {@code PolicyFactory} directly.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class PolicyUtil {

    private static final PolicyUtil INSTANCE = new PolicyUtil();

    /*
     * Static Methods.
     */
    @Deprecated(forRemoval = true)
    public static void setPolicy(final Policy policy) {
        throw eeLog.noLegacyPolicyAccess();
    }

    @Deprecated(forRemoval = true)
    public static Policy getPolicy() {
        throw eeLog.noLegacyPolicyAccess();
    }

    public static PolicyUtil getPolicyUtil() {
        return INSTANCE;
    }

    PolicyUtil() {}

    /**
     * @deprecated Implementations should migrate to {@code PolicyUtil#implies(Permission, Subject)}.
     */
    @Deprecated(forRemoval = true)
    public boolean implies(final ProtectionDomain domain, final Permission permission) {
        return implies(permission, PolicyContext.get(SUBJECT));
    }

    /**
     * Perform the required {@code Permission} check for the current caller.
     *
     * @param permission the {@code Permission} to be checked.
     * @param subject the {@code Subject} representation of the caller.
     * @return {@code true} if the caller has been granted the {@code Permission}, {@code false} otherwise.
     */
    public boolean implies(final Permission permission, final Subject subject) {
        // We did consider if we should be passed the SecurityIdentity here but we know the target APIs
        // do need a Subject and it is a once line call for our caller to obtain the Subject.
        PolicyFactory policyFactory = PolicyFactory.getPolicyFactory();
        jakarta.security.jacc.Policy jaccPolicy = policyFactory.getPolicy();

        return (jaccPolicy != null && subject != null) ? jaccPolicy.implies(permission, subject) : false;
    }


    @Deprecated
    public void refresh() {}

}
