/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import java.security.GeneralSecurityException;

import org.jboss.metadata.web.jboss.JBossWebMetaData;

/**
 * No-op implementation for Jakarta EE 10 compatibility.
 *
 * <p>PolicyFactory does not exist in Jakarta Authorization 2.1,
 * so this class provides a no-op implementation that always returns null.</p>
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WebPolicyContextRegistration {

    /**
     * No-op registration method for Jakarta EE 10 compatibility.
     *
     * <p>PolicyFactory was introduced in Jakarta Authorization 3.0 (EE 11).
     * This method always returns null for EE 10 deployments.</p>
     *
     * @param webAppMetaData the meta data of the web application being deployed (unused)
     * @param deploymentClassLoader the class loader of the deployment (unused)
     * @param contextId the JACC context ID for this deployment (unused)
     * @return null (no cleanup needed)
     * @throws GeneralSecurityException never thrown in this no-op implementation
     */
    public static Runnable register(JBossWebMetaData webAppMetaData,
                                    ClassLoader deploymentClassLoader,
                                    String contextId) throws GeneralSecurityException {
        // No-op for EE10 - PolicyFactory does not exist in Jakarta Authorization 2.1
        return null;
    }
}
