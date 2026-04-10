/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import jakarta.security.jacc.PolicyConfigurationFactory;
import org.jboss.metadata.web.jboss.JBossWebMetaData;

/**
 * Utility responsible for resolving the {@code PolicyConfigurationFactory} for
 * a web application.
 *
 * This class is called a "Resolver" as the caller is still responsible for
 * registration.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WebPCFResolver {

    /**
     * Resolve the {@code PolicyConfigurationFactory} to set for the deployment based
     * on the defined meta data and using the deployments ClassLoader if necessary.
     *
     * @param original the currently defined {@code PolicyConfigurationFactory}.
     * @param webApppMetaData the meta data of the web application being deployed.
     * @param deploymentClassLoader the class loader of the deployment to load any replacement.
     * @return the resolved {@code PolicyConfigurationFactory}.
     */
    public static PolicyConfigurationFactory resolvePolicyConfigurationFactory(PolicyConfigurationFactory original,
                                                                                JBossWebMetaData webApppMetaData,
                                                                                ClassLoader deploymentClassLoader) {
        // This initial implementation just returns the original, later implementations will add dynamic loading etc..
        return original;
    }

}
