/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import static jakarta.security.jacc.PolicyConfigurationFactory.setPolicyConfigurationFactory;
import static org.wildfly.security.authz.jacc.ElytronEEMessages.eeLog;

import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.util.List;

import jakarta.security.jacc.PolicyConfigurationFactory;
import org.jboss.metadata.javaee.spec.ParamValueMetaData;
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
     * @throws GeneralSecurityException if unable to load or instantiate the custom factory.
     */
    public static PolicyConfigurationFactory resolvePolicyConfigurationFactory(PolicyConfigurationFactory original,
                                                                                JBossWebMetaData webApppMetaData,
                                                                                ClassLoader deploymentClassLoader) throws GeneralSecurityException {
        // For Jakarta Authorization 3.0 the PolicyConfigurationFactory can be overridden by a context param in the web.xml.

        // Get the context parameters from the web application metadata
        List<ParamValueMetaData> params = webApppMetaData.getContextParams();
        if (params == null) {
            return original;
        }

        // Search for the PolicyConfigurationFactory provider parameter
        String factoryClassName = null;
        for (ParamValueMetaData param : params) {
            if (PolicyConfigurationFactory.FACTORY_NAME.equals(param.getParamName())) {
                factoryClassName = param.getParamValue();
                break;
            }
        }

        // If not found, return the original factory
        if (factoryClassName == null) {
            return original;
        }

        // Load the class using the deployment ClassLoader
        Class<?> loadedClass;
        try {
            loadedClass = deploymentClassLoader.loadClass(factoryClassName);
        } catch (ClassNotFoundException e) {
            throw eeLog.unableToLoadPolicyConfigurationFactory(factoryClassName, e);
        }

        // Validate it extends PolicyConfigurationFactory
        if (!PolicyConfigurationFactory.class.isAssignableFrom(loadedClass)) {
            throw eeLog.invalidPolicyConfigurationFactoryClass(factoryClassName);
        }

        // Cast to the correct type
        Class<? extends PolicyConfigurationFactory> factoryClass = loadedClass.asSubclass(PolicyConfigurationFactory.class);

        // Try wrapping constructor first, then fallback to no-arg constructor
        PolicyConfigurationFactory newFactory;
        try {
            // Try wrapping constructor first
            try {
                Constructor<? extends PolicyConfigurationFactory> wrappingConstructor =
                        factoryClass.getConstructor(PolicyConfigurationFactory.class);
                newFactory = wrappingConstructor.newInstance(original);
            } catch (NoSuchMethodException e) {
                // Fallback to no-arg constructor
                Constructor<? extends PolicyConfigurationFactory> defaultConstructor =
                        factoryClass.getDeclaredConstructor();
                newFactory = defaultConstructor.newInstance();
            }
        } catch (ReflectiveOperationException e) {
            throw eeLog.unableToInstantiatePolicyConfigurationFactory(factoryClassName, e);
        }

        return newFactory;
    }

    /**
     * Replace the globally registered {@code PolicyConfigurationFactory}.
     *
     * @param pcf the {@code PolicyConfigurationFactory} to register globally.
     */
    public static void setGlobalPolicyConfigurationFactory(final PolicyConfigurationFactory pcf) {
        setPolicyConfigurationFactory(pcf);
    }

}
