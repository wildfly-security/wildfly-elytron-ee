/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import static org.wildfly.security.authz.jacc.ElytronEEMessages.eeLog;

import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.util.List;

import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyFactory;
import org.jboss.metadata.javaee.spec.ParamValueMetaData;
import org.jboss.metadata.web.jboss.JBossWebMetaData;

/**
 * Utility responsible for registering a custom {@code PolicyFactory} for a web
 * application based on the {@code jakarta.security.jacc.PolicyFactory.provider}
 * context parameter in web.xml.
 *
 * <p>This class handles the Jakarta Authorization 3.0 specification requirement
 * (section 2.1.1) that allows web applications to replace the PolicyFactory via
 * a context-param in web.xml.</p>
 *
 * <p><strong>Important:</strong> PolicyFactory replacement is a global operation.
 * {@link PolicyFactory#setPolicyFactory(PolicyFactory)} affects all deployments
 * in the server. When multiple deployments specify custom factories, the last
 * deployed factory is active at runtime. Each deployment restores the factory
 * it cached upon undeployment, maintaining proper lifecycle behavior.</p>
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WebPolicyContextRegistration {

    /**
     * Register a custom {@code PolicyFactory} for the deployment if specified via
     * context parameter in web.xml.
     *
     * <p>This method searches for the {@code jakarta.security.jacc.PolicyFactory.provider}
     * context parameter, and if found, loads and instantiates the custom factory using
     * the deployment's ClassLoader. The custom factory is set globally via
     * {@link PolicyFactory#setPolicyFactory(PolicyFactory)}.</p>
     *
     * <p>Per spec section 2.1.1, if the custom PolicyFactory has a wrapping constructor
     * that takes a PolicyFactory argument, it will be used. Otherwise, the no-arg
     * constructor is used.</p>
     *
     * <p><strong>Global replacement behavior:</strong> The PolicyFactory replacement
     * is global and affects all deployments. If multiple deployments specify custom
     * factories, they will override each other as they deploy. This is spec-compliant
     * behavior as defined in Jakarta Authorization 3.0.</p>
     *
     * @param webAppMetaData the meta data of the web application being deployed
     * @param deploymentClassLoader the class loader of the deployment to load any custom factory
     * @param contextId the JACC context ID for this deployment (needed during factory instantiation)
     * @return a Runnable that restores the original PolicyFactory when called, or null if no custom factory was registered
     * @throws GeneralSecurityException if unable to load or instantiate the custom factory
     */
    public static Runnable register(JBossWebMetaData webAppMetaData,
                                    ClassLoader deploymentClassLoader,
                                    String contextId) throws GeneralSecurityException {
        // Get the context parameters from the web application metadata
        List<ParamValueMetaData> params = webAppMetaData.getContextParams();
        if (params == null) {
            return null;
        }

        // Search for the PolicyFactory provider parameter
        String factoryClassName = null;
        for (ParamValueMetaData param : params) {
            if (PolicyFactory.FACTORY_NAME.equals(param.getParamName())) {
                factoryClassName = param.getParamValue();
                break;
            }
        }

        // If not found, no custom factory to register
        if (factoryClassName == null) {
            return null;
        }

        // Get the current PolicyFactory before we replace it
        PolicyFactory originalFactory = PolicyFactory.getPolicyFactory();

        // Load the custom factory class using the deployment ClassLoader
        Class<?> loadedClass;
        try {
            loadedClass = deploymentClassLoader.loadClass(factoryClassName);
        } catch (ClassNotFoundException e) {
            throw eeLog.unableToLoadClass("PolicyFactory", factoryClassName, e);
        }

        // Validate it extends PolicyFactory
        if (!PolicyFactory.class.isAssignableFrom(loadedClass)) {
            throw eeLog.invalidClass(factoryClassName, "PolicyFactory");
        }

        // Cast to the correct type
        Class<? extends PolicyFactory> factoryClass = loadedClass.asSubclass(PolicyFactory.class);

        // Set the context ID before instantiating the factory
        // Custom PolicyFactory constructors may call getPolicy() which relies on PolicyContext.getContextID()
        String previousContextId = PolicyContext.getContextID();
        try {
            PolicyContext.setContextID(contextId);

            // Try wrapping constructor first, then fallback to no-arg constructor
            PolicyFactory newFactory;
            try {
                // Try wrapping constructor first (per spec section 2.1.1)
                try {
                    Constructor<? extends PolicyFactory> wrappingConstructor =
                            factoryClass.getConstructor(PolicyFactory.class);
                    newFactory = wrappingConstructor.newInstance(originalFactory);
                } catch (NoSuchMethodException e) {
                    // Fallback to no-arg constructor
                    Constructor<? extends PolicyFactory> defaultConstructor =
                            factoryClass.getDeclaredConstructor();
                    newFactory = defaultConstructor.newInstance();
                }
            } catch (ReflectiveOperationException e) {
                throw eeLog.unableToInstantiateClass("PolicyFactory", factoryClassName, e);
            }

            // Set the custom factory globally
            PolicyFactory.setPolicyFactory(newFactory);

            // Return a cleanup Runnable that restores the original factory
            return () -> PolicyFactory.setPolicyFactory(originalFactory);
        } finally {
            // Restore the previous context ID
            PolicyContext.setContextID(previousContextId);
        }
    }
}
