/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyFactory;
import org.jboss.metadata.javaee.spec.ParamValueMetaData;
import org.jboss.metadata.web.jboss.JBossWebMetaData;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test cases for {@link WebPolicyContextRegistration}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WebPolicyContextRegistrationTest {

    private PolicyFactory originalFactory;

    @Before
    public void setUp() {
        // Capture original factory before each test
        originalFactory = PolicyFactory.getPolicyFactory();
    }

    @After
    public void tearDown() {
        // Restore original factory after each test to ensure clean state
        PolicyFactory.setPolicyFactory(originalFactory);

        // Clear any context ID
        try {
            PolicyContext.setContextID(null);
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Test that when no context params are defined, no factory change occurs.
     */
    @Test
    public void testNoContextParams() throws GeneralSecurityException {
        JBossWebMetaData metadata = new JBossWebMetaData();
        // Don't set any context params (returns null)

        Runnable cleanup = WebPolicyContextRegistration.register(
                metadata, getClass().getClassLoader(), "test-context");

        assertNull("Should return null when no context params", cleanup);
        assertSame("Factory should be unchanged", originalFactory, PolicyFactory.getPolicyFactory());
    }

    /**
     * Test that when context params exist but no PolicyFactory param is defined, no factory change occurs.
     */
    @Test
    public void testNoRelevantContextParam() throws GeneralSecurityException {
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param1 = new ParamValueMetaData();
        param1.setParamName("some.other.param");
        param1.setParamValue("someValue");
        params.add(param1);

        metadata.setContextParams(params);

        Runnable cleanup = WebPolicyContextRegistration.register(
                metadata, getClass().getClassLoader(), "test-context");

        assertNull("Should return null when PolicyFactory param not present", cleanup);
        assertSame("Factory should be unchanged", originalFactory, PolicyFactory.getPolicyFactory());
    }

    /**
     * Test that a valid PolicyFactory class with wrapping constructor is instantiated correctly.
     */
    @Test
    public void testValidFactoryWithWrappingConstructor() throws GeneralSecurityException {
        JBossWebMetaData metadata = createMetadata(WrappingTestPolicyFactory.class.getName());

        Runnable cleanup = WebPolicyContextRegistration.register(
                metadata, getClass().getClassLoader(), "test-context");

        assertNotNull("Cleanup runnable should not be null", cleanup);
        PolicyFactory currentFactory = PolicyFactory.getPolicyFactory();
        assertTrue("Should be instance of wrapping factory", currentFactory instanceof WrappingTestPolicyFactory);

        WrappingTestPolicyFactory wrappingFactory = (WrappingTestPolicyFactory) currentFactory;
        assertSame("Should wrap the original factory", originalFactory, wrappingFactory.getWrapped());
    }

    /**
     * Test that a valid PolicyFactory class with only no-arg constructor is instantiated correctly.
     */
    @Test
    public void testValidFactoryWithNoArgConstructor() throws GeneralSecurityException {
        JBossWebMetaData metadata = createMetadata(NoArgTestPolicyFactory.class.getName());

        Runnable cleanup = WebPolicyContextRegistration.register(
                metadata, getClass().getClassLoader(), "test-context");

        assertNotNull("Cleanup runnable should not be null", cleanup);
        PolicyFactory currentFactory = PolicyFactory.getPolicyFactory();
        assertTrue("Should be instance of no-arg factory", currentFactory instanceof NoArgTestPolicyFactory);
        assertNull("Should not wrap anything when using no-arg constructor", currentFactory.getWrapped());
    }

    /**
     * Test that calling the cleanup Runnable restores the original PolicyFactory.
     */
    @Test
    public void testCleanupRestoresOriginalFactory() throws GeneralSecurityException {
        JBossWebMetaData metadata = createMetadata(NoArgTestPolicyFactory.class.getName());

        Runnable cleanup = WebPolicyContextRegistration.register(
                metadata, getClass().getClassLoader(), "test-context");

        assertNotNull("Cleanup runnable should not be null", cleanup);
        assertTrue("Custom factory should be active", PolicyFactory.getPolicyFactory() instanceof NoArgTestPolicyFactory);

        // Call cleanup
        cleanup.run();

        assertSame("Original factory should be restored", originalFactory, PolicyFactory.getPolicyFactory());
    }

    /**
     * Test proper cleanup behavior when multiple deployments override factories sequentially.
     */
    @Test
    public void testMultipleDeploymentsCleanupChain() throws GeneralSecurityException {
        // Original factory (Factory A)
        PolicyFactory factoryA = originalFactory;

        // Deploy first app with custom factory (Factory B)
        JBossWebMetaData metadata1 = createMetadata(NoArgTestPolicyFactory.class.getName());
        Runnable cleanup1 = WebPolicyContextRegistration.register(
                metadata1, getClass().getClassLoader(), "context-1");
        PolicyFactory factoryB = PolicyFactory.getPolicyFactory();
        assertTrue("Factory B should be active", factoryB instanceof NoArgTestPolicyFactory);

        // Deploy second app with different custom factory (Factory C)
        JBossWebMetaData metadata2 = createMetadata(WrappingTestPolicyFactory.class.getName());
        Runnable cleanup2 = WebPolicyContextRegistration.register(
                metadata2, getClass().getClassLoader(), "context-2");
        PolicyFactory factoryC = PolicyFactory.getPolicyFactory();
        assertTrue("Factory C should be active", factoryC instanceof WrappingTestPolicyFactory);

        // Cleanup second deployment
        cleanup2.run();
        assertSame("Factory B should be restored (not A)", factoryB, PolicyFactory.getPolicyFactory());

        // Cleanup first deployment
        cleanup1.run();
        assertSame("Original Factory A should be fully restored", factoryA, PolicyFactory.getPolicyFactory());
    }

    /**
     * Test that contextId is set during factory construction and restored after.
     */
    @Test
    public void testContextIdSetDuringInstantiation() throws GeneralSecurityException {
        // Set initial context ID
        PolicyContext.setContextID("initial-context");

        JBossWebMetaData metadata = createMetadata(ContextAwareTestPolicyFactory.class.getName());

        Runnable cleanup = WebPolicyContextRegistration.register(
                metadata, getClass().getClassLoader(), "test-deployment");

        assertNotNull("Cleanup runnable should not be null", cleanup);
        PolicyFactory currentFactory = PolicyFactory.getPolicyFactory();
        assertTrue("Should be instance of context-aware factory", currentFactory instanceof ContextAwareTestPolicyFactory);

        ContextAwareTestPolicyFactory contextAwareFactory = (ContextAwareTestPolicyFactory) currentFactory;
        assertSame("Factory should have captured test-deployment context ID", "test-deployment", contextAwareFactory.getCapturedContextId());
        assertSame("Context ID should be restored to initial-context", "initial-context", PolicyContext.getContextID());
    }

    /**
     * Test that an invalid class name throws GeneralSecurityException with correct message ID 1004.
     */
    @Test
    public void testInvalidClassName() {
        JBossWebMetaData metadata = createMetadata("com.example.NonExistentFactory");

        try {
            WebPolicyContextRegistration.register(
                    metadata, getClass().getClassLoader(), "test-context");
            fail("Should throw GeneralSecurityException for non-existent class");
        } catch (GeneralSecurityException e) {
            assertTrue("Should contain ELYEE01004", e.getMessage().contains("ELYEE01004"));
            assertTrue("Should mention class name", e.getMessage().contains("com.example.NonExistentFactory"));
        }
    }

    /**
     * Test that a class that doesn't extend PolicyFactory throws with correct message ID 1006.
     */
    @Test
    public void testInvalidFactoryClass() {
        JBossWebMetaData metadata = createMetadata(String.class.getName());

        try {
            WebPolicyContextRegistration.register(
                    metadata, getClass().getClassLoader(), "test-context");
            fail("Should throw GeneralSecurityException for invalid factory class");
        } catch (GeneralSecurityException e) {
            assertTrue("Should contain ELYEE01006", e.getMessage().contains("ELYEE01006"));
            assertTrue("Should mention String class", e.getMessage().contains("java.lang.String"));
        }
    }

    /**
     * Test that constructor invocation failures throw with correct message ID 1005.
     */
    @Test
    public void testConstructorInvocationFailure() {
        JBossWebMetaData metadata = createMetadata(FailingConstructorPolicyFactory.class.getName());

        try {
            WebPolicyContextRegistration.register(
                    metadata, getClass().getClassLoader(), "test-context");
            fail("Should throw GeneralSecurityException for constructor failure");
        } catch (GeneralSecurityException e) {
            assertTrue("Should contain ELYEE01005", e.getMessage().contains("ELYEE01005"));
        }
    }

    /**
     * Test that a factory without accessible constructor throws with correct message ID 1005.
     */
    @Test
    public void testPrivateConstructor() {
        JBossWebMetaData metadata = createMetadata(PrivateConstructorPolicyFactory.class.getName());

        try {
            WebPolicyContextRegistration.register(
                    metadata, getClass().getClassLoader(), "test-context");
            fail("Should throw GeneralSecurityException for private constructor");
        } catch (GeneralSecurityException e) {
            assertTrue("Should contain ELYEE01005", e.getMessage().contains("ELYEE01005"));
        }
    }

    // ===== Helper Methods =====

    /**
     * Helper method to create JBossWebMetaData with optional PolicyFactory context param.
     */
    private JBossWebMetaData createMetadata(String factoryClassName) {
        JBossWebMetaData metadata = new JBossWebMetaData();

        if (factoryClassName != null) {
            List<ParamValueMetaData> params = new ArrayList<>();
            ParamValueMetaData param = new ParamValueMetaData();
            param.setParamName(PolicyFactory.FACTORY_NAME);
            param.setParamValue(factoryClassName);
            params.add(param);
            metadata.setContextParams(params);
        }

        return metadata;
    }

    // ===== Test Helper Classes =====

    /**
     * Basic test implementation of PolicyFactory.
     */
    public static class TestPolicyFactory extends PolicyFactory {
        @Override
        public Policy getPolicy(String contextId) {
            return null;
        }

        @Override
        public void setPolicy(String contextId, Policy policy) {
        }
    }

    /**
     * Test factory with wrapping constructor that takes another factory as parameter.
     */
    public static class WrappingTestPolicyFactory extends PolicyFactory {
        public WrappingTestPolicyFactory(PolicyFactory wrapped) {
            super(wrapped);
        }

        @Override
        public Policy getPolicy(String contextId) {
            return getWrapped() != null ? getWrapped().getPolicy(contextId) : null;
        }

        @Override
        public void setPolicy(String contextId, Policy policy) {
            if (getWrapped() != null) {
                getWrapped().setPolicy(contextId, policy);
            }
        }
    }

    /**
     * Test factory with only no-arg constructor.
     */
    public static class NoArgTestPolicyFactory extends PolicyFactory {
        public NoArgTestPolicyFactory() {
        }

        @Override
        public Policy getPolicy(String contextId) {
            return null;
        }

        @Override
        public void setPolicy(String contextId, Policy policy) {
        }
    }

    /**
     * Test factory that captures the context ID during construction.
     */
    public static class ContextAwareTestPolicyFactory extends PolicyFactory {
        private final String capturedContextId;

        public ContextAwareTestPolicyFactory() {
            // Capture the context ID during construction
            this.capturedContextId = PolicyContext.getContextID();
        }

        public String getCapturedContextId() {
            return capturedContextId;
        }

        @Override
        public Policy getPolicy(String contextId) {
            return null;
        }

        @Override
        public void setPolicy(String contextId, Policy policy) {
        }
    }

    /**
     * Test factory with constructor that throws an exception.
     */
    public static class FailingConstructorPolicyFactory extends PolicyFactory {
        public FailingConstructorPolicyFactory() {
            throw new RuntimeException("Constructor intentionally fails");
        }

        @Override
        public Policy getPolicy(String contextId) {
            return null;
        }

        @Override
        public void setPolicy(String contextId, Policy policy) {
        }
    }

    /**
     * Test factory with private constructor.
     */
    public static class PrivateConstructorPolicyFactory extends PolicyFactory {
        private PrivateConstructorPolicyFactory() {
        }

        @Override
        public Policy getPolicy(String contextId) {
            return null;
        }

        @Override
        public void setPolicy(String contextId, Policy policy) {
        }
    }
}
