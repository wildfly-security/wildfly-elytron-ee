/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jakarta.authz;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContextException;
import org.jboss.metadata.javaee.spec.ParamValueMetaData;
import org.jboss.metadata.web.jboss.JBossWebMetaData;
import org.junit.Test;

/**
 * Test cases for {@link WebPCFResolver}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WebPCFResolverTest {

    /**
     * Test that when no context params are defined, the original factory is returned.
     */
    @Test
    public void testNoContextParams() throws GeneralSecurityException {
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();
        // Don't set any context params (returns null)

        PolicyConfigurationFactory result = WebPCFResolver.resolvePolicyConfigurationFactory(
                original, metadata, getClass().getClassLoader());

        assertSame("Should return original when no context params", original, result);
    }

    /**
     * Test that when context params exist but no PCF param is defined, the original factory is returned.
     */
    @Test
    public void testNoRelevantContextParam() throws GeneralSecurityException {
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param1 = new ParamValueMetaData();
        param1.setParamName("some.other.param");
        param1.setParamValue("someValue");
        params.add(param1);

        metadata.setContextParams(params);

        PolicyConfigurationFactory result = WebPCFResolver.resolvePolicyConfigurationFactory(
                original, metadata, getClass().getClassLoader());

        assertSame("Should return original when PCF param not present", original, result);
    }

    /**
     * Test that a valid PCF class with wrapping constructor is instantiated correctly.
     */
    @Test
    public void testValidFactoryWithWrappingConstructor() throws GeneralSecurityException {
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(PolicyConfigurationFactory.FACTORY_NAME);
        param.setParamValue(WrappingTestPolicyConfigurationFactory.class.getName());
        params.add(param);

        metadata.setContextParams(params);

        PolicyConfigurationFactory result = WebPCFResolver.resolvePolicyConfigurationFactory(
                original, metadata, getClass().getClassLoader());

        assertNotNull("Result should not be null", result);
        assertTrue("Should be instance of wrapping factory", result instanceof WrappingTestPolicyConfigurationFactory);

        WrappingTestPolicyConfigurationFactory wrappingFactory = (WrappingTestPolicyConfigurationFactory) result;
        assertSame("Should wrap the original factory", original, wrappingFactory.getWrapped());
    }

    /**
     * Test that a valid PCF class with only no-arg constructor is instantiated correctly.
     */
    @Test
    public void testValidFactoryWithNoArgConstructor() throws GeneralSecurityException {
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(PolicyConfigurationFactory.FACTORY_NAME);
        param.setParamValue(NoArgTestPolicyConfigurationFactory.class.getName());
        params.add(param);

        metadata.setContextParams(params);

        PolicyConfigurationFactory result = WebPCFResolver.resolvePolicyConfigurationFactory(
                original, metadata, getClass().getClassLoader());

        assertNotNull("Result should not be null", result);
        assertTrue("Should be instance of no-arg factory", result instanceof NoArgTestPolicyConfigurationFactory);
        assertSame("Should not wrap anything when using no-arg constructor", null, result.getWrapped());
    }

    /**
     * Test that an invalid class name throws GeneralSecurityException with correct message ID 1004.
     */
    @Test
    public void testInvalidClassName() {
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(PolicyConfigurationFactory.FACTORY_NAME);
        param.setParamValue("com.example.NonExistentClass");
        params.add(param);

        metadata.setContextParams(params);

        try {
            WebPCFResolver.resolvePolicyConfigurationFactory(
                    original, metadata, getClass().getClassLoader());
            fail("Should throw GeneralSecurityException for non-existent class");
        } catch (GeneralSecurityException e) {
            assertTrue("Should contain ELYEE01004", e.getMessage().contains("ELYEE01004"));
            assertTrue("Should mention class name", e.getMessage().contains("com.example.NonExistentClass"));
        }
    }

    /**
     * Test that a class that doesn't extend PolicyConfigurationFactory throws with correct message ID 1006.
     */
    @Test
    public void testInvalidFactoryClass() {
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(PolicyConfigurationFactory.FACTORY_NAME);
        param.setParamValue(String.class.getName()); // String doesn't extend PCF
        params.add(param);

        metadata.setContextParams(params);

        try {
            WebPCFResolver.resolvePolicyConfigurationFactory(
                    original, metadata, getClass().getClassLoader());
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
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(PolicyConfigurationFactory.FACTORY_NAME);
        param.setParamValue(FailingConstructorPolicyConfigurationFactory.class.getName());
        params.add(param);

        metadata.setContextParams(params);

        try {
            WebPCFResolver.resolvePolicyConfigurationFactory(
                    original, metadata, getClass().getClassLoader());
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
        PolicyConfigurationFactory original = new TestPolicyConfigurationFactory();
        JBossWebMetaData metadata = new JBossWebMetaData();

        List<ParamValueMetaData> params = new ArrayList<>();
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(PolicyConfigurationFactory.FACTORY_NAME);
        param.setParamValue(PrivateConstructorPolicyConfigurationFactory.class.getName());
        params.add(param);

        metadata.setContextParams(params);

        try {
            WebPCFResolver.resolvePolicyConfigurationFactory(
                    original, metadata, getClass().getClassLoader());
            fail("Should throw GeneralSecurityException for private constructor");
        } catch (GeneralSecurityException e) {
            assertTrue("Should contain ELYEE01005", e.getMessage().contains("ELYEE01005"));
        }
    }

    // ===== Test Helper Classes =====

    /**
     * Basic test implementation of PolicyConfigurationFactory.
     */
    public static class TestPolicyConfigurationFactory extends PolicyConfigurationFactory {
        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID) {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration() {
            return null;
        }

        @Override
        public boolean inService(String contextID) throws PolicyContextException {
            return false;
        }
    }

    /**
     * Test factory with wrapping constructor that takes another factory as parameter.
     */
    public static class WrappingTestPolicyConfigurationFactory extends PolicyConfigurationFactory {
        public WrappingTestPolicyConfigurationFactory(PolicyConfigurationFactory wrapped) {
            super(wrapped);
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
            return getWrapped().getPolicyConfiguration(contextID, remove);
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID) {
            return getWrapped().getPolicyConfiguration(contextID);
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration() {
            return getWrapped().getPolicyConfiguration();
        }

        @Override
        public boolean inService(String contextID) throws PolicyContextException {
            return getWrapped().inService(contextID);
        }
    }

    /**
     * Test factory with only no-arg constructor.
     */
    public static class NoArgTestPolicyConfigurationFactory extends PolicyConfigurationFactory {
        public NoArgTestPolicyConfigurationFactory() {
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID) {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration() {
            return null;
        }

        @Override
        public boolean inService(String contextID) throws PolicyContextException {
            return false;
        }
    }

    /**
     * Test factory with constructor that throws an exception.
     */
    public static class FailingConstructorPolicyConfigurationFactory extends PolicyConfigurationFactory {
        public FailingConstructorPolicyConfigurationFactory() {
            throw new RuntimeException("Constructor intentionally fails");
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID) {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration() {
            return null;
        }

        @Override
        public boolean inService(String contextID) throws PolicyContextException {
            return false;
        }
    }

    /**
     * Test factory with private constructor.
     */
    public static class PrivateConstructorPolicyConfigurationFactory extends PolicyConfigurationFactory {
        private PrivateConstructorPolicyConfigurationFactory() {
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration(String contextID) {
            return null;
        }

        @Override
        public PolicyConfiguration getPolicyConfiguration() {
            return null;
        }

        @Override
        public boolean inService(String contextID) throws PolicyContextException {
            return false;
        }
    }
}
