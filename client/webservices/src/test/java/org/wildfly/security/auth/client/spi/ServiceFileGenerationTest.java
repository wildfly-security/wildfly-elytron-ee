/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.client.spi;

import org.jboss.wsf.spi.security.ClientConfigProvider;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ServiceLoader;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Test to verify that the META-INF/services file is properly generated
 * by the metainf-services annotation processor.
 *
 * This test ensures that the @MetaInfServices annotation on
 * WebServicesClientConfigProviderImpl results in the correct service
 * file being created during compilation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ServiceFileGenerationTest {

    private static final String SERVICE_FILE = "META-INF/services/" + ClientConfigProvider.class.getName();
    private static final String EXPECTED_IMPL = WebServicesClientConfigProviderImpl.class.getName();

    @Test
    public void testMetaInfServicesFileExists() {
        InputStream is = getClass().getClassLoader().getResourceAsStream(SERVICE_FILE);
        assertNotNull("META-INF/services file not found: " + SERVICE_FILE +
                ". The metainf-services annotation processor may not be configured correctly.", is);

        try {
            is.close();
        } catch (IOException e) {
            // Ignore
        }
    }

    @Test
    public void testMetaInfServicesFileContent() throws IOException {
        InputStream is = getClass().getClassLoader().getResourceAsStream(SERVICE_FILE);
        assertNotNull("META-INF/services file not found: " + SERVICE_FILE, is);

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            boolean found = false;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (EXPECTED_IMPL.equals(line)) {
                    found = true;
                    break;
                }
            }
            assertTrue("Expected implementation class '" + EXPECTED_IMPL +
                    "' not found in " + SERVICE_FILE, found);
        }
    }

    @Test
    public void testServiceLoaderCanFindImplementation() {
        ServiceLoader<ClientConfigProvider> loader = ServiceLoader.load(ClientConfigProvider.class);
        boolean found = false;
        for (ClientConfigProvider provider : loader) {
            if (provider instanceof WebServicesClientConfigProviderImpl) {
                found = true;
                break;
            }
        }
        assertTrue("ServiceLoader could not find WebServicesClientConfigProviderImpl. " +
                "This indicates the META-INF/services file was not generated correctly.", found);
    }
}
