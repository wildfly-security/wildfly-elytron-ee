/*
 * Copyright 2023 Red Hat, Inc.
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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import jakarta.security.jacc.PolicyContextHandler;

/**
 * A factory to return a {@code List} of {@code PolicyContextHandler} instances supported by
 * WildFly Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronPolicyContextHandlerFactory {

    public static List<PolicyContextHandler> getPolicyContextHandlers() {
        HttpServletRequestContext httpServletRequestContext = getHttpServletRequestContext();

        List<PolicyContextHandler> policyContextHandlers = new ArrayList<>(httpServletRequestContext != null ? 3 : 2);

        policyContextHandlers.add(new SecurityIdentityHandler());
        policyContextHandlers.add(new SubjectPolicyContextHandler());
        if (httpServletRequestContext != null) {
            policyContextHandlers.add(new RequestPolicyContextHandler(httpServletRequestContext));
        }

        return policyContextHandlers;
    }

    private static HttpServletRequestContext getHttpServletRequestContext() {
        ServiceLoader<HttpServletRequestContext> requestContextLoader = ServiceLoader.load(HttpServletRequestContext.class,
                ElytronPolicyContextHandlerFactory.class.getClassLoader());
        Iterator<HttpServletRequestContext> iterator = requestContextLoader.iterator();
        for (;;)
            try {
                if (!iterator.hasNext()) {
                    return null;
                }
                HttpServletRequestContext requestContext = iterator.next();
                return requestContext;
            } catch (ServiceConfigurationError ignored) {
                // explicitly ignored
            }
    }
}
