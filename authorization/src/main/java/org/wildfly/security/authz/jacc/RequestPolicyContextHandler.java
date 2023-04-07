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

import static org.wildfly.security.authz.jacc.SecurityActions.doPrivileged;

import java.security.PrivilegedAction;

import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PolicyContextHandler;
import jakarta.servlet.http.HttpServletRequest;

/**
 * A {@code PolicyContextHandler} to return a {@code HttpServletRequest} from the current request.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RequestPolicyContextHandler implements PolicyContextHandler {

    private static final String KEY = "jakarta.servlet.http.HttpServletRequest";

    private final PrivilegedAction<HttpServletRequest> getRequestAction;

    RequestPolicyContextHandler(final HttpServletRequestContext requestContext) {
        getRequestAction = new PrivilegedAction<HttpServletRequest>() {

            @Override
            public HttpServletRequest run() {
                return requestContext.getCurrent();
            }
        };
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return KEY.equalsIgnoreCase(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return new String[] { KEY };
    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        if (!supports(key)) {
            return null;
        }

        return doPrivileged(getRequestAction);
    }

}
