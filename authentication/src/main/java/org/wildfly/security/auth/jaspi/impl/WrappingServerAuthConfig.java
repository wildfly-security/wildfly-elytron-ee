/*
 * Copyright 2022 Red Hat, Inc.
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

package org.wildfly.security.auth.jaspi.impl;

import static org.wildfly.common.Assert.assertNotNull;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.security.auth.message.config.ServerAuthContext;

/**
 * A wrapper around {@code ServerAuthConfig} to allow us to use a {@code ThreadLocal} to associate our {@code CallbackHandler}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class WrappingServerAuthConfig implements ServerAuthConfig {

    private final ThreadLocalCallbackHandler threadLocalHandler;
    private final CallbackHandler realHandler;
    private final ServerAuthConfig delegate;

    WrappingServerAuthConfig(ThreadLocalCallbackHandler threadLocalHandler, CallbackHandler realHandler,
            ServerAuthConfig delegate) {
        this.threadLocalHandler = checkNotNullParam("threadLocalHandler", threadLocalHandler);
        this.realHandler = checkNotNullParam("realHandler", realHandler);
        this.delegate = checkNotNullParam("delegate", delegate);
    }

    @Override
    public String getMessageLayer() {
        return threadLocalHandler.get(delegate::getMessageLayer, realHandler);
    }

    @Override
    public String getAppContext() {
        return threadLocalHandler.get(delegate::getAppContext, realHandler);
    }

    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return threadLocalHandler.get(() -> delegate.getAuthContextID(messageInfo), realHandler);
    }

    @Override
    public void refresh() {
        threadLocalHandler.run(delegate::refresh, realHandler);
    }

    @Override
    public boolean isProtected() {
        return threadLocalHandler.get(delegate::isProtected, realHandler);
    }

    @Override
    public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject, Map properties) throws AuthException {
        ServerAuthContext serverAuthContext = threadLocalHandler
                .get(() -> delegate.getAuthContext(authContextID, serviceSubject, properties), realHandler);

        return serverAuthContext != null ? new WrappingServerAuthContext(threadLocalHandler, realHandler, serverAuthContext)
                : null;
    }

    static ServerAuthConfig getServerAuthConfig(AuthConfigProvider authConfigProvider, String layer, String appContext,
            CallbackHandler realCallbackHandler) throws AuthException {
        ThreadLocalCallbackHandler threadLocalHandler = ThreadLocalCallbackHandler.getInstance();

        ServerAuthConfig serverAuthConfig = threadLocalHandler
                .get(() -> authConfigProvider.getServerAuthConfig(layer, appContext, threadLocalHandler), realCallbackHandler);
        assertNotNull(serverAuthConfig);

        return new WrappingServerAuthConfig(threadLocalHandler, realCallbackHandler, serverAuthConfig);
    }

}
