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

import static org.wildfly.common.Assert.checkNotNullParam;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.config.ServerAuthContext;

/**
 * A wrapper around {@code ServerAuthContext} to allow us to use a {@code ThreadLocal} to associate our {@code CallbackHandler}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WrappingServerAuthContext implements ServerAuthContext {

    private final ThreadLocalCallbackHandler threadLocalHandler;
    private final CallbackHandler realHandler;
    private final ServerAuthContext delegate;

    WrappingServerAuthContext(ThreadLocalCallbackHandler threadLocalHandler, CallbackHandler realHandler,
            ServerAuthContext delegate) {
        this.threadLocalHandler = checkNotNullParam("threadLocalHandler", threadLocalHandler);
        this.realHandler = checkNotNullParam("realHandler", realHandler);
        this.delegate = checkNotNullParam("delegate", delegate);
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
            throws AuthException {
        return threadLocalHandler.get(() -> delegate.validateRequest(messageInfo, clientSubject, serviceSubject), realHandler);
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return threadLocalHandler.get(() -> delegate.secureResponse(messageInfo, serviceSubject), realHandler);
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        threadLocalHandler.get(() -> {
            delegate.cleanSubject(messageInfo, subject);
            return null;
        }, realHandler);
    }

}
