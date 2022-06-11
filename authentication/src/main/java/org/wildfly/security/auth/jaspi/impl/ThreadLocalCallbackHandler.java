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

import static org.wildfly.security.auth.jaspi._private.ElytronEEMessages.eeLog;
import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.function.ExceptionSupplier;

/**
 * A {@code CallbackHandler} implementation which always delegates to one associated
 * with a {@code ThreadLocal}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ThreadLocalCallbackHandler implements CallbackHandler {

    private static final ThreadLocalCallbackHandler INSTANCE = new ThreadLocalCallbackHandler();

    private final ThreadLocal<CallbackHandler> delegateLocal = new ThreadLocal<>();

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        CallbackHandler delegate = delegateLocal.get();
        if (delegate == null) {
            // This could only happen if there is an attempt to use the CallbackHandler from
            // a different thread.
            throw eeLog.noThreadLocalCallbackHandler();
        }

        delegate.handle(callbacks);
    }

    <R, E extends Exception> R get(ExceptionSupplier<R, E> supplier, CallbackHandler realHandler) throws E {
        CallbackHandler original = delegateLocal.get();
        try {
            delegateLocal.set(realHandler);
            return supplier.get();
        } finally {
            delegateLocal.set(original);
        }
    }

    void run(Runnable runnable, CallbackHandler realHandler) {
        CallbackHandler original = delegateLocal.get();
        try {
            delegateLocal.set(realHandler);
            runnable.run();
        } finally {
            delegateLocal.set(original);
        }
    }

    static ThreadLocalCallbackHandler getInstance() {
        return INSTANCE;
    }

}
