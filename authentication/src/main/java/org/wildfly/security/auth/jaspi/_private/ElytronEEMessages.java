/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.jaspi._private;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for Elytron EE.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELYEE", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1, max = 999)
})
public interface ElytronEEMessages extends BasicLogger {

    ElytronEEMessages eeLog = Logger.getMessageLogger(ElytronEEMessages.class, "org.wildfly.security.ee");

    @Message(id = 1, value = "No ThreadLocal CallbackHandler available.")
    IllegalStateException noThreadLocalCallbackHandler();

    @Message(id = 2, value = "Unrecognised context type '%s'.")
    IllegalStateException unrecognisedContext(final String contextClassName);

    @Message(id = 3, value = "No registration for '%s'.")
    IllegalStateException noSavedRegistration(final String appContext);

}
