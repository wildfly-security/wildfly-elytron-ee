/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.authz.jacc;

import java.security.GeneralSecurityException;

import jakarta.security.jacc.PolicyContextException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;

/**
 * Log messages and exceptions for Elytron EE.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELYEE", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1000, max = 1999)
})
public interface ElytronEEMessages extends BasicLogger {

    ElytronEEMessages eeLog = Logger.getMessageLogger(ElytronEEMessages.class, "org.wildfly.security.ee");



    @Message(id = 1003, value = "Unable to complete PolicyContextHandler registration.")
    GeneralSecurityException unableToCompletePolicyContextHandlerRegistration(@Cause PolicyContextException cause);

}
