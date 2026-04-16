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
import org.jboss.logging.annotations.LogMessage;
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
    @ValidIdRange(min = 1000, max = 1999)
})
public interface ElytronEEMessages extends BasicLogger {

    ElytronEEMessages eeLog = Logger.getMessageLogger(ElytronEEMessages.class, "org.wildfly.security.ee");

    @Message(id = 1000, value = "No legacy Policy access from Jakarta EE 11 and later.")
    UnsupportedOperationException noLegacyPolicyAccess();

    @Message(id = 1001, value = "Unable to create Policy instance.")
    GeneralSecurityException unableToCreatePolicy(@Cause Exception cause);

    @Message(id = 1002, value = "Class %s does not implement %s")
    GeneralSecurityException invalidPolicyClass(String className, String expectedType);

    @Message(id = 1003, value = "Unable to complete PolicyContextHandler registration.")
    GeneralSecurityException unableToCompletePolicyContextHandlerRegistration(@Cause PolicyContextException cause);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 1007, value = "RunAs principal '%s' does not exist in security domain. Creating ad-hoc identity with only the persona role '%s'. Define the principal in your security domain configuration for full role mapping.")
    void runAsPrincipalNotFoundInDomain(String principalName, String runAsRoleName);

}
