/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.authz.jacc;

import static jakarta.security.jacc.PolicyContext.PRINCIPAL_MAPPER;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;

import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.PolicyContextHandler;
import jakarta.security.jacc.PrincipalMapper;
import org.wildfly.security.auth.principal.NamedGroup;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Roles;

/**
 * A WildFly Elytron specific {@code PrincipalMapper} implementation.
 *
 * This implementation maps directly from the {@code SecurityIdentity} instance
 * held within the {@code Subject}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class PrincipalMapperContextHandler implements PolicyContextHandler {

    private static final PrincipalMapper MAPPER_INSTANCE = new ElytronPrincipalMapper();

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return PRINCIPAL_MAPPER.equals(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return new String[] { PRINCIPAL_MAPPER };
    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        return supports(key) ? MAPPER_INSTANCE : null;
    }

    static class ElytronPrincipalMapper implements PrincipalMapper {

        @Override
        public Principal getCallerPrincipal(Subject subject) {
            SecurityIdentity securityIdentity = toSecurityIdentity(subject);

            return securityIdentity != null ? securityIdentity.getPrincipal() : null;
        }

        @Override
        public Set<String> getMappedRoles(Subject subject) {
            Set<String> roles = new HashSet<>();

            SecurityIdentity securityIdentity = toSecurityIdentity(subject);
            if (securityIdentity != null) {
                Roles originalRoles = securityIdentity.getRoles();
                for (String currentRole : originalRoles) {
                    roles.add(currentRole);
                }
            } else {
                for (Principal principal : subject.getPrincipals()) {
                    if (principal instanceof NamedGroup && "Roles".equals(principal.getName())) {
                        Enumeration<? extends Principal> members = ((NamedGroup) principal).members();
                        while (members.hasMoreElements()) {
                            roles.add(members.nextElement().getName());
                        }
                    }
                }
            }

            return roles;
        }

        private static SecurityIdentity toSecurityIdentity(final Subject subject) {
            Set<Object> privateCredentials = subject.getPrivateCredentials();
            for (Object currentCredential : privateCredentials) {
                if (currentCredential instanceof SecurityIdentity) {
                    return (SecurityIdentity) currentCredential;
                }
            }

            return null;
        }
    }

}
