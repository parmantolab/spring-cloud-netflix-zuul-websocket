/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.mthizo247.cloud.netflix.zuul.web.authentication;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.WebSocketSession;

import java.util.Collections;

/**
 * @author Ronald Mthombeni
 */
public class BasicAuthPrincipalHeadersCallback extends AbstractHeadersCallback {
    @Override
    protected void applyHeadersInternal(WebSocketSession userAgentSession, WebSocketHttpHeaders headers) {
        Authentication authentication = (Authentication) userAgentSession.getPrincipal();
        String usernameColonPwd = authentication.getName() + ":"
                + authentication.getCredentials().toString();
        String encodedCredentials = new String(
                Base64.encode(usernameColonPwd.getBytes()));
        headers.put(HttpHeaders.AUTHORIZATION,
                Collections.singletonList("Basic " + encodedCredentials));
        if (logger.isDebugEnabled()) {
            logger.debug("Added basic authentication header for user " + authentication.getName() + " to web sockets http headers");
        }
    }

    @Override
    protected boolean shouldApplyHeaders(WebSocketSession userAgentSession, WebSocketHttpHeaders headers) {
        return !headers.containsKey(HttpHeaders.AUTHORIZATION) && userAgentSession.getPrincipal() instanceof Authentication && ((Authentication) userAgentSession.getPrincipal()).getCredentials() != null;
    }
}
