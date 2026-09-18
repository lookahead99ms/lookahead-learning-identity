package com.lookahead.identity.oauth;

import com.lookahead.identity.security.AccountPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.context.request.*;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class StablePrincipalAuthorizationServiceTest {
    @Test void persistenceKeepsImmutableOwnerAndBindsEachActualBrowserSessionWithoutStoringItsCookie() throws Exception {
        var delegate=new InMemoryOAuth2AuthorizationService();var service=new StablePrincipalAuthorizationService(delegate);
        var owner=UUID.randomUUID();var principal=new AccountPrincipal(owner,"synthetic@example.test","Synthetic","discarded-password",true);
        var authentication=UsernamePasswordAuthenticationToken.authenticated(principal,null,principal.getAuthorities());
        var client=RegisteredClient.withId("synthetic-client").clientId("lookahead-web-gateway")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://example.test/callback").build();
        var hashes=new HashSet<String>();
        try {
            for(int browser=0;browser<2;browser++) {
                var request=new MockHttpServletRequest();String sessionId=request.getSession().getId();
                RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
                var authorization=OAuth2Authorization.withRegisteredClient(client).id("browser-"+browser)
                        .principalName(principal.getUsername()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .attribute(Principal.class.getName(),authentication).build();
                service.save(authorization);var saved=service.findById(authorization.getId());
                assertThat(saved.getPrincipalName()).isEqualTo(owner.toString());
                Authentication stored=saved.getAttribute(Principal.class.getName());
                assertThat(stored.getName()).isEqualTo(principal.getUsername());
                assertThat(stored.getPrincipal()).isInstanceOf(User.class);
                assertThat(((User)stored.getPrincipal()).getPassword()).isEmpty();
                String expected=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(sessionId.getBytes(StandardCharsets.US_ASCII)));
                String actual=saved.getAttribute("lookahead.identity-session-hash");assertThat(actual).isEqualTo(expected).isNotEqualTo(sessionId);hashes.add(actual);
            }
            assertThat(hashes).hasSize(2);
        } finally {RequestContextHolder.resetRequestAttributes();}
    }
}
