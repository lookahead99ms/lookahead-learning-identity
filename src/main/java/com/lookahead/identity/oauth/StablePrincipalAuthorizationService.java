package com.lookahead.identity.oauth;

import com.lookahead.identity.security.AccountPrincipal;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import java.security.Principal;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Persist a framework-supported, password-free identity keyed by immutable account UUID. */
public final class StablePrincipalAuthorizationService implements OAuth2AuthorizationService {
    private final OAuth2AuthorizationService delegate;
    public StablePrincipalAuthorizationService(OAuth2AuthorizationService delegate) { this.delegate=delegate; }
    @Override public void save(OAuth2Authorization authorization) {
        Authentication authentication=authorization.getAttribute(Principal.class.getName());
        if(authentication!=null && authentication.getPrincipal() instanceof AccountPrincipal principal) {
            // OIDC logout compares this authentication name with the current identity session.
            var user=User.withUsername(principal.getUsername()).password("").authorities(principal.getAuthorities()).build();
            var stored=UsernamePasswordAuthenticationToken.authenticated(user,null,user.getAuthorities());
            var builder=OAuth2Authorization.from(authorization).principalName(principal.accountId().toString())
                    .attribute(Principal.class.getName(),stored)
                    .attribute(EpochAuthorizationService.EPOCH,Long.toString(principal.credentialEpoch()));
            // Bind logout to the actual authorizing browser session, not the latest session for this user.
            if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
                var session=attributes.getRequest().getSession(false);
                if(session!=null) {
                    try {
                        String hash=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(session.getId().getBytes(StandardCharsets.US_ASCII)));
                        builder.attribute("lookahead.identity-session-hash",hash);
                    } catch(java.security.NoSuchAlgorithmException error) { throw new IllegalStateException("SHA-256 unavailable",error); }
                }
            }
            authorization=builder.build();
        }
        delegate.save(authorization);
    }
    @Override public void remove(OAuth2Authorization authorization) { delegate.remove(authorization); }
    @Override public OAuth2Authorization findById(String id) { return delegate.findById(id); }
    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType type) { return delegate.findByToken(token,type); }
}
