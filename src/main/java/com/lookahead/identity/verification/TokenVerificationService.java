package com.lookahead.identity.verification;

import com.lookahead.identity.oauth.OAuthSettings;
import com.lookahead.identity.repository.AccountRepository;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

/** Authoritative token and enabled-account check; never returns token bytes or credentials. */
@Service
public final class TokenVerificationService {
    private final JwtDecoder decoder;
    private final OAuthSettings settings;
    private final OAuth2AuthorizationService authorizations;
    private final RegisteredClientRepository clients;
    private final AccountRepository accounts;

    public TokenVerificationService(JwtDecoder decoder, OAuthSettings settings,
            OAuth2AuthorizationService authorizations, RegisteredClientRepository clients,
            AccountRepository accounts) {
        this.decoder = decoder; this.settings = settings; this.authorizations = authorizations;
        this.clients = clients; this.accounts = accounts;
    }

    public Map<String, Object> verify(String value) {
        if (value == null || value.isBlank() || value.length() > 16384) return inactive();
        Jwt token;
        UUID subject;
        try {
            token = decoder.decode(value);
            subject = UUID.fromString(token.getSubject());
            if (!subject.toString().equals(token.getSubject())
                    || token.getAudience() == null || !token.getAudience().contains("lookahead-api")
                    || !settings.clientId().equals(token.getClaimAsString("client_id"))) return inactive();
        } catch (JwtException | IllegalArgumentException | NullPointerException invalid) {
            return inactive();
        }
        var authorization = authorizations.findByToken(value, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null || authorization.getAccessToken() == null
                || !authorization.getAccessToken().isActive()
                || !value.equals(authorization.getAccessToken().getToken().getTokenValue())
                || !subject.toString().equals(authorization.getPrincipalName())) return inactive();
        var client = clients.findById(authorization.getRegisteredClientId());
        if (client == null || !settings.clientId().equals(client.getClientId())) return inactive();
        var account = accounts.findById(subject).filter(candidate -> candidate.enabled());
        if (account.isEmpty()) return inactive();
        var identity = account.orElseThrow();
        return Map.of("active", true, "subject", identity.accountId().toString(),
                "username", identity.username(), "displayName", identity.displayName(),
                "clientId", client.getClientId());
    }

    private static Map<String, Object> inactive() { return Map.of("active", false); }
}
