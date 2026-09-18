package com.lookahead.identity.verification;

import com.lookahead.identity.model.AccountCredentials;
import com.lookahead.identity.oauth.OAuthSettings;
import com.lookahead.identity.repository.AccountRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenVerificationServiceTest {
    private final UUID subject = UUID.randomUUID();
    private final JwtDecoder decoder = mock(JwtDecoder.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    private final OAuth2AuthorizationService authorizations = mock(OAuth2AuthorizationService.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    private final AccountRepository accounts = mock(AccountRepository.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    private final OAuthSettings settings = new OAuthSettings("https://learning.example", "lookahead-web-gateway",
            "synthetic-client-secret-32-characters", "http://identity:8080", "https://learning.example");
    private final RegisteredClient client = RegisteredClient.withId("registered-v1")
            .clientId(settings.clientId()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://learning.example/login/oauth2/code/lookahead").build();
    private TokenVerificationService service;

    @BeforeEach void setup() {
        service = new TokenVerificationService(decoder, settings, authorizations, clients, accounts);
        when(decoder.decode("token")).thenReturn(jwt("lookahead-api", settings.clientId(), subject.toString()));
        when(authorizations.findByToken("token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization(false, subject.toString()));
        when(clients.findById(client.getId())).thenReturn(client);
        when(accounts.findById(subject)).thenReturn(Optional.of(new AccountCredentials(subject,
                "learner@example.test", "Learner", null, true)));
    }
    private Jwt jwt(String audience, String clientId, String user) {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject(user)
                .audience(List.of(audience)).claim("client_id", clientId).build();
    }
    private OAuth2Authorization authorization(boolean revoked, String user) {
        var access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
                Instant.now().minusSeconds(10), Instant.now().plusSeconds(300), Set.of("account"));
        return OAuth2Authorization.withRegisteredClient(client).principalName(user)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(access, metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, revoked)).build();
    }
    @Test void returnsIdentityOnlyAfterAllAuthoritativeChecks() {
        var result = service.verify("token");
        assertThat(result).containsEntry("active", true).containsEntry("subject", subject.toString())
                .containsEntry("username", "learner@example.test").containsEntry("displayName", "Learner")
                .containsEntry("clientId", settings.clientId()).hasSize(5);
        assertThat(result.toString()).doesNotContain("password", "token");
    }
    @Test void malformedAndWrongAppClaimsNeverReachStorage() {
        for (Jwt jwt : List.of(jwt("another-api", settings.clientId(), subject.toString()),
                jwt("lookahead-api", "another-client", subject.toString()),
                jwt("lookahead-api", settings.clientId(), "invalid-subject"))) {
            when(decoder.decode("token")).thenReturn(jwt);
            assertThat(service.verify("token")).containsOnly(entry("active", false));
        }
        verifyNoInteractions(authorizations, clients, accounts);
    }
    @Test void cryptoErrorsAndOversizedOrMissingTokensAreInactive() {
        when(decoder.decode("token")).thenThrow(new BadJwtException("Do not expose parser detail"));
        for (String value : new String[]{"token", null, "", "a".repeat(16385)})
            assertThat(service.verify(value)).containsOnly(entry("active", false));
        verifyNoInteractions(authorizations, clients, accounts);
    }
    @Test void revokedMissingMismatchedAndDisabledIdentityRemainInactive() {
        when(authorizations.findByToken("token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(null);
        assertThat(service.verify("token")).containsOnly(entry("active", false));
        when(authorizations.findByToken("token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization(true, subject.toString()));
        assertThat(service.verify("token")).containsOnly(entry("active", false));
        when(authorizations.findByToken("token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization(false, UUID.randomUUID().toString()));
        assertThat(service.verify("token")).containsOnly(entry("active", false));
        when(authorizations.findByToken("token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization(false, subject.toString()));
        when(accounts.findById(subject)).thenReturn(Optional.empty());
        assertThat(service.verify("token")).containsOnly(entry("active", false));
        when(accounts.findById(subject)).thenReturn(Optional.of(new AccountCredentials(subject, "learner", "Learner", null, false)));
        assertThat(service.verify("token")).containsOnly(entry("active", false));
    }
    @Test void authorizationCannotBorrowAnotherRegisteredClient() {
        when(clients.findById(client.getId())).thenReturn(RegisteredClient.withId(client.getId()).clientId("another-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://example.test/callback").build());
        assertThat(service.verify("token")).containsOnly(entry("active", false));
        verifyNoInteractions(accounts);
    }
    @Test void storageFailureIsNotMisrepresentedAsInactive() {
        when(authorizations.findByToken("token", OAuth2TokenType.ACCESS_TOKEN)).thenThrow(new DataAccessResourceFailureException("unavailable"));
        assertThatThrownBy(() -> service.verify("token")).isInstanceOf(DataAccessResourceFailureException.class);
    }
}
