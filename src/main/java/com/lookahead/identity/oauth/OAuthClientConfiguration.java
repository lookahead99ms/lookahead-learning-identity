package com.lookahead.identity.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration
@Profile("oauth-server")
public class OAuthClientConfiguration {
    @Bean RegisteredClientRepository registeredClients(JdbcTemplate jdbc, PasswordEncoder encoder, OAuthSettings settings, OAuthProperties properties) {
        var repository=new JdbcRegisteredClientRepository(jdbc);
        var old=repository.findByClientId(settings.clientId());
        repository.save(configuredClient(old, encoder, settings, properties));
        return repository;
    }

    /** Each deployment owns a distinct row; the default preserves the existing registration ID. */
    static RegisteredClient configuredClient(RegisteredClient old, PasswordEncoder encoder,
                                             OAuthSettings settings, OAuthProperties properties) {
        if (old != null && !settings.clientId().equals(old.getClientId()))
            throw new IllegalStateException("Existing OAuth registration belongs to a different client");
        String encoded=old!=null && encoder.matches(settings.clientSecret(),old.getClientSecret()) ? old.getClientSecret() : encoder.encode(settings.clientSecret());
        return RegisteredClient.withId(old==null?settings.clientId()+"-v1":old.getId())
                .clientId(settings.clientId()).clientSecret(encoded).clientName("Look Ahead")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(settings.frontend()+"/login/oauth2/code/lookahead")
                .postLogoutRedirectUri(settings.frontend()+"/sign-in")
                .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope("account").scope("content").scope("support")
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(properties.authorizationCodeTtl())
                        .accessTokenTimeToLive(properties.accessTokenTtl()).refreshTokenTimeToLive(properties.refreshTokenTtl()).reuseRefreshTokens(false).build()).build();
    }
    @Bean OAuth2AuthorizationService authorizations(JdbcTemplate jdbc, RegisteredClientRepository clients,
            org.springframework.transaction.PlatformTransactionManager transactions, com.lookahead.identity.signin.SignInRegistry signIns) {
        return new TransactionalAuthorizationService(
                new StablePrincipalAuthorizationService(new EpochAuthorizationService(new JdbcOAuth2AuthorizationService(jdbc,clients), jdbc, transactions, signIns)), transactions);
    }
    @Bean OAuth2AuthorizationConsentService consents(JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc,clients);
    }
}
