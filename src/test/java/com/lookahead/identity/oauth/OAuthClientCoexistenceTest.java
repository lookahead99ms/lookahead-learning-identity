package com.lookahead.identity.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class OAuthClientCoexistenceTest {
    private final PasswordEncoder encoder = mock(PasswordEncoder.class,
            withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));

    private MockEnvironment environment(String clientId, int port) {
        return new MockEnvironment().withProperty("app.deployment-environment", "local")
                .withProperty("app.oauth.issuer", "http://127.0.0.1:" + port)
                .withProperty("app.oauth.frontend", "http://127.0.0.1:" + port)
                .withProperty("app.oauth.client-id", clientId)
                .withProperty("app.oauth.client-secret", clientId + "-synthetic-client-secret-for-test");
    }

    private RegisteredClient client(RegisteredClient old, String clientId, int port) {
        var environment = environment(clientId, port);
        var properties = Binder.get(environment).bind("app.oauth", OAuthProperties.class).get();
        when(encoder.encode(anyString())).thenAnswer(invocation -> "synthetic-encoded:" + invocation.getArgument(0, String.class));
        return OAuthClientConfiguration.configuredClient(old, encoder, OAuthSettings.from(environment), properties);
    }

    @Test void distinctOriginsUseDistinctRowsAndExactCallbacks() {
        var stable = client(null, "lookahead-web-gateway", 4300);
        var development = client(null, "lookahead-web-gateway-dev", 4301);
        assertThat(stable.getId()).isEqualTo("lookahead-web-gateway-v1");
        assertThat(development.getId()).isEqualTo("lookahead-web-gateway-dev-v1");
        var repository = new InMemoryRegisteredClientRepository(stable, development);
        assertThat(repository.findByClientId(stable.getClientId())).isSameAs(stable);
        assertThat(repository.findByClientId(development.getClientId())).isSameAs(development);
        assertThat(stable.getRedirectUris()).containsExactly("http://127.0.0.1:4300/login/oauth2/code/lookahead");
        assertThat(development.getRedirectUris()).containsExactly("http://127.0.0.1:4301/login/oauth2/code/lookahead");
        assertThat(stable.getPostLogoutRedirectUris()).containsExactly("http://127.0.0.1:4300/sign-in");
        assertThat(development.getPostLogoutRedirectUris()).containsExactly("http://127.0.0.1:4301/sign-in");
        assertThat(stable.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(development.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(development.getTokenSettings().isReuseRefreshTokens()).isFalse();
    }

    @Test void reconfiguringOneClientPreservesTheOtherAndItsExistingIdentity() {
        var stable = client(null, "lookahead-web-gateway", 4316);
        var development = client(null, "lookahead-web-gateway-dev", 4301);
        var repository = new InMemoryRegisteredClientRepository(stable, development);
        when(encoder.matches(anyString(), eq(stable.getClientSecret()))).thenReturn(true);
        var moved = client(stable, "lookahead-web-gateway", 4300);
        repository.save(moved);
        assertThat(moved.getId()).isEqualTo(stable.getId());
        assertThat(moved.getClientSecret()).isEqualTo(stable.getClientSecret());
        assertThat(moved.getRedirectUris()).containsExactly("http://127.0.0.1:4300/login/oauth2/code/lookahead");
        assertThat(repository.findByClientId("lookahead-web-gateway-dev")).isSameAs(development);
    }

    @Test void cannotReuseAnotherClientsPersistedIdentity() {
        var stable = client(null, "lookahead-web-gateway", 4300);
        assertThatThrownBy(() -> client(stable, "lookahead-web-gateway-dev", 4301))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test void separateClientsDoNotPermitMismatchedFrontendAndIssuer() {
        var environment = environment("lookahead-web-gateway-dev", 4301)
                .withProperty("app.oauth.issuer", "http://127.0.0.1:4300");
        assertThatThrownBy(() -> OAuthSettings.from(environment)).isInstanceOf(IllegalStateException.class);
    }
}
