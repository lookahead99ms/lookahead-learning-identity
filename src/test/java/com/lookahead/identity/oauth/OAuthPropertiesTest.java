package com.lookahead.identity.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.mock.env.MockEnvironment;
import java.time.Duration;
import static org.assertj.core.api.Assertions.*;

class OAuthPropertiesTest {
    private MockEnvironment environment() {
        return new MockEnvironment().withProperty("app.deployment-environment", "local")
                .withProperty("app.oauth.issuer", "http://127.0.0.1:4331")
                .withProperty("app.oauth.frontend", "http://127.0.0.1:4331")
                .withProperty("app.oauth.client-secret", "synthetic-long-client-secret-for-testing");
    }

    @Test void bindsExistingNamesWithUnchangedDefaultsAndRedactsSecret() {
        var properties = bind(environment());
        assertThat(properties.connectTimeout()).isEqualTo(Duration.ofSeconds(3));
        assertThat(properties.readTimeout()).isEqualTo(Duration.ofSeconds(7));
        assertThat(properties.authorizationCodeTtl()).isEqualTo(Duration.ofMinutes(1));
        assertThat(properties.accessTokenTtl()).isEqualTo(Duration.ofMinutes(5));
        assertThat(properties.refreshTokenTtl()).isEqualTo(Duration.ofHours(8));
        assertThat(properties.upstream()).isEqualTo("http://identity:8080");
        assertThat(properties.clientId()).isEqualTo("lookahead-web-gateway");
        assertThat(OAuthSettings.from(environment()).clientId()).isEqualTo("lookahead-web-gateway");
        assertThat(properties.toString()).doesNotContain(properties.clientSecret());
    }

    @Test void bindsDurationOverridesAndRejectsUnboundedOrInvalidSettings() {
        assertThat(bind(environment().withProperty("app.oauth.read-timeout", "2s")).readTimeout())
                .isEqualTo(Duration.ofSeconds(2));
        for (String[] setting : new String[][]{{"connect-timeout", "0s"}, {"read-timeout", "31s"},
                {"authorization-code-ttl", "3m"}, {"access-token-ttl", "16m"},
                {"refresh-token-ttl", "25h"}, {"read-timeout", "invalid"}}) {
            assertThatThrownBy(() -> bind(environment().withProperty("app.oauth." + setting[0], setting[1])))
                    .isInstanceOf(org.springframework.boot.context.properties.bind.BindException.class);
        }
        assertThatThrownBy(() -> bind(environment().withProperty("app.oauth.refresh-token-ttl", "5m")))
                .isInstanceOf(org.springframework.boot.context.properties.bind.BindException.class);
    }

    @Test void requiredSecretsAndPublicOriginRulesStillFailClosed() {
        assertThatThrownBy(() -> OAuthSettings.from(environment().withProperty("app.oauth.client-secret", "short")))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> OAuthSettings.from(environment().withProperty("app.oauth.frontend", "http://other.example")))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> OAuthSettings.from(environment().withProperty("app.oauth.upstream", "http://service/path")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test void bindsDistinctDeploymentClientAndRejectsInvalidIdentities() {
        assertThat(OAuthSettings.from(environment().withProperty("app.oauth.client-id", "lookahead-web-gateway-dev")).clientId())
                .isEqualTo("lookahead-web-gateway-dev");
        for (String invalid : new String[]{"", "a", "Gateway", "../gateway", "gateway client", "x".repeat(81)})
            assertThatThrownBy(() -> OAuthSettings.from(environment().withProperty("app.oauth.client-id", invalid)))
                    .isInstanceOf(IllegalStateException.class);
    }

    private OAuthProperties bind(MockEnvironment environment) {
        return Binder.get(environment).bind("app.oauth", OAuthProperties.class).get();
    }
}
