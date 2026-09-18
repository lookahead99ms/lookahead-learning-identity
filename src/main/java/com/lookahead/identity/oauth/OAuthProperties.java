package com.lookahead.identity.oauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.nio.file.Path;
import java.time.Duration;

/** Deployment values only. Scopes, PKCE, chain ordering and token rotation stay in Java. */
@ConfigurationProperties("app.oauth")
public record OAuthProperties(
        String issuer,
        String frontend,
        String clientSecret,
        @DefaultValue("lookahead-web-gateway") String clientId,
        @DefaultValue("http://identity:8080") String upstream,
        Path signingPrivateKey,
        Path signingPublicKey,
        @DefaultValue("3s") Duration connectTimeout,
        @DefaultValue("7s") Duration readTimeout,
        @DefaultValue("1m") Duration authorizationCodeTtl,
        @DefaultValue("5m") Duration accessTokenTtl,
        @DefaultValue("8h") Duration refreshTokenTtl) {

    public OAuthProperties {
        bounded("connect-timeout", connectTimeout, Duration.ofMillis(100), Duration.ofSeconds(10));
        bounded("read-timeout", readTimeout, Duration.ofMillis(100), Duration.ofSeconds(30));
        bounded("authorization-code-ttl", authorizationCodeTtl, Duration.ofSeconds(30), Duration.ofMinutes(2));
        bounded("access-token-ttl", accessTokenTtl, Duration.ofMinutes(1), Duration.ofMinutes(15));
        bounded("refresh-token-ttl", refreshTokenTtl, Duration.ofMinutes(5), Duration.ofHours(24));
        if (refreshTokenTtl.compareTo(accessTokenTtl) <= 0) {
            throw new IllegalStateException("app.oauth.refresh-token-ttl must exceed access-token-ttl");
        }
    }

    private static void bounded(String name, Duration value, Duration minimum, Duration maximum) {
        if (value == null || value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw new IllegalStateException("app.oauth." + name + " is outside the supported range");
        }
    }

    @Override public String toString() { return "OAuthProperties[redacted]"; }
}
