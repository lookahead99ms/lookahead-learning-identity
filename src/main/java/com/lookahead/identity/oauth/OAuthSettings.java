package com.lookahead.identity.oauth;

import org.springframework.core.env.Environment;
import java.net.URI;

/** Deployment-owned endpoints; request headers and browser parameters never select an issuer or upstream. */
public record OAuthSettings(String issuer, String clientId, String clientSecret, String upstream, String frontend) {
    public static OAuthSettings from(Environment environment) {
        var properties = org.springframework.boot.context.properties.bind.Binder.get(environment)
                .bind("app.oauth", OAuthProperties.class).orElseThrow(() -> new IllegalStateException("app.oauth is required"));
        return from(properties, "local".equals(environment.getProperty("app.deployment-environment")));
    }

    static OAuthSettings from(OAuthProperties properties, boolean local) {
        String issuer = required(properties.issuer(), "app.oauth.issuer");
        String frontend = required(properties.frontend(), "app.oauth.frontend");
        String secret = required(properties.clientSecret(), "app.oauth.client-secret");
        String clientId = required(properties.clientId(), "app.oauth.client-id");
        if (!clientId.matches("[a-z][a-z0-9-]{2,79}"))
            throw new IllegalStateException("OAuth client ID must be 3 to 80 lowercase letters, digits or hyphens, starting with a letter");
        if (secret.length() < 32) throw new IllegalStateException("OAuth client secret must contain at least 32 characters");
        validatePublicUrl(issuer, local); validatePublicUrl(frontend, local);
        if (!issuer.equals(frontend)) throw new IllegalStateException("This first-party deployment uses one configured frontend/issuer origin");
        String upstream = properties.upstream();
        URI uri = URI.create(upstream);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null || !uri.getPath().isEmpty())
            throw new IllegalStateException("OAuth upstream must be an explicit service origin");
        return new OAuthSettings(issuer, clientId, secret, upstream, frontend);
    }
    private static String required(String value, String name) {
        if(value==null || value.isBlank()) throw new IllegalStateException(name+" is required");
        return value;
    }
    private static void validatePublicUrl(String value, boolean local) {
        URI uri=URI.create(value);
        boolean loopback=uri.getHost()!=null && java.util.Set.of("127.0.0.1","localhost").contains(uri.getHost());
        if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null || !uri.getPath().isEmpty()
                || !("https".equals(uri.getScheme()) || local && loopback && "http".equals(uri.getScheme())))
            throw new IllegalStateException("OAuth public origins require HTTPS except explicit local loopback");
    }
    @Override public String toString() { return "OAuthSettings[redacted]"; }
}
