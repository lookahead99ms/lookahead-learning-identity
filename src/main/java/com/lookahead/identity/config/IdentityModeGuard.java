package com.lookahead.identity.config;

import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

@Component
public final class IdentityModeGuard {
    public IdentityModeGuard(Environment environment) {
        if (!environment.acceptsProfiles(Profiles.of("accounts & oauth-server"))
                || environment.acceptsProfiles(Profiles.of("gateway | platform | resource | resource-server")))
            throw new IllegalStateException("Identity requires accounts and oauth-server exclusively");
        String deployment = environment.getProperty("app.deployment-environment", "");
        if (!Set.of("local", "dev", "prod").contains(deployment))
            throw new IllegalStateException("Identity requires canonical local, dev or prod environment");
        if (environment.acceptsProfiles(Profiles.of("production | development")))
            throw new IllegalStateException("Use canonical local, dev or prod profiles");
        for (String profile : Set.of("local", "dev", "prod")) {
            if (environment.acceptsProfiles(Profiles.of(profile)) && !profile.equals(deployment))
                throw new IllegalStateException("Identity profile must match its deployment environment");
        }
        if (!"local".equals(deployment) && environment.acceptsProfiles(Profiles.of("local-test")))
            throw new IllegalStateException("Synthetic identities require the local environment");
        if (!"local".equals(deployment)
                && !environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, true))
            throw new IllegalStateException("Identity requires secure cookies outside local development");
        if (!environment.getProperty("server.servlet.session.cookie.name", "LOOKAHEAD_SESSION")
                .matches("[A-Z][A-Z0-9_]{2,63}"))
            throw new IllegalStateException("Identity cookie name must be 3 to 64 uppercase letters, digits or underscores");
    }
}
