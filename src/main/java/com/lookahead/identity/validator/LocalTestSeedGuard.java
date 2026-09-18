package com.lookahead.identity.validator;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/** Fail closed before any seed runner can write synthetic credentials. */
@Component
public class LocalTestSeedGuard {
    public LocalTestSeedGuard(Environment environment) {
        boolean localTest = environment.acceptsProfiles(Profiles.of("local-test"));
        boolean seedEnabled = environment.getProperty("app.local-test.seed-enabled", Boolean.class, false);
        boolean localEnvironment = "local".equals(environment.getProperty("app.deployment-environment"));
        boolean productionProfile = environment.acceptsProfiles(Profiles.of("prod", "production"));
        if (localTest && (!localEnvironment || productionProfile)) {
            throw new IllegalStateException("local-test requires deployment environment local and cannot coexist with production profiles");
        }
        if (seedEnabled && (!localTest || !localEnvironment || productionProfile
                || !environment.acceptsProfiles(Profiles.of("accounts")))) {
            throw new IllegalStateException("Synthetic account seeding requires accounts, local-test, and deployment environment local");
        }
        boolean authorEnabled = environment.getProperty("app.local-test.author-enabled", Boolean.class, false);
        if (authorEnabled && !seedEnabled) {
            throw new IllegalStateException("Local author access requires explicitly enabled local synthetic accounts");
        }
        if (seedEnabled) {
            String password = environment.getProperty("app.local-test.seed-password", "");
            if (password.length() < 12 || password.getBytes(StandardCharsets.UTF_8).length > 72) {
                throw new IllegalStateException("Synthetic account seed password must be supplied using a local secret with at least 12 characters and at most 72 UTF-8 bytes");
            }
        }
    }
}
