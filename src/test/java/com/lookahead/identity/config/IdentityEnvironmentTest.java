package com.lookahead.identity.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import static org.assertj.core.api.Assertions.*;

class IdentityEnvironmentTest {
    private ApplicationContextRunner configuration(String profile, String mode) {
        return new ApplicationContextRunner().withInitializer(new ConfigDataApplicationContextInitializer())
                .withUserConfiguration(IdentityModeGuard.class)
                .withPropertyValues("spring.profiles.active=" + profile, "LOOKAHEAD_ENVIRONMENT=" + mode,
                        "LOOKAHEAD_IDENTITY_JDBC_URL=jdbc:postgresql://127.0.0.1/not-connected",
                        "LOOKAHEAD_IDENTITY_DB_PASSWORD=synthetic-only");
    }
    @Test void explicitModesBindRoleProfilesAndKeepSecretsOutsideDefaults() {
        for (String mode : new String[]{"local", "dev", "prod"}) {
            configuration(mode, mode).run(context -> {
                assertThat(context).hasNotFailed();
                var environment = context.getEnvironment();
                assertThat(environment.getActiveProfiles()).contains("accounts", "oauth-server", mode);
                assertThat(environment.getProperty("app.deployment-environment")).isEqualTo(mode);
                assertThat(environment.getProperty("spring.datasource.username")).isEqualTo("lookahead_identity_app");
                assertThat(environment.getProperty("server.address")).isEqualTo("127.0.0.1");
                assertThat(environment.getProperty("server.forward-headers-strategy")).isEqualTo("none");
                assertThat(environment.getProperty("server.servlet.session.cookie.secure", Boolean.class)).isEqualTo(!"local".equals(mode));
            });
        }
    }
    @Test void profileCannotMaskContradictoryEnvironmentAndCookieOverride() {
        for (String mode : new String[]{"dev", "prod"}) {
            configuration("local", mode).run(context -> assertThat(context).hasFailed());
            configuration(mode, "local").run(context -> assertThat(context).hasFailed());
            configuration(mode, mode).withPropertyValues("server.servlet.session.cookie.secure=false")
                    .run(context -> assertThat(context).hasFailed());
        }
        configuration("local", "").run(context -> assertThat(context).hasFailed());
        configuration("dev", "development").run(context -> assertThat(context).hasFailed());
        configuration("prod", "production").run(context -> assertThat(context).hasFailed());
    }
}
