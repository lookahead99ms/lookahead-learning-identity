package com.lookahead.identity.validator;

import com.lookahead.identity.validator.LocalTestSeedGuard;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalTestSeedGuardTest {
    @Test void rejectsAuthorCapabilityWithoutExplicitSyntheticSeeding() {
        var env = new MockEnvironment().withProperty("app.local-test.author-enabled", "true");
        assertThatThrownBy(() -> new LocalTestSeedGuard(env)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void ordinaryFoundationNeedsNoSeedSettings() {
        assertThatCode(() -> new LocalTestSeedGuard(new MockEnvironment())).doesNotThrowAnyException();
    }

    @Test
    void acceptsExplicitLocalAccountSeeding() {
        assertThatCode(() -> new LocalTestSeedGuard(valid())).doesNotThrowAnyException();
    }

    @Test
    void rejectsMissingAccountOrLocalTestProfile() {
        for (String profile : new String[] {"accounts", "local-test", "local"}) {
            var environment = valid();
            environment.setActiveProfiles(profile);
            assertThatThrownBy(() -> new LocalTestSeedGuard(environment)).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void rejectsProductionMixedWithLocalTestEvenWithoutSeeding() {
        var environment = valid().withProperty("app.local-test.seed-enabled", "false");
        environment.setActiveProfiles("accounts", "local-test", "prod");
        assertThatThrownBy(() -> new LocalTestSeedGuard(environment)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsWrongDeploymentEnvironmentOrAbsentSecret() {
        assertThatThrownBy(() -> new LocalTestSeedGuard(valid().withProperty("app.deployment-environment", "production")))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new LocalTestSeedGuard(valid().withProperty("app.local-test.seed-password", "")))
                .isInstanceOf(IllegalStateException.class);
    }

    private MockEnvironment valid() {
        var environment = new MockEnvironment().withProperty("app.local-test.seed-enabled", "true")
                .withProperty("app.deployment-environment", "local")
                .withProperty("app.local-test.seed-password", "synthetic-unit-test-password");
        environment.setActiveProfiles("accounts", "local-test");
        return environment;
    }
}
