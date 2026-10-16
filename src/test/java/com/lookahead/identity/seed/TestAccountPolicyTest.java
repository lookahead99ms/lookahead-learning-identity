package com.lookahead.identity.seed;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

class TestAccountPolicyTest {
    static MockEnvironment local() {
        var env = new MockEnvironment().withProperty("app.deployment-environment", "local")
                .withProperty("app.test-accounts.enabled", "true");
        env.setActiveProfiles("accounts", "local-test");
        return env;
    }
    @Test void onlyExplicitLocalFixtureConfigurationIsEnabled() {
        assertThatCode(() -> new TestAccountPolicy(local()).requireEnabled()).doesNotThrowAnyException();
        assertThatThrownBy(() -> new TestAccountPolicy(new MockEnvironment()).requireEnabled())
                .isInstanceOf(com.lookahead.identity.exception.AccountFailure.class);
        for (String value : new String[]{"dev", "prod", "production", "LOCAL", ""})
            assertThatThrownBy(() -> new TestAccountPolicy(local().withProperty("app.deployment-environment", value)).requireEnabled())
                    .isInstanceOf(com.lookahead.identity.exception.AccountFailure.class);
        for (String profile : new String[]{"prod", "production", "dev"}) {
            var env = local(); env.addActiveProfile(profile);
            assertThatThrownBy(() -> new TestAccountPolicy(env).requireEnabled())
                    .isInstanceOf(com.lookahead.identity.exception.AccountFailure.class);
        }
        var noAccounts = local(); noAccounts.setActiveProfiles("local-test");
        assertThatThrownBy(() -> new TestAccountPolicy(noAccounts).requireEnabled())
                .isInstanceOf(com.lookahead.identity.exception.AccountFailure.class);
        assertThatThrownBy(() -> new TestAccountPolicy(local().withProperty("app.test-accounts.enabled", "false")).requireEnabled())
                .isInstanceOf(com.lookahead.identity.exception.AccountFailure.class);
    }
}
