package com.lookahead.identity.config;

import com.lookahead.identity.verification.TokenVerificationSecurity;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

class IdentityIsolationTest {
    @Test void credentialRecordDoesNotExposeSensitiveIdentityInDiagnostics() {
        var credentials = new com.lookahead.identity.model.AccountCredentials(java.util.UUID.randomUUID(),
                "learner@example.test", "Private Name", "private-password-hash", true);
        assertThat(credentials.toString()).isEqualTo("AccountCredentials[redacted]");
    }
    private MockEnvironment environment() {
        var environment = new MockEnvironment().withProperty("app.deployment-environment", "local")
                .withProperty("app.sign-ins.maximum-active-sessions", "0");
        environment.setActiveProfiles("accounts", "oauth-server");
        return environment;
    }
    @Test void invalidRoleEnvironmentAndCookieCombinationsFailClosed() {
        assertThatCode(() -> new IdentityModeGuard(environment())).doesNotThrowAnyException();
        var env = environment(); env.setActiveProfiles("accounts");
        assertThatThrownBy(() -> new IdentityModeGuard(env)).isInstanceOf(IllegalStateException.class);
        // The retired Domain API profile must remain rejected as well.
        for (String role : new String[]{"gateway", "domain-api", "platform", "resource", "resource-server"}) {
            var invalid = environment(); invalid.addActiveProfile(role);
            assertThatThrownBy(() -> new IdentityModeGuard(invalid)).isInstanceOf(IllegalStateException.class);
        }
        var insecure = environment().withProperty("app.deployment-environment", "prod")
                .withProperty("server.servlet.session.cookie.secure", "false");
        assertThatThrownBy(() -> new IdentityModeGuard(insecure)).isInstanceOf(IllegalStateException.class);
        var misleading = environment(); misleading.addActiveProfile("production");
        assertThatThrownBy(() -> new IdentityModeGuard(misleading)).isInstanceOf(IllegalStateException.class);
        for (String mode : new String[]{"dev", "prod"}) {
            var localProfile = environment().withProperty("app.deployment-environment", mode);
            localProfile.addActiveProfile("local");
            assertThatThrownBy(() -> new IdentityModeGuard(localProfile)).isInstanceOf(IllegalStateException.class);
            var localMode = environment(); localMode.addActiveProfile(mode);
            assertThatThrownBy(() -> new IdentityModeGuard(localMode)).isInstanceOf(IllegalStateException.class);
        }
        var wrongCookie = environment().withProperty("server.servlet.session.cookie.name", "unsafe;cookie");
        assertThatThrownBy(() -> new IdentityModeGuard(wrongCookie)).isInstanceOf(IllegalStateException.class);
        var candidateCookie = environment().withProperty("server.servlet.session.cookie.name", "LOOKAHEAD_CANDIDATE_IDENTITY");
        assertThatCode(() -> new IdentityModeGuard(candidateCookie)).doesNotThrowAnyException();
    }
    @Test void databaseRejectsLegacyRolesOtherServicesAndMigrationRole() {
        for (String role : new String[]{"lookahead_app", "lookahead_platform_app", "lookahead_identity_migrator", "postgres"})
            assertThatThrownBy(() -> new AccountDatabaseConfiguration().accountDataSource(
                    "jdbc:postgresql://localhost/not-connected", role, "synthetic-secret", 3, 3000, 2000))
                    .isInstanceOf(IllegalStateException.class);
    }
    @Test void verifierCredentialMustBeStrongAndDistinctFromGateway() {
        assertThatThrownBy(() -> new TokenVerificationSecurity("short", "another-secret")).isInstanceOf(IllegalStateException.class);
        String secret = "synthetic-gateway-secret-with-32-characters";
        assertThatThrownBy(() -> new TokenVerificationSecurity(secret, secret)).isInstanceOf(IllegalStateException.class);
    }
    @Test void migrationContainsOnlyIdentityOwnershipAndIdentityRole() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/identity/V1__identity.sql"));
        assertThat(sql).contains("CREATE TABLE accounts", "CREATE TABLE account_profiles", "CREATE TABLE oauth2_authorization",
                "TO lookahead_identity_app").doesNotContain("CREATE TABLE plans", "account_grants", "support_receipts", "TO lookahead_app");
        for (String forbidden : new String[]{"com.lookahead.learning.content.repository.PlanRepository",
                "com.lookahead.identity.repository.PlanRepository", "com.lookahead.identity.service.ProtectedContentPolicy",
                "org.springframework.mail.javamail.JavaMailSender"})
            assertThatThrownBy(() -> Class.forName(forbidden)).isInstanceOf(ClassNotFoundException.class);
    }
}
