package com.lookahead.identity.seed;

import com.lookahead.identity.validator.LocalTestSeedGuard;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class LocalIdentitySeederTest {
    private MockEnvironment environment() {
        var environment = new MockEnvironment().withProperty("app.deployment-environment", "local")
                .withProperty("app.local-test.seed-enabled", "true")
                .withProperty("app.local-test.author-enabled", "true")
                .withProperty("app.local-test.seed-password", "synthetic-local-passphrase");
        environment.setActiveProfiles("accounts", "local-test");
        return environment;
    }
    @Test void fixturesUseStableSubjectsAndOnlyWriteIdentityRows() {
        var jdbc = mock(JdbcTemplate.class);
        var encoder = mock(PasswordEncoder.class);
        when(encoder.encode(anyString())).thenReturn("synthetic-password-hash");
        when(jdbc.queryForList(anyString(), eq(UUID.class), anyString())).thenReturn(List.of());
        var environment = environment();
        new LocalIdentitySeeder(jdbc, encoder, environment, new LocalTestSeedGuard(environment)).run(new DefaultApplicationArguments());
        UUID learner = UUID.nameUUIDFromBytes("lookahead-local-test:learner01".getBytes(StandardCharsets.UTF_8));
        UUID author = UUID.nameUUIDFromBytes("lookahead-local-author:author@lookahead.test".getBytes(StandardCharsets.UTF_8));
        verify(jdbc).update("INSERT INTO accounts(id,username,display_name,password_hash,enabled) VALUES (?,?,?,?,true)",
                learner, "learner01", "Synthetic Learner 01", "synthetic-password-hash");
        verify(jdbc).update("INSERT INTO accounts(id,username,display_name,password_hash,enabled) VALUES (?,?,?,?,true)",
                author, "author@lookahead.test", "Author", "synthetic-password-hash");
        assertThat(mockingDetails(jdbc).getInvocations()).allSatisfy(invocation -> {
            String sql = invocation.getArgument(0);
            assertThat(sql).contains("accounts").doesNotContain("account_grants", "plans", "publication");
        });
    }
    @Test void conflictingReservedIdentityDoesNotGetOverwritten() {
        var jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForList(anyString(), eq(UUID.class), eq("learner01"))).thenReturn(List.of(UUID.randomUUID()));
        var environment = environment();
        assertThatThrownBy(() -> new LocalIdentitySeeder(jdbc, mock(PasswordEncoder.class), environment,
                new LocalTestSeedGuard(environment)).run(new DefaultApplicationArguments()))
                .isInstanceOf(IllegalStateException.class);
        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }
}
