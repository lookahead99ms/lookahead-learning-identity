package com.lookahead.identity.seed;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class TestAccountServiceTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    private final PasswordEncoder encoder = mock(PasswordEncoder.class, withSettings().mockMaker(org.mockito.MockMakers.PROXY));
    private final TestAccountPolicy policy = new TestAccountPolicy(TestAccountPolicyTest.local());
    private final TestAccountService service = new TestAccountService(jdbc, encoder, policy);
    private static final String LEARNER = "synthetic-learner-fixture-only";

    @Test void existingLearnersAreAdoptedWithoutUpdatingCredentialsProfilesOrOwner() {
        when(jdbc.queryForList(anyString(), eq(UUID.class), anyString())).thenAnswer(call -> {
            String name = call.getArgument(2);
            return TestAccountRoster.entries().stream().filter(e -> e.username().equals(name))
                    .map(TestAccountRoster.Entry::accountId).toList();
        });
        var results = service.seed(LEARNER);
        assertThat(results).hasSize(27).allMatch(r -> !r.created());
        verifyNoInteractions(encoder);
        verify(jdbc, never()).update(startsWith("UPDATE"), any(Object[].class));
        verify(jdbc, never()).update(startsWith("INSERT INTO accounts("), any(Object[].class));
        verify(jdbc, never()).update(contains("account_profiles"), any(Object[].class));
        assertThat(results.stream().map(TestAccountService.Result::username)).noneMatch(x -> x.startsWith("author"));
    }

    @Test void newAccountsUseTheLearnerPasswordAndReservedProfiles() {
        when(encoder.encode(anyString())).thenReturn("synthetic-encoded-value");
        var results = service.seed(LEARNER);
        assertThat(results).hasSize(27).allMatch(TestAccountService.Result::created);
        verify(encoder, times(27)).encode(LEARNER);
        verifyNoMoreInteractions(encoder);
        assertThat(results.stream().map(TestAccountService.Result::username))
                .allMatch(name -> name.matches("learner(0[1-9]|1[0-9]|2[0-7])"));
        var first = TestAccountRoster.entries().getFirst();
        verify(jdbc).update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,?,'Test',?,'US')",
                first.accountId(), "Learner01", "learner01@lookahead.test");
    }

    @Test void conflictingIdentityFailsWithoutReplacingIt() {
        when(jdbc.queryForList(anyString(), eq(UUID.class), eq("learner01"))).thenReturn(List.of(UUID.randomUUID()));
        assertThatThrownBy(() -> service.seed(LEARNER)).hasMessageContaining("reserved test username");
        verifyNoInteractions(encoder);
        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }

    @Test void disabledMaintenanceAndInvalidPasswordsNeverTouchStorage() {
        var disabled = new TestAccountService(jdbc, encoder,
                new TestAccountPolicy(TestAccountPolicyTest.local().withProperty("app.deployment-environment", "prod")));
        assertThatThrownBy(() -> disabled.seed(LEARNER)).hasMessageContaining("disabled");
        assertThatThrownBy(() -> disabled.rotate(LEARNER)).hasMessageContaining("disabled");
        assertThatThrownBy(() -> service.seed(null)).hasMessageContaining("password");
        assertThatThrownBy(() -> service.rotate("界".repeat(30))).hasMessageContaining("72 UTF-8");
        verifyNoInteractions(jdbc, encoder);
    }

    @Test void rotationDoesNotAdoptOrUpdateAccountsOutsideTheRegistry() {
        assertThat(service.rotate(LEARNER)).isZero();
        verifyNoInteractions(encoder);
        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }

    @Test void rotationRevokesSessionsForAnExplicitlyRegisteredLearner() {
        var first = TestAccountRoster.entries().getFirst();
        when(jdbc.queryForList(anyString(), eq(UUID.class), eq(first.accountId()), eq(first.username())))
                .thenReturn(List.of(first.accountId()));
        when(encoder.encode(LEARNER)).thenReturn("synthetic-encoded-value");
        when(jdbc.update(startsWith("UPDATE accounts SET password_hash"), eq("synthetic-encoded-value"), eq(first.accountId()), eq(first.username())))
                .thenReturn(1);
        assertThat(service.rotate(LEARNER)).isEqualTo(1);
        verify(jdbc).update("DELETE FROM oauth2_authorization WHERE principal_name=?", first.accountId().toString());
        verify(jdbc).update("UPDATE logical_sign_ins SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE account_id=?", first.accountId());
        verify(jdbc).update("UPDATE sign_in_challenges SET cancelled=true WHERE account_id=?", first.accountId());
    }

    @Test void provisionCreatesDisabledIndependentLoginAndOnlyActivateEnablesIt() {
        UUID accountId = UUID.randomUUID();
        String username = "test-0123456789abcdef01234567";
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), eq(accountId), eq(username))).thenReturn(false);
        when(encoder.encode(LEARNER)).thenReturn("synthetic-encoded-value");
        when(jdbc.update(startsWith("UPDATE accounts SET enabled=true"),
                eq(accountId), eq(username), eq(accountId), eq(username))).thenReturn(1);
        assertThat(service.provision(accountId, username, LEARNER).created()).isTrue();
        verify(jdbc).update("INSERT INTO accounts(id,username,display_name,password_hash,enabled) VALUES (?,?,?,?,false)",
                accountId, username, "Test Learner", "synthetic-encoded-value");
        verify(jdbc).update("INSERT INTO test_accounts(account_id,username,creation_state,last_changed_by) VALUES (?,?,'pending','managed-creation')",
                accountId, username);
        service.activate(accountId, username);
        verify(jdbc).update(startsWith("UPDATE accounts SET enabled=true"),
                eq(accountId), eq(username), eq(accountId), eq(username));
    }

    @Test void provisionRetryDoesNotChangeAnExistingPassword() {
        UUID accountId = UUID.randomUUID();
        String username = "test-0123456789abcdef01234567";
        when(jdbc.queryForList(contains("creation_state IN"), eq(UUID.class), eq(accountId), eq(username)))
                .thenReturn(List.of(accountId));
        assertThat(service.provision(accountId, username, LEARNER).created()).isFalse();
        verifyNoInteractions(encoder);
        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }

    @Test void provisionRejectsReservedNamesAndExistingRealAccounts() {
        UUID accountId = UUID.randomUUID();
        for (String reserved : List.of("learner01", "admin01", "coauthor01"))
            assertThatThrownBy(() -> service.provision(accountId, reserved, LEARNER))
                    .hasMessageContaining("Invalid managed test account");
        String username = "test-0123456789abcdef01234567";
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), eq(accountId), eq(username))).thenReturn(true);
        assertThatThrownBy(() -> service.provision(accountId, username, LEARNER))
                .hasMessageContaining("already in use");
        verifyNoInteractions(encoder);
    }

    @Test void disableRevokesLoginAndErasesProfileButKeepsRegistryTombstone() {
        UUID accountId = UUID.randomUUID();
        String username = "test-0123456789abcdef01234567";
        when(jdbc.queryForList(contains("creation_state IN ('pending','active','deleted')"), eq(UUID.class), eq(accountId), eq(username)))
                .thenReturn(List.of(accountId));
        service.disable(accountId, username);
        verify(jdbc).update(startsWith("UPDATE accounts SET enabled=false"), eq(accountId), eq(username));
        verify(jdbc).update("DELETE FROM oauth2_authorization WHERE principal_name=?", accountId.toString());
        verify(jdbc).update("DELETE FROM logical_sign_ins WHERE account_id=?", accountId);
        verify(jdbc).update("DELETE FROM sign_in_challenges WHERE account_id=?", accountId);
        verify(jdbc).update("DELETE FROM account_preferences WHERE account_id=?", accountId);
        verify(jdbc).update("DELETE FROM account_profile_links WHERE account_id=?", accountId);
        verify(jdbc).update("DELETE FROM account_profiles WHERE account_id=?", accountId);
        verify(jdbc).update(contains("creation_state='deleted'"), eq(accountId), eq(username));
        assertThatThrownBy(() -> service.activate(accountId, username)).hasMessageContaining("unavailable");
    }
    @Test void disablePermitsRosterLearnersButRejectsUnmanagedAndRetiredStaffIdentities() {
        var learner=TestAccountRoster.entries().getFirst();
        assertThatThrownBy(() -> service.disable(UUID.randomUUID(),learner.username())).hasMessageContaining("Invalid managed test account");
        // Retired staff names are no longer roster identities; their deterministic IDs prove nothing now.
        var retired=new TestAccountRoster.Entry("admin01");
        assertThatThrownBy(() -> service.disable(retired.accountId(),retired.username())).hasMessageContaining("Invalid managed test account");
        verify(jdbc, never()).update(anyString(), any(Object[].class));
        when(jdbc.queryForList(contains("creation_state IN ('pending','active','deleted')"), eq(UUID.class),
                eq(learner.accountId()), eq(learner.username()))).thenReturn(List.of(learner.accountId()));
        service.disable(learner.accountId(),learner.username());
        verify(jdbc).update(contains("creation_state='deleted'"),eq(learner.accountId()),eq(learner.username()));
        var last=TestAccountRoster.entries().getLast();
        when(jdbc.queryForList(contains("creation_state IN ('pending','active','deleted')"), eq(UUID.class),
                eq(last.accountId()), eq(last.username()))).thenReturn(List.of(last.accountId()));
        service.disable(last.accountId(),last.username());
        verify(jdbc).update(contains("creation_state='deleted'"),eq(last.accountId()),eq(last.username()));
    }
}
