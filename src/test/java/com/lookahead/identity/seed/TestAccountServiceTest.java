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
    private static final String LEARNER = "synthetic-learner-fixture-only", STAFF = "synthetic-staff-fixture-only";

    @Test void existingLearnersAreAdoptedWithoutUpdatingCredentialsProfilesOrOwner() {
        when(jdbc.queryForList(anyString(), eq(UUID.class), anyString())).thenAnswer(call -> {
            String name = call.getArgument(2);
            return TestAccountRoster.entries().stream().filter(e -> e.username().equals(name))
                    .map(TestAccountRoster.Entry::accountId).toList();
        });
        var results = service.seed(LEARNER, STAFF);
        assertThat(results).hasSize(35).allMatch(r -> !r.created());
        verifyNoInteractions(encoder);
        verify(jdbc, never()).update(startsWith("UPDATE"), any(Object[].class));
        verify(jdbc, never()).update(startsWith("INSERT INTO accounts("), any(Object[].class));
        verify(jdbc, never()).update(contains("account_profiles"), any(Object[].class));
        assertThat(results.stream().map(TestAccountService.Result::username)).noneMatch(x -> x.startsWith("author"));
    }

    @Test void newAccountsUseTheTwoSeparatePasswordsAndReservedProfiles() {
        when(encoder.encode(anyString())).thenReturn("synthetic-encoded-value");
        var results = service.seed(LEARNER, STAFF);
        assertThat(results).hasSize(35).allMatch(TestAccountService.Result::created);
        verify(encoder, times(27)).encode(LEARNER);
        verify(encoder, times(8)).encode(STAFF);
        var first = TestAccountRoster.entries().getFirst();
        verify(jdbc).update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,?,'Test',?,'US')",
                first.accountId(), "Learner01", "learner01@lookahead.test");
    }

    @Test void conflictingIdentityFailsWithoutReplacingIt() {
        when(jdbc.queryForList(anyString(), eq(UUID.class), eq("learner01"))).thenReturn(List.of(UUID.randomUUID()));
        assertThatThrownBy(() -> service.seed(LEARNER, STAFF)).hasMessageContaining("reserved test username");
        verifyNoInteractions(encoder);
        verify(jdbc, never()).update(anyString(), any(Object[].class));
    }

    @Test void disabledMaintenanceAndInvalidPasswordsNeverTouchStorage() {
        var disabled = new TestAccountService(jdbc, encoder,
                new TestAccountPolicy(TestAccountPolicyTest.local().withProperty("app.deployment-environment", "prod")));
        assertThatThrownBy(() -> disabled.seed(LEARNER, STAFF)).hasMessageContaining("disabled");
        assertThatThrownBy(() -> disabled.rotate(LEARNER, STAFF)).hasMessageContaining("disabled");
        assertThatThrownBy(() -> service.seed(null, STAFF)).hasMessageContaining("password");
        assertThatThrownBy(() -> service.rotate(LEARNER, "界".repeat(30))).hasMessageContaining("72 UTF-8");
        verifyNoInteractions(jdbc, encoder);
    }

    @Test void rotationDoesNotAdoptOrUpdateAccountsOutsideTheRegistry() {
        assertThat(service.rotate(LEARNER, STAFF)).isZero();
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
        assertThat(service.rotate(LEARNER, STAFF)).isEqualTo(1);
        verify(jdbc).update("DELETE FROM oauth2_authorization WHERE principal_name=?", first.accountId().toString());
        verify(jdbc).update("UPDATE logical_sign_ins SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE account_id=?", first.accountId());
        verify(jdbc).update("UPDATE sign_in_challenges SET cancelled=true WHERE account_id=?", first.accountId());
    }
}
