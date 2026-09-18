package com.lookahead.identity.service;

import com.lookahead.identity.dto.RegistrationRequest;
import com.lookahead.identity.exception.AccountFailure;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.dao.DuplicateKeyException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class RegistrationServiceTest {
    private RegistrationRequest valid() {
        return new RegistrationRequest("Avery", "Learner", "AVERY@example.test", "long test passphrase", "long test passphrase", "US");
    }
    @Test void rejectsMissingCountryMismatchAndInvalidIdentityBeforeWriting() {
        var jdbc = mock(JdbcTemplate.class);
        var service = new RegistrationService(jdbc);
        for (var request : new RegistrationRequest[] {
                new RegistrationRequest("Avery", "Learner", "a@example.test", "long test passphrase", "long test passphrase", null),
                new RegistrationRequest("Avery", "Learner", "a@example.test", "long test passphrase", "long test passphrase", "ZZ"),
                new RegistrationRequest("Avery", "Learner", "a@example.test", "long test passphrase", "different", "US"),
                new RegistrationRequest("", "Learner", "a@example.test", "long test passphrase", "long test passphrase", "US"),
                new RegistrationRequest("Avery", "Learner", "not-email", "long test passphrase", "long test passphrase", "US") }) {
            assertThatThrownBy(() -> service.register(request)).isInstanceOf(AccountFailure.class);
        }
        verifyNoInteractions(jdbc);
    }
    @Test void normalizesEmailHashesPasswordAndCreatesNoPaidGrant() {
        var jdbc = mock(JdbcTemplate.class);
        var service = new RegistrationService(jdbc);
        var account = service.register(valid());
        assertThat(account.getUsername()).isEqualTo("avery@example.test");
        assertThat(account.getPassword()).isNull();
        verify(jdbc).update(eq("INSERT INTO accounts(id,username,display_name,password_hash) VALUES (?,?,?,?)"), eq(account.accountId()), eq("avery@example.test"), eq("Avery Learner"), argThat((Object hash) -> PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(valid().password(), (String) hash)));
        verify(jdbc).update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,?,?,?,?)", account.accountId(), "Avery", "Learner", "avery@example.test", "US");
        verifyNoMoreInteractions(jdbc);
        assertThat(valid().toString()).doesNotContain(valid().password(), valid().email());
    }
    @Test void duplicateIdentityDoesNotReturnDatabaseDetails() {
        var jdbc = mock(JdbcTemplate.class);
        when(jdbc.update(anyString(), any(Object[].class))).thenThrow(new DuplicateKeyException("private database detail"));
        assertThatThrownBy(() -> new RegistrationService(jdbc).register(valid()))
                .isInstanceOf(AccountFailure.class).hasMessageNotContaining("private database detail");
    }
}
