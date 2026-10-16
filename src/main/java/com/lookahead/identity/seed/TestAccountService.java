package com.lookahead.identity.seed;

import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.validator.NewPasswordPolicy;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Identity-owned maintenance; never updates product grants or study plans. */
@Service
@org.springframework.context.annotation.Profile("accounts")
public class TestAccountService {
    public record Result(UUID accountId, String username, boolean created) {}
    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;
    private final TestAccountPolicy policy;
    public TestAccountService(JdbcTemplate jdbc, PasswordEncoder encoder, TestAccountPolicy policy) {
        this.jdbc = jdbc; this.encoder = encoder; this.policy = policy;
    }

    @Transactional
    public List<Result> seed(String learnerPassword, String staffPassword) {
        policy.requireEnabled();
        validatePassword(learnerPassword);
        validatePassword(staffPassword);
        // Serialize maintenance, including concurrent startup calls, across instances.
        jdbc.execute("LOCK TABLE test_accounts IN SHARE ROW EXCLUSIVE MODE");
        return TestAccountRoster.entries().stream().map(entry -> seed(entry,
                entry.staff() ? staffPassword : learnerPassword)).toList();
    }

    private Result seed(TestAccountRoster.Entry entry, String password) {
        var existing = jdbc.queryForList("SELECT id FROM accounts WHERE username=?", UUID.class, entry.username());
        if (!existing.isEmpty() && !entry.accountId().equals(existing.getFirst()))
            throw new AccountFailure(409, "TEST_ACCOUNT_CONFLICT", "A reserved test username has a different identity.");
        boolean created = existing.isEmpty();
        if (created) {
            jdbc.update("INSERT INTO accounts(id,username,display_name,password_hash,enabled) VALUES (?,?,?,?,true)",
                    entry.accountId(), entry.username(), entry.firstName() + " Test", encoder.encode(password));
            jdbc.update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,?,'Test',?,'US')",
                    entry.accountId(), entry.firstName(), entry.email());
        }
        // Adoption marks an existing fixture without replacing any of its data.
        jdbc.update("INSERT INTO test_accounts(account_id,username,last_changed_by) VALUES (?,?,?) ON CONFLICT (account_id) DO NOTHING",
                entry.accountId(), entry.username(), created ? "test-account-seed" : "existing-fixture");
        return new Result(entry.accountId(), entry.username(), created);
    }

    @Transactional
    public int rotate(String learnerPassword, String staffPassword) {
        policy.requireEnabled();
        validatePassword(learnerPassword);
        validatePassword(staffPassword);
        jdbc.execute("LOCK TABLE test_accounts IN SHARE ROW EXCLUSIVE MODE");
        int updated = 0;
        for (var entry : TestAccountRoster.entries()) {
            var registered = jdbc.queryForList("SELECT account_id FROM test_accounts WHERE account_id=? AND username=?",
                    UUID.class, entry.accountId(), entry.username());
            if (registered.isEmpty()) continue;
            int count = jdbc.update("UPDATE accounts SET password_hash=?,credential_epoch=credential_epoch+1,password_failure_count=0,password_failure_window=NULL WHERE id=? AND username=?",
                    encoder.encode(entry.staff() ? staffPassword : learnerPassword), entry.accountId(), entry.username());
            if (count != 1) throw new AccountFailure(409, "TEST_ACCOUNT_CONFLICT", "A test account changed during maintenance.");
            jdbc.update("DELETE FROM oauth2_authorization WHERE principal_name=?", entry.accountId().toString());
            jdbc.update("UPDATE logical_sign_ins SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE account_id=?", entry.accountId());
            jdbc.update("UPDATE sign_in_challenges SET cancelled=true WHERE account_id=?", entry.accountId());
            jdbc.update("UPDATE test_accounts SET last_changed_by='test-account-password-rotation',last_changed_at=clock_timestamp() WHERE account_id=?", entry.accountId());
            updated += count;
        }
        return updated;
    }

    private static void validatePassword(String password) {
        NewPasswordPolicy.validate(password);
        if (password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 72)
            throw new AccountFailure(422, "INVALID_PASSWORD", "Fixture passwords must fit within 72 UTF-8 bytes.");
    }
}
