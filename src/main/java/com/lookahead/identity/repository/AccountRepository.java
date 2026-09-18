package com.lookahead.identity.repository;

import com.lookahead.identity.model.AccountCredentials;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
@Profile("accounts")
public class AccountRepository {
    private final JdbcTemplate jdbc;

    public AccountRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean hasRegistrationProfile(UUID accountId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM account_profiles WHERE account_id=?)", Boolean.class, accountId));
    }

    public Optional<AccountCredentials> findById(UUID id) {
        var rows=jdbc.query("SELECT id,username,display_name,enabled FROM accounts WHERE id=?",
                (row,index)->new AccountCredentials(row.getObject("id",UUID.class),row.getString("username"),row.getString("display_name"),null,row.getBoolean("enabled")),id);
        return rows.stream().findFirst();
    }

    public Optional<AccountCredentials> findByUsername(String username) {
        var accounts = jdbc.query("""
                SELECT id, username, display_name, password_hash, enabled
                FROM accounts WHERE username = ?
                """, (row, index) -> new AccountCredentials(row.getObject("id", UUID.class),
                row.getString("username"), row.getString("display_name"),
                row.getString("password_hash"), row.getBoolean("enabled")), username);
        return accounts.size() == 1 ? Optional.of(accounts.getFirst()) : Optional.empty();
    }
}
