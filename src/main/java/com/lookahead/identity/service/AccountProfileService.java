package com.lookahead.identity.service;

import com.lookahead.identity.dto.AccountProfileView;
import com.lookahead.identity.exception.AccountFailure;
import java.util.UUID;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

@Service
@Profile("accounts")
public class AccountProfileService {
    private final JdbcTemplate jdbc;
    private static final RowMapper<AccountProfileView> PROFILE = (row, index) ->
            new AccountProfileView(row.getObject("id", UUID.class), row.getString("username"), row.getString("display_name"));

    public AccountProfileService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public AccountProfileView read(UUID owner, long epoch) {
        return jdbc.query("SELECT id, username, display_name FROM accounts WHERE id=? AND enabled=true AND credential_epoch=?", PROFILE, owner, epoch)
                .stream().findFirst().orElseThrow(AccountProfileService::unauthorized);
    }

    public AccountProfileView update(UUID owner, long epoch, String displayName) {
        String name = validate(displayName);
        // RETURNING reports the committed statement's authoritative values; no caller-selected owner or other columns.
        return jdbc.query("UPDATE accounts SET display_name=? WHERE id=? AND enabled=true AND credential_epoch=? RETURNING id, username, display_name",
                PROFILE, name, owner, epoch).stream().findFirst().orElseThrow(AccountProfileService::unauthorized);
    }

    public static String validate(String value) {
        if (value == null) throw invalid();
        String name = value.strip();
        if (name.isEmpty() || name.codePointCount(0, name.length()) > 160
                || name.codePoints().anyMatch(code -> Character.isISOControl(code)
                    || code >= 0xD800 && code <= 0xDFFF)) throw invalid();
        return name;
    }

    private static AccountFailure invalid() {
        return new AccountFailure(422, "INVALID_PROFILE", "Use a display name with 1 to 160 characters and no control characters.");
    }
    private static AccountFailure unauthorized() {
        return new AccountFailure(401, "AUTHENTICATION_REQUIRED", "Sign in again to manage your account.");
    }
}
