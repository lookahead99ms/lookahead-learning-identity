package com.lookahead.identity.service;

import com.lookahead.identity.dto.AccountProfileView;
import com.lookahead.identity.dto.AccountProfileView.ProfileLinks;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.validator.ProfileLinkPolicy;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
@Profile("accounts")
public class AccountProfileService {
    public static final Set<String> THEMES = Set.of("light", "dark", "system");
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private static final RowMapper<AccountProfileView> PROFILE = (row, index) ->
            new AccountProfileView(row.getObject("id", UUID.class), row.getString("username"), row.getString("display_name"),
                    row.getString("theme"), new ProfileLinks(row.getString("github"), row.getString("linkedin"),
                    row.getString("x"), row.getString("website")));
    /** One statement, one snapshot: the account, its stored theme (default system) and every link kind. */
    private static final String VIEW = """
            SELECT a.id, a.username, a.display_name, COALESCE(p.theme, 'system') AS theme,
              l.github, l.linkedin, l.x, l.website
            FROM %s a
            LEFT JOIN account_preferences p ON p.account_id = a.id
            CROSS JOIN LATERAL (SELECT
                max(url) FILTER (WHERE kind = 'github') AS github,
                max(url) FILTER (WHERE kind = 'linkedin') AS linkedin,
                max(url) FILTER (WHERE kind = 'x') AS x,
                max(url) FILTER (WHERE kind = 'website') AS website
              FROM account_profile_links WHERE account_id = a.id) l
            """;
    private static final String READ = VIEW.formatted("accounts") + "WHERE a.id=? AND a.enabled=true AND a.credential_epoch=?";

    public AccountProfileService(JdbcTemplate jdbc, PlatformTransactionManager manager) {
        this.jdbc = jdbc;
        this.transaction = new TransactionTemplate(manager);
    }

    public AccountProfileView read(UUID owner, long epoch) {
        return jdbc.query(READ, PROFILE, owner, epoch).stream().findFirst().orElseThrow(AccountProfileService::unauthorized);
    }

    public AccountProfileView update(UUID owner, long epoch, String displayName) {
        String name = validate(displayName);
        // The CTE's RETURNING row is the committed statement's authoritative account; no caller-selected owner or other columns.
        return jdbc.query("WITH updated AS (UPDATE accounts SET display_name=? WHERE id=? AND enabled=true AND credential_epoch=? "
                        + "RETURNING id, username, display_name) " + VIEW.formatted("updated"),
                PROFILE, name, owner, epoch).stream().findFirst().orElseThrow(AccountProfileService::unauthorized);
    }

    public AccountProfileView updateTheme(UUID owner, long epoch, String theme) {
        if (theme == null || !THEMES.contains(theme)) throw invalidPreferences();
        return locked(owner, epoch, () -> {
            jdbc.update("""
                    INSERT INTO account_preferences(account_id, theme, updated_at) VALUES (?, ?, now())
                    ON CONFLICT (account_id) DO UPDATE SET theme=EXCLUDED.theme, updated_at=EXCLUDED.updated_at
                    """, owner, theme);
        });
    }

    /** Replaces all four links atomically. Keys must be exactly {@link ProfileLinkPolicy#KINDS}. */
    public AccountProfileView updateLinks(UUID owner, long epoch, Map<String, String> links) {
        if (links == null || !links.keySet().equals(Set.copyOf(ProfileLinkPolicy.KINDS))) throw ProfileLinkPolicy.invalidShape();
        var stored = new LinkedHashMap<String, String>();
        for (String kind : ProfileLinkPolicy.KINDS) {
            String value = ProfileLinkPolicy.validate(kind, links.get(kind));
            if (value != null) stored.put(kind, value);
        }
        return locked(owner, epoch, () -> {
            jdbc.update("DELETE FROM account_profile_links WHERE account_id=?", owner);
            stored.forEach((kind, url) ->
                    jdbc.update("INSERT INTO account_profile_links(account_id, kind, url) VALUES (?, ?, ?)", owner, kind, url));
        });
    }

    /** Locks the current enabled account at this credential epoch, writes, and returns the view from the same transaction. */
    private AccountProfileView locked(UUID owner, long epoch, Runnable write) {
        return transaction.execute(status -> {
            var current = jdbc.query("SELECT enabled, credential_epoch FROM accounts WHERE id=? FOR UPDATE",
                    (row, index) -> row.getBoolean(1) && row.getLong(2) == epoch, owner);
            if (current.size() != 1 || !current.getFirst()) throw unauthorized();
            write.run();
            return read(owner, epoch);
        });
    }

    public static String validate(String value) {
        if (value == null) throw invalid();
        String name = value.strip();
        if (name.isEmpty() || name.codePointCount(0, name.length()) > 160
                || name.codePoints().anyMatch(code -> Character.isISOControl(code)
                    || code >= 0xD800 && code <= 0xDFFF)) throw invalid();
        return name;
    }

    public static AccountFailure invalidPreferences() {
        return new AccountFailure(422, "INVALID_PREFERENCES", "Choose light, dark or system.");
    }
    private static AccountFailure invalid() {
        return new AccountFailure(422, "INVALID_PROFILE", "Use a display name with 1 to 160 characters and no control characters.");
    }
    private static AccountFailure unauthorized() {
        return new AccountFailure(401, "AUTHENTICATION_REQUIRED", "Sign in again to manage your account.");
    }
}
