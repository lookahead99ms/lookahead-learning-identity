package com.lookahead.identity.seed;

import com.lookahead.identity.validator.LocalTestSeedGuard;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Synthetic identity fixtures only; grants are seeded by Platform using these stable subjects. */
@Component
@Profile("accounts & local-test")
@ConditionalOnProperty(name = "app.local-test.seed-enabled", havingValue = "true")
public class LocalIdentitySeeder implements ApplicationRunner {
    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;
    private final Environment environment;
    public LocalIdentitySeeder(JdbcTemplate jdbc, PasswordEncoder encoder, Environment environment,
            LocalTestSeedGuard guard) {
        this.jdbc = jdbc; this.encoder = encoder; this.environment = environment;
    }
    @Override @Transactional public void run(ApplicationArguments arguments) {
        for (int number = 1; number <= 10; number++) {
            String username = "learner%02d".formatted(number);
            create("lookahead-local-test:" + username, username, "Synthetic Learner %02d".formatted(number));
        }
        if (environment.getProperty("app.local-test.author-enabled", Boolean.class, false))
            create("lookahead-local-author:author@lookahead.test", "author@lookahead.test", "Author");
    }
    private void create(String seed, String username, String displayName) {
        UUID subject = UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
        var existing = jdbc.queryForList("SELECT id FROM accounts WHERE username=?", UUID.class, username);
        if (!existing.isEmpty()) {
            if (!subject.equals(existing.getFirst()))
                throw new IllegalStateException("Reserved synthetic identity does not match its stable subject");
            return;
        }
        jdbc.update("INSERT INTO accounts(id,username,display_name,password_hash,enabled) VALUES (?,?,?,?,true)",
                subject, username, displayName, encoder.encode(environment.getRequiredProperty("app.local-test.seed-password")));
    }
}
