package com.lookahead.identity.service;

import com.lookahead.identity.dto.RegistrationRequest;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.security.AccountPrincipal;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@Profile("accounts")
public class RegistrationService {
    private static final Set<String> COUNTRIES = Set.of(Locale.getISOCountries());
    private final JdbcTemplate jdbc;
    private final Pbkdf2PasswordEncoder passwords = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    public RegistrationService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Transactional
    public AccountPrincipal register(RegistrationRequest request) {
        validate(request);
        String firstName = request.firstName().strip();
        String lastName = request.lastName().strip();
        String email = request.email().strip().toLowerCase(Locale.ROOT);
        UUID id = UUID.randomUUID();
        String displayName = firstName + " " + lastName;
        String hash = "{pbkdf2@SpringSecurity_v5_8}" + passwords.encode(request.password());
        try {
            jdbc.update("INSERT INTO accounts(id,username,display_name,password_hash) VALUES (?,?,?,?)",
                    id, email, displayName, hash);
            jdbc.update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,?,?,?,?)",
                    id, firstName, lastName, email, request.countryCode());
        } catch (DuplicateKeyException error) {
            throw new AccountFailure(409, "REGISTRATION_UNAVAILABLE", "An account could not be created with these details. Try signing in.");
        }
        // Registration never creates paid topic grants or imports another browser's data.
        return new AccountPrincipal(id, email, displayName, null, true);
    }

    public static void validate(RegistrationRequest request) {
        if (request == null || invalidName(request.firstName()) || invalidName(request.lastName()))
            throw invalid("Provide your first and last name, each using 1 to 79 characters.");
        String email = request.email() == null ? "" : request.email().strip();
        if (email.length() > 254 || !email.matches("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\\.[A-Za-z]{2,63}")
                || email.contains("..") || email.startsWith(".") || email.contains(".@"))
            throw invalid("Provide a valid email address.");
        if (request.password() == null || request.password().length() < 12 || request.password().length() > 128)
            throw invalid("Use a password with 12 to 128 characters.");
        if (!request.password().equals(request.confirmPassword())) throw invalid("Passwords must match.");
        if (request.countryCode() == null || !COUNTRIES.contains(request.countryCode()))
            throw invalid("Choose your country of residence from the country list.");
    }

    private static boolean invalidName(String name) {
        return name == null || name.isBlank() || name.strip().length() > 79 || name.codePoints().anyMatch(Character::isISOControl);
    }
    private static AccountFailure invalid(String message) { return new AccountFailure(422, "INVALID_REGISTRATION", message); }
}
