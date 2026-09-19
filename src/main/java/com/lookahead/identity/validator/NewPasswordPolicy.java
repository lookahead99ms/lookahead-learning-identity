package com.lookahead.identity.validator;

import com.lookahead.identity.exception.AccountFailure;
import java.util.Locale;
import java.util.Set;

/** Full Unicode input, no composition rules. This small local denylist is not a breach-corpus check. */
public final class NewPasswordPolicy {
    private NewPasswordPolicy() { }
    private static final Set<String> COMMON = Set.of("passwordpassword", "password123456789", "123456789012345",
            "qwertyuiopasdfgh", "letmeinletmeinletmein", "correct horse battery staple");
    public static void validate(String password) {
        if(password==null || password.codePointCount(0,password.length())<15 || password.codePointCount(0,password.length())>128
                || password.codePoints().anyMatch(c->c>=0xD800 && c<=0xDFFF))
            throw new AccountFailure(422,"INVALID_PASSWORD","Use a password with 15 to 128 valid Unicode characters");
        if(COMMON.contains(password.toLowerCase(Locale.ROOT)))
            throw new AccountFailure(422,"PASSWORD_TOO_COMMON","Choose a less common password");
    }
}
