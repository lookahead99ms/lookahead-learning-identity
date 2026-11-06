package com.lookahead.identity.seed;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Fixed synthetic namespace: learner test accounts only (DLV-971). The existing owner is deliberately outside maintenance. */
public final class TestAccountRoster {
    public record Entry(String username) {
        public UUID accountId() {
            return UUID.nameUUIDFromBytes(("lookahead-local-test:" + username).getBytes(StandardCharsets.UTF_8));
        }
        public String email() { return username + "@lookahead.test"; }
        public String firstName() { return Character.toUpperCase(username.charAt(0)) + username.substring(1); }
    }
    private TestAccountRoster() {}
    public static List<Entry> entries() {
        var result = new ArrayList<Entry>();
        for (int n = 1; n <= 27; n++) result.add(new Entry("learner%02d".formatted(n)));
        return List.copyOf(result);
    }
}
