package com.lookahead.identity.model;

import java.util.UUID;

/** Database credential record; never returned by a controller. */
public record AccountCredentials(UUID accountId, String username, String displayName,
                                 String passwordHash, boolean enabled, long credentialEpoch) {
    public AccountCredentials(UUID id, String username, String displayName, String hash, boolean enabled) { this(id, username, displayName, hash, enabled, 0); }
    @Override public String toString() { return "AccountCredentials[redacted]"; }
}
