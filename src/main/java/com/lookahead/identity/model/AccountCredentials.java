package com.lookahead.identity.model;

import java.util.UUID;

/** Database credential record; never returned by a controller. */
public record AccountCredentials(UUID accountId, String username, String displayName,
                                 String passwordHash, boolean enabled) {
    @Override public String toString() { return "AccountCredentials[redacted]"; }
}
