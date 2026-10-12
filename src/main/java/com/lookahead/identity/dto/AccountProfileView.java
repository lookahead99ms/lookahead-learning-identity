package com.lookahead.identity.dto;

import java.util.UUID;

/** Identity facts only; product grants remain Domain-owned. */
public record AccountProfileView(UUID accountId, String username, String displayName,
        String themePreference, ProfileLinks links) {
    public static final String DEFAULT_THEME = "system";

    public AccountProfileView {
        if (themePreference == null) themePreference = DEFAULT_THEME;
        if (links == null) links = ProfileLinks.EMPTY;
    }

    /** A profile with no stored preference or links. */
    public AccountProfileView(UUID accountId, String username, String displayName) {
        this(accountId, username, displayName, DEFAULT_THEME, ProfileLinks.EMPTY);
    }

    /** Every key is always serialized; an unset link is {@code null}. */
    public record ProfileLinks(String github, String linkedin, String x, String website) {
        public static final ProfileLinks EMPTY = new ProfileLinks(null, null, null, null);
    }
}
