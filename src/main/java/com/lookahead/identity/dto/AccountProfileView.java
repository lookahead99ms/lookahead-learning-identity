package com.lookahead.identity.dto;

import java.util.UUID;

/** Identity facts only; product grants remain Domain-owned. */
public record AccountProfileView(UUID accountId, String username, String displayName) {}
