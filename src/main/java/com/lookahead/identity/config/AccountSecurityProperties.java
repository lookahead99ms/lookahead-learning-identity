package com.lookahead.identity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Deployment choice; the chain still enforces the local fixture profile guard. */
@ConfigurationProperties("app.accounts")
public record AccountSecurityProperties(boolean registrationEnabled) { }
