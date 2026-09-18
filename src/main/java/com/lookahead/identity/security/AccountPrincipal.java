package com.lookahead.identity.security;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** The authenticated database identity; request payloads never choose an owner. */
public final class AccountPrincipal implements UserDetails, CredentialsContainer {
    private final UUID accountId;
    private final String username;
    private final String displayName;
    private final boolean enabled;
    private String password;

    public AccountPrincipal(UUID accountId, String username, String displayName, String password, boolean enabled) {
        this.accountId = accountId;
        this.username = username;
        this.displayName = displayName;
        this.password = password;
        this.enabled = enabled;
    }

    public UUID accountId() { return accountId; }
    public String displayName() { return displayName; }
    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return password; }
    @Override public boolean isEnabled() { return enabled; }
    @Override public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_LEARNER"));
    }
    @Override public void eraseCredentials() { password = null; }
}
