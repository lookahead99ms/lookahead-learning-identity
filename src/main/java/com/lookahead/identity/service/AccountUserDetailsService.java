package com.lookahead.identity.service;

import com.lookahead.learning.content.dto.AccountView;
import com.lookahead.identity.repository.AccountRepository;
import com.lookahead.identity.security.AccountPrincipal;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Profile("accounts")
public class AccountUserDetailsService implements UserDetailsService {
    private final AccountRepository accounts;
    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.core.env.Environment environment;
    public AccountUserDetailsService(AccountRepository accounts) { this.accounts = accounts; }

    public AccountView accountView(AccountPrincipal principal) {
        // Identity facts only. Product permissions are composed by Platform /api/v1/auth/me after OAuth.
        return new AccountView(principal.accountId(), principal.getUsername(), principal.displayName(),
                java.util.Set.of(), java.util.Set.of(), false);
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        if (username == null || username.length() > 254) {
            throw new UsernameNotFoundException("Invalid credentials");
        }
        var account = accounts.findByUsername(username.strip().toLowerCase(java.util.Locale.ROOT))
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));
        boolean syntheticAllowed = environment != null && environment.acceptsProfiles(org.springframework.core.env.Profiles.of("local-test"))
                && "local".equals(environment.getProperty("app.deployment-environment"))
                && !environment.acceptsProfiles(org.springframework.core.env.Profiles.of("prod", "production"));
        if (!syntheticAllowed && !accounts.hasRegistrationProfile(account.accountId()))
            throw new UsernameNotFoundException("Invalid credentials");
        return new AccountPrincipal(account.accountId(), account.username(), account.displayName(),
                account.passwordHash(), account.enabled());
    }
}
