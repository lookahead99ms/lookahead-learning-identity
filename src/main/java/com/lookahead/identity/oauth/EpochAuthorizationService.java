package com.lookahead.identity.oauth;

import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Serializes authorization publication with credential rotation; stale refresh/code saves fail closed. */
public final class EpochAuthorizationService implements OAuth2AuthorizationService {
    public static final String EPOCH = "lookahead.credential-epoch";
    private final OAuth2AuthorizationService delegate;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    public EpochAuthorizationService(OAuth2AuthorizationService delegate, JdbcTemplate jdbc, PlatformTransactionManager manager) {
        this.delegate=delegate; this.jdbc=jdbc; this.transaction=new TransactionTemplate(manager);
    }
    private boolean current(OAuth2Authorization value, boolean lock) {
        if (value == null) return false;
        UUID id;
        try { id=UUID.fromString(value.getPrincipalName()); } catch (IllegalArgumentException e) { return false; }
        var rows=jdbc.query("SELECT credential_epoch,enabled FROM accounts WHERE id=?"+(lock?" FOR UPDATE":""),
                (rs,n)-> rs.getBoolean("enabled") && Long.toString(rs.getLong("credential_epoch")).equals(value.getAttribute(EPOCH)),id);
        return rows.size()==1 && rows.getFirst();
    }
    @Override public void save(OAuth2Authorization value) {
        transaction.executeWithoutResult(status->{
            if (!current(value,true)) throw new OAuth2AuthenticationException(new OAuth2Error("invalid_grant"));
            delegate.save(value);
        });
    }
    @Override public void remove(OAuth2Authorization value) { delegate.remove(value); }
    @Override public OAuth2Authorization findById(String id) { var value=delegate.findById(id); return current(value,false)?value:null; }
    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType type) { var value=delegate.findByToken(token,type); return current(value,false)?value:null; }
}
