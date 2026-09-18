package com.lookahead.identity.oauth;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Keep nested authorization/client JDBC lookups on one transaction-bound connection. */
public final class TransactionalAuthorizationService implements OAuth2AuthorizationService {
    private final OAuth2AuthorizationService delegate;
    private final TransactionTemplate transaction;

    public TransactionalAuthorizationService(OAuth2AuthorizationService delegate,
            PlatformTransactionManager transactionManager) {
        this.delegate = delegate;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    @Override public void save(OAuth2Authorization authorization) {
        transaction.executeWithoutResult(status -> delegate.save(authorization));
    }

    @Override public void remove(OAuth2Authorization authorization) {
        transaction.executeWithoutResult(status -> delegate.remove(authorization));
    }

    @Override public OAuth2Authorization findById(String id) {
        return transaction.execute(status -> delegate.findById(id));
    }

    @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
        return transaction.execute(status -> delegate.findByToken(token, type));
    }
}
