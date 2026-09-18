package com.lookahead.identity.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/** Security-filter database failures occur before MVC's account error advice. */
@Component
@Profile("oauth-server")
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class OAuthStorageFailureFilter extends OncePerRequestFilter {
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } catch (DataAccessException | CannotCreateTransactionException | TransactionSystemException failure) {
            if (response.isCommitted()) throw failure;
            response.reset();
            response.setStatus(503);
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().write("{\"status\":503,\"code\":\"ACCOUNT_STORAGE_UNAVAILABLE\","
                    + "\"message\":\"Account storage is unavailable; retain your work and retry\"}");
        }
    }
}
