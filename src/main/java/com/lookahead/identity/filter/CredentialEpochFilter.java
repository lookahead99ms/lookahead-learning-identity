package com.lookahead.identity.filter;

import com.lookahead.identity.repository.AccountRepository;
import com.lookahead.identity.security.AccountPrincipal;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Every instance checks durable identity state before accepting an authenticated session. */
public final class CredentialEpochFilter extends OncePerRequestFilter {
    private final AccountRepository accounts;
    public CredentialEpochFilter(AccountRepository accounts) { this.accounts=accounts; }
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth!=null && auth.getPrincipal() instanceof AccountPrincipal principal) {
            boolean current;
            try { current=accounts.findById(principal.accountId()).filter(a->a.enabled() && a.credentialEpoch()==principal.credentialEpoch()).isPresent(); }
            catch(org.springframework.dao.DataAccessException error) {
                response.setStatus(503); response.setContentType("application/json"); response.setHeader("Cache-Control","no-store");
                response.getWriter().write("{\"status\":503,\"code\":\"ACCOUNT_STORAGE_UNAVAILABLE\",\"message\":\"Account storage is temporarily unavailable\"}"); return;
            }
            if(!current) {
                SecurityContextHolder.clearContext(); var session=request.getSession(false); if(session!=null) session.invalidate();
                response.setStatus(401); response.setContentType("application/json");response.setHeader("Cache-Control","no-store");
                response.getWriter().write("{\"status\":401,\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in to continue\"}");return;
            }
        }
        chain.doFilter(request,response);
    }
}
