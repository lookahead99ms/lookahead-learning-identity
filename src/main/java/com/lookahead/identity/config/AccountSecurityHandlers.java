package com.lookahead.identity.config;

import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.AccountUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.csrf.CsrfException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

/** Stable JSON contracts shared by the account chain's authentication handlers. */
public class AccountSecurityHandlers {
    private final ObjectMapper mapper;
    private final AccountUserDetailsService users;

    public AccountSecurityHandlers(ObjectMapper mapper, AccountUserDetailsService users) {
        this.mapper = mapper;
        this.users = users;
    }

    void authenticationRequired(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationException exception) throws IOException {
        error(request, response, 401, "AUTHENTICATION_REQUIRED", "Sign in to continue");
    }

    void accessDenied(HttpServletRequest request, HttpServletResponse response,
                      AccessDeniedException exception) throws IOException {
        boolean csrf = exception instanceof CsrfException;
        error(request, response, 403, csrf ? "CSRF_INVALID" : "ACCESS_DENIED",
                csrf ? "Refresh the security token and retry" : "Access denied");
    }

    void loginSucceeded(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) throws IOException {
        try {
            write(response, 200, ApiResponse.success(users.accountView((AccountPrincipal) authentication.getPrincipal())));
        } catch (com.lookahead.identity.exception.AccountFailure stale) {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
            var session=request.getSession(false); if(session!=null)session.invalidate();
            error(request,response,401,"AUTHENTICATION_REQUIRED","Sign in to continue");
        } catch (org.springframework.dao.DataAccessException unavailable) {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
            var session=request.getSession(false); if(session!=null)session.invalidate();
            error(request,response,503,"ACCOUNT_STORAGE_UNAVAILABLE","Account storage is temporarily unavailable");
        }
    }

    void loginFailed(HttpServletRequest request, HttpServletResponse response,
                     AuthenticationException exception) throws IOException {
        boolean unavailable = exception instanceof AuthenticationServiceException;
        error(request, response, unavailable ? 503 : 401,
                unavailable ? "ACCOUNT_STORAGE_UNAVAILABLE" : "INVALID_CREDENTIALS",
                unavailable ? "Account storage is temporarily unavailable. Retry shortly." : "Invalid username or password");
    }

    private void error(HttpServletRequest request, HttpServletResponse response,
                       int status, String code, String message) throws IOException {
        write(response, status, Map.of("status", status, "code", code, "message", message,
                "path", request.getRequestURI(), "timestamp", Instant.now()));
    }

    private void write(HttpServletResponse response, int status, Object body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(mapper.writeValueAsString(body));
    }
}
