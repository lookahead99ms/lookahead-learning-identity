package com.lookahead.identity.controller;

import com.lookahead.learning.content.dto.AccountView;
import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.identity.dto.RegistrationRequest;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.service.AccountUserDetailsService;
import com.lookahead.identity.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile("accounts")
@ConditionalOnProperty(name = "app.accounts.registration-enabled", havingValue = "true")
public class RegistrationController {
    private final RegistrationService registration;
    private final AccountUserDetailsService users;
    private final com.lookahead.identity.signin.SignInSessionSupport sessions;
    public RegistrationController(RegistrationService registration, AccountUserDetailsService users, com.lookahead.identity.signin.SignInSessionSupport sessions) {
        this.registration = registration; this.users = users; this.sessions = sessions;
    }

    @PostMapping("/api/v1/auth/register")
    public ApiResponse<AccountView> register(@RequestBody RegistrationRequest payload,
            HttpServletRequest request, HttpServletResponse response) {
        var current = SecurityContextHolder.getContext().getAuthentication();
        if (current != null && current.isAuthenticated() && !(current instanceof AnonymousAuthenticationToken))
            throw new AccountFailure(409, "ALREADY_AUTHENTICATED", "Sign out before creating another account.");
        var principal = registration.register(payload);
        var admission=sessions.admit(principal,request,response);
        if(admission.signInId()==null)throw new AccountFailure(409,"SIGN_IN_LIMIT","Choose a sign-in to end.");
        principal=principal.withSignIn(admission.signInId());
        var authentication = UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
        new ChangeSessionIdAuthenticationStrategy().onAuthentication(authentication, request, response);
        new CsrfAuthenticationStrategy(new HttpSessionCsrfTokenRepository()).onAuthentication(authentication, request, response);
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        new HttpSessionSecurityContextRepository().saveContext(context, request, response);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(201);
        return ApiResponse.success(users.accountView(principal));
    }
}
