package com.lookahead.identity.controller;

import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.AccountUserDetailsService;

import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.dto.AccountView;
import com.lookahead.learning.content.dto.CsrfView;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile("accounts")
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AccountUserDetailsService users;
    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.core.env.Environment environment;

    public AuthController(AccountUserDetailsService users) { this.users = users; }

    @GetMapping("/options")
    public ApiResponse<java.util.Map<String, Boolean>> options(jakarta.servlet.http.HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        return ApiResponse.success(java.util.Map.of("registration", environment.getProperty("app.accounts.registration-enabled", Boolean.class, false), "google", false, "oauth", environment.acceptsProfiles(org.springframework.core.env.Profiles.of("oauth-server"))));
    }

    @GetMapping("/csrf")
    public ApiResponse<CsrfView> csrf(CsrfToken token) {
        return ApiResponse.success(new CsrfView(token.getToken(), token.getHeaderName(), token.getParameterName()));
    }

    @GetMapping("/me")
    public ApiResponse<AccountView> me(@AuthenticationPrincipal AccountPrincipal principal) {
        return ApiResponse.success(users.accountView(principal));
    }
}
