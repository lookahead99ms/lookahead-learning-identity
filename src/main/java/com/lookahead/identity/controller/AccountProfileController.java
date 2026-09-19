package com.lookahead.identity.controller;

import com.lookahead.identity.dto.AccountProfileView;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.AccountProfileService;
import com.lookahead.learning.content.dto.ApiResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile("accounts")
@RequestMapping("/api/v1/account/profile")
public class AccountProfileController {
    private final AccountProfileService profiles;
    public AccountProfileController(AccountProfileService profiles) { this.profiles = profiles; }

    @GetMapping
    public ApiResponse<AccountProfileView> read(@AuthenticationPrincipal AccountPrincipal principal,
            HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        requirePrincipal(principal);
        return ApiResponse.success(profiles.read(principal.accountId(), principal.credentialEpoch()));
    }

    @PostMapping
    public ApiResponse<AccountProfileView> update(@AuthenticationPrincipal AccountPrincipal principal,
            @RequestBody Map<String, Object> body, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        requirePrincipal(principal);
        // Explicit allowlist rejects mass assignment even when global JSON decoding ignores unknown fields.
        if (body == null || !body.keySet().equals(Set.of("displayName")) || !(body.get("displayName") instanceof String))
            throw new AccountFailure(422, "INVALID_PROFILE", "Provide only the displayName field.");
        return ApiResponse.success(profiles.update(principal.accountId(), principal.credentialEpoch(), (String) body.get("displayName")));
    }

    private static void requirePrincipal(AccountPrincipal principal) {
        if (principal == null) throw new AccountFailure(401, "AUTHENTICATION_REQUIRED", "Sign in again to manage your account.");
    }
}
