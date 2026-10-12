package com.lookahead.identity.controller;

import com.lookahead.identity.dto.AccountProfileView;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.AccountProfileService;
import com.lookahead.identity.validator.ProfileLinkPolicy;
import com.lookahead.learning.content.dto.ApiResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile("accounts")
public class AccountProfileController {
    private final AccountProfileService profiles;
    public AccountProfileController(AccountProfileService profiles) { this.profiles = profiles; }

    @GetMapping("/api/v1/account/profile")
    public ApiResponse<AccountProfileView> read(@AuthenticationPrincipal AccountPrincipal principal,
            HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        requirePrincipal(principal);
        return ApiResponse.success(profiles.read(principal.accountId(), principal.credentialEpoch()));
    }

    @PostMapping("/api/v1/account/profile")
    public ApiResponse<AccountProfileView> update(@AuthenticationPrincipal AccountPrincipal principal,
            @RequestBody Map<String, Object> body, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        requirePrincipal(principal);
        // Explicit allowlist rejects mass assignment even when global JSON decoding ignores unknown fields.
        if (body == null || !body.keySet().equals(Set.of("displayName")) || !(body.get("displayName") instanceof String))
            throw new AccountFailure(422, "INVALID_PROFILE", "Provide only the displayName field.");
        return ApiResponse.success(profiles.update(principal.accountId(), principal.credentialEpoch(), (String) body.get("displayName")));
    }

    /** Body is exactly {"theme": "light"|"dark"|"system"}; any other JSON value or shape is a 422. */
    @PostMapping("/api/v1/account/preferences")
    public ApiResponse<AccountProfileView> preferences(@AuthenticationPrincipal AccountPrincipal principal,
            @RequestBody(required = false) Object body, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        requirePrincipal(principal);
        if (!(body instanceof Map<?, ?> fields) || !fields.keySet().equals(Set.of("theme"))
                || !(fields.get("theme") instanceof String theme) || !AccountProfileService.THEMES.contains(theme))
            throw AccountProfileService.invalidPreferences();
        return ApiResponse.success(profiles.updateTheme(principal.accountId(), principal.credentialEpoch(), theme));
    }

    /** Body is exactly the four link keys; each value is a string or null (null or blank clears it). */
    @PostMapping("/api/v1/account/links")
    public ApiResponse<AccountProfileView> links(@AuthenticationPrincipal AccountPrincipal principal,
            @RequestBody(required = false) Object body, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        requirePrincipal(principal);
        if (!(body instanceof Map<?, ?> fields) || !fields.keySet().equals(Set.copyOf(ProfileLinkPolicy.KINDS)))
            throw ProfileLinkPolicy.invalidShape();
        var links = new HashMap<String, String>();
        for (String kind : ProfileLinkPolicy.KINDS) {
            Object value = fields.get(kind);
            if (value != null && !(value instanceof String)) throw ProfileLinkPolicy.invalidShape();
            links.put(kind, (String) value);
        }
        return ApiResponse.success(profiles.updateLinks(principal.accountId(), principal.credentialEpoch(), links));
    }

    private static void requirePrincipal(AccountPrincipal principal) {
        if (principal == null) throw new AccountFailure(401, "AUTHENTICATION_REQUIRED", "Sign in again to manage your account.");
    }
}
