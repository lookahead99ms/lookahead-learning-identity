package com.lookahead.identity.verification;

import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class TokenVerificationController {
    private final TokenVerificationService verifier;
    public TokenVerificationController(TokenVerificationService verifier) { this.verifier = verifier; }
    @PostMapping(value = "/internal/v1/tokens/verify", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> verify(@RequestParam(required = false) String token) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(verifier.verify(token));
    }
}
