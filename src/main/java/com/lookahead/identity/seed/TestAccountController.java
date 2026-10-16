package com.lookahead.identity.seed;

import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@Profile("accounts")
@RequestMapping("/internal/v1/test-accounts")
public class TestAccountController {
    public record Passwords(String learnerPassword, String staffPassword) {
        @Override public String toString() { return "Passwords[redacted]"; }
    }
    private final TestAccountService service;
    public TestAccountController(TestAccountService service) { this.service = service; }
    @ModelAttribute void noStore(HttpServletResponse response) { response.setHeader("Cache-Control", "no-store"); }
    @PostMapping("/seed") public Object seed(@RequestBody Passwords passwords) {
        return service.seed(passwords.learnerPassword(), passwords.staffPassword());
    }
    @PostMapping("/passwords") public Object passwords(@RequestBody Passwords passwords) {
        return Map.of("updated", service.rotate(passwords.learnerPassword(), passwords.staffPassword()));
    }
}
