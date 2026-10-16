package com.lookahead.identity.seed;

import java.util.Map;
import java.util.UUID;
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
    public record Provision(UUID accountId, String username, String password) {
        @Override public String toString() { return "Provision[redacted]"; }
    }
    public record AccountRef(UUID accountId, String username) {}
    @PostMapping("/provision") public Object provision(@RequestBody Provision request) {
        return service.provision(request.accountId(), request.username(), request.password());
    }
    @PostMapping("/activate") public Object activate(@RequestBody AccountRef request) {
        service.activate(request.accountId(), request.username());
        return Map.of("active", true);
    }
    @PostMapping("/disable") public Object disable(@RequestBody AccountRef request) {
        service.disable(request.accountId(), request.username());
        return Map.of("disabled", true);
    }
}
