package com.lookahead.identity.verification;

import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** Exact account lookup for the authenticated Domain service, never a public directory. */
@RestController
public class AccountDirectoryController {
    public record Account(UUID accountId, String username, String displayName, String email) {}
    private final JdbcTemplate jdbc;
    public AccountDirectoryController(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    @PostMapping("/internal/v1/accounts/lookup")
    public ResponseEntity<?> lookup(@RequestBody Map<String,String> body) {
        String query=body.getOrDefault("query","").strip().toLowerCase(java.util.Locale.ROOT);
        if(query.isEmpty()||query.length()>254||query.codePoints().anyMatch(Character::isISOControl))
            return ResponseEntity.unprocessableContent().header("Cache-Control","no-store").build();
        var rows=jdbc.query("SELECT a.id,a.username,a.display_name,p.email FROM accounts a LEFT JOIN account_profiles p ON p.account_id=a.id WHERE a.enabled AND (lower(a.username)=? OR p.email=?) LIMIT 2",
            (r,i)->new Account(r.getObject(1,UUID.class),r.getString(2),r.getString(3),r.getString(4)),query,query);
        if(rows.size()!=1)return ResponseEntity.status(404).header("Cache-Control","no-store").build();
        return ResponseEntity.ok().header("Cache-Control","no-store").body(rows.getFirst());
    }
}
