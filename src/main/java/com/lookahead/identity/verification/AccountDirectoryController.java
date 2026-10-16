package com.lookahead.identity.verification;

import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** Account reads for the authenticated Domain service; never exposed publicly. */
@RestController
public class AccountDirectoryController {
    public record Account(UUID accountId, String username, String displayName, String email) {}
    private final JdbcTemplate jdbc;
    public AccountDirectoryController(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public record Page(java.util.List<Account> accounts, int page, boolean hasNext) {}
    @GetMapping("/internal/v1/accounts")
    public ResponseEntity<?> list(@RequestParam(defaultValue="") String query,
            @RequestParam(defaultValue="0") int page) {
        if(query.length()>254 || query.codePoints().anyMatch(Character::isISOControl) || page<0 || page>100000)
            return ResponseEntity.unprocessableContent().header("Cache-Control","no-store").build();
        String term=query.strip().toLowerCase(java.util.Locale.ROOT);
        // position treats %, _ and backslash literally; the caller cannot supply SQL wildcards.
        var rows=jdbc.query("""
            SELECT a.id,a.username,a.display_name,p.email FROM accounts a
            LEFT JOIN account_profiles p ON p.account_id=a.id
            WHERE a.enabled AND (?='' OR position(? in lower(a.username))>0
              OR position(? in lower(a.display_name))>0 OR position(? in lower(coalesce(p.email,'')))>0)
            ORDER BY lower(a.username),a.id LIMIT 51 OFFSET ?
            """, (r,i)->new Account(r.getObject(1,UUID.class),r.getString(2),r.getString(3),r.getString(4)),
            term,term,term,term,page*50);
        return ResponseEntity.ok().header("Cache-Control","no-store")
            .body(new Page(java.util.List.copyOf(rows.subList(0,Math.min(50,rows.size()))),page,rows.size()>50));
    }
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
    @GetMapping("/internal/v1/accounts/{id}")
    public ResponseEntity<?> byId(@PathVariable UUID id) {
        var rows=jdbc.query("SELECT a.id,a.username,a.display_name,p.email FROM accounts a LEFT JOIN account_profiles p ON p.account_id=a.id WHERE a.id=? AND a.enabled",
            (r,i)->new Account(r.getObject(1,UUID.class),r.getString(2),r.getString(3),r.getString(4)),id);
        if(rows.isEmpty())return ResponseEntity.status(404).header("Cache-Control","no-store").build();
        return ResponseEntity.ok().header("Cache-Control","no-store").body(rows.getFirst());
    }
}
