package com.lookahead.identity.service;

import com.lookahead.identity.dto.PasswordChangeRequest;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.security.AccountPrincipal;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
@Profile("accounts")
public class PasswordChangeService {
    private final JdbcTemplate jdbc;
    private final PasswordEncoder verifier;
    private final TransactionTemplate transaction;
    private final Pbkdf2PasswordEncoder encoder=Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    public PasswordChangeService(JdbcTemplate jdbc,PasswordEncoder verifier,PlatformTransactionManager manager) {
        this.jdbc=jdbc; this.verifier=verifier; this.transaction=new TransactionTemplate(manager);
    }
    public void change(AccountPrincipal principal,PasswordChangeRequest request) {
        validate(request);
        // Hash before taking the row lock; no credentials are retained in the result or logs.
        String encoded="{pbkdf2@SpringSecurity_v5_8}"+encoder.encode(request.newPassword());
        AccountFailure failure=transaction.execute(status->{
            var rows=jdbc.query("""
                SELECT password_hash,credential_epoch,enabled,password_failure_count,
                  (password_failure_window IS NOT NULL AND password_failure_window > CURRENT_TIMESTAMP - INTERVAL '15 minutes') AS active_window
                FROM accounts WHERE id=? FOR UPDATE
                """, (rs,n)->new CredentialState(rs.getString("password_hash"),rs.getLong("credential_epoch"),rs.getBoolean("enabled"),rs.getInt("password_failure_count"),rs.getBoolean("active_window")),principal.accountId());
            if(rows.size()!=1 || !rows.getFirst().enabled() || rows.getFirst().epoch()!=principal.credentialEpoch())
                return new AccountFailure(401,"AUTHENTICATION_REQUIRED","Sign in to continue");
            var state=rows.getFirst();
            if(state.activeWindow() && state.failures()>=5) return new AccountFailure(429,"PASSWORD_CHANGE_RATE_LIMITED","Retry after 15 minutes");
            if(!matches(request.currentPassword(),state.hash())) {
                jdbc.update("""
                    UPDATE accounts SET password_failure_count=?,
                    password_failure_window=CASE WHEN ? THEN password_failure_window ELSE CURRENT_TIMESTAMP END WHERE id=?
                    """,state.activeWindow()?state.failures()+1:1,state.activeWindow(),principal.accountId());
                return new AccountFailure(401,"INVALID_CURRENT_PASSWORD","Current password could not be verified");
            }
            if(matches(request.newPassword(),state.hash())) return new AccountFailure(422,"PASSWORD_UNCHANGED","Choose a different password");
            jdbc.update("UPDATE accounts SET password_hash=?,credential_epoch=credential_epoch+1,password_failure_count=0,password_failure_window=NULL WHERE id=?",encoded,principal.accountId());
            jdbc.update("DELETE FROM oauth2_authorization WHERE principal_name=?",principal.accountId().toString());
            return null;
        });
        // Throw outside the transaction so failed-verification counters are committed.
        if(failure!=null) throw failure;
    }
    private boolean matches(String raw, String hash) {
        // BCrypt cannot represent passwords beyond 72 bytes. New hashes always use full-input PBKDF2.
        if (hash.startsWith("{bcrypt}") && raw.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 72) return false;
        return verifier.matches(raw,hash);
    }
    public static void validate(PasswordChangeRequest request) {
        if(request==null || request.currentPassword()==null || request.currentPassword().isEmpty() || request.currentPassword().length()>4096)
            throw new AccountFailure(422,"INVALID_PASSWORD","Provide your current password");
        String password=request.newPassword();
        com.lookahead.identity.validator.NewPasswordPolicy.validate(password);
        if(!password.equals(request.confirmPassword())) throw new AccountFailure(422,"INVALID_PASSWORD","Passwords must match");
    }
    private record CredentialState(String hash,long epoch,boolean enabled,int failures,boolean activeWindow) {
        @Override public String toString() {return "CredentialState[redacted]";}
    }
}
