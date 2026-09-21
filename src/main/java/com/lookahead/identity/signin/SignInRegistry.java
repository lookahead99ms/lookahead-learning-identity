package com.lookahead.identity.signin;

import com.lookahead.identity.exception.AccountFailure;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.time.*;
import java.sql.Timestamp;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;

/** Account-row serialization is shared with credential changes and OAuth publication. */
@Service
@Profile("accounts")
@EnableConfigurationProperties(SignInProperties.class)
public class SignInRegistry {
    public record Admission(UUID accountId, long credentialEpoch, UUID signInId, String challengeToken, Instant expiresAt) {
        @Override public String toString() { return "Admission[challenge="+(challengeToken!=null)+", expiresAt="+expiresAt+"]"; }
    }
    public record SignIn(UUID id, boolean current, String label, String clientDescription, Instant createdAt, Instant lastActiveAt, Instant recentAuthAt) {}
    private record Challenge(UUID owner,long epoch,String binding,String description,Instant expires,boolean cancelled,UUID selected,UUID admitted) {}
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final SignInProperties properties;
    private final Clock clock;
    @org.springframework.beans.factory.annotation.Autowired
    public SignInRegistry(JdbcTemplate jdbc,PlatformTransactionManager manager,SignInProperties properties) {
        this(jdbc,manager,properties,null);
    }
    public SignInRegistry(JdbcTemplate jdbc,PlatformTransactionManager manager,SignInProperties properties,Clock clock) {
        this.jdbc=jdbc;this.transaction=new TransactionTemplate(manager);this.properties=properties;this.clock=clock;
    }
    public Admission admit(UUID owner,long epoch,String bindingDigest,String description) {
        if(bindingDigest==null || !bindingDigest.matches("[a-f0-9]{64}"))throw invalid();
        String client=plain(description,80,"Browser");
        return locked(owner,epoch,()->{
            Instant now=now(); expire(owner,epoch,now);
            var existing=jdbc.query("SELECT id FROM logical_sign_ins WHERE account_id=? AND credential_epoch=? AND binding_digest=? AND revoked_at IS NULL",(r,i)->r.getObject(1,UUID.class),owner,epoch,bindingDigest);
            if(!existing.isEmpty()) {
                UUID id=existing.getFirst();jdbc.update("UPDATE logical_sign_ins SET recent_auth_at=?,last_active_at=? WHERE id=?",ts(now),ts(now),id);
                return admission(owner,epoch,id);
            }
            if(properties.unlimited() || activeCount(owner)<properties.maximumActiveSessions())
                return admission(owner,epoch,insert(owner,epoch,bindingDigest,client,now));
            jdbc.update("DELETE FROM sign_in_challenges WHERE account_id=? AND created_at<?",owner,ts(now.minus(Duration.ofMinutes(15))));
            if(jdbc.queryForObject("SELECT count(*) FROM sign_in_challenges WHERE account_id=?",Integer.class,owner)>=5)
                throw new AccountFailure(429,"SIGN_IN_RATE_LIMITED","Try signing in later.");
            String token=randomToken(); Instant expiry=now.plus(Duration.ofMinutes(5));
            jdbc.update("INSERT INTO sign_in_challenges(token_digest,account_id,credential_epoch,binding_digest,client_description,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",digest(token),owner,epoch,bindingDigest,client,ts(now),ts(expiry));
            return new Admission(owner,epoch,null,token,expiry);
        });
    }
    public SignIn current(UUID owner,long epoch,UUID id,boolean touch) {
        return locked(owner,epoch,()->{expire(owner,epoch,now());SignIn value=find(owner,id,id);if(touch)jdbc.update("UPDATE logical_sign_ins SET last_active_at=? WHERE id=?",ts(now()),id);return value;});
    }
    public List<SignIn> list(UUID owner,long epoch,UUID currentId) {
        return locked(owner,epoch,()->{expire(owner,epoch,now());find(owner,currentId,currentId);return inventory(owner,currentId);});
    }
    public List<SignIn> challengeInventory(String token) {
        Challenge proof=challenge(token);
        return locked(proof.owner,proof.epoch,()->{Challenge fresh=validChallenge(token);expire(fresh.owner,fresh.epoch,now());return inventory(fresh.owner,null);});
    }
    public Instant challengeExpiresAt(String token) {
        Challenge proof=challenge(token);
        return locked(proof.owner,proof.epoch,()->validChallenge(token).expires);
    }
    public UUID challengeAccount(String token) {
        Challenge proof=challenge(token);
        return locked(proof.owner,proof.epoch,()->validChallenge(token).owner);
    }
    public Admission replace(String token,UUID selectedId) {
        Challenge proof=challenge(token);
        return locked(proof.owner,proof.epoch,()->{
            Challenge fresh=validChallenge(token);Instant now=now();expire(fresh.owner,fresh.epoch,now);
            if(fresh.admitted!=null) {
                if(!Objects.equals(selectedId,fresh.selected))throw invalid();
                find(fresh.owner,fresh.admitted,fresh.admitted);return admission(fresh.owner,fresh.epoch,fresh.admitted);
            }
            if(selectedId==null || !Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM logical_sign_ins WHERE id=? AND account_id=?)",Boolean.class,selectedId,fresh.owner)))throw invalid();
            // A second challenge for this same browser may already have succeeded.
            var bound=jdbc.query("SELECT id FROM logical_sign_ins WHERE account_id=? AND credential_epoch=? AND binding_digest=? AND revoked_at IS NULL",(r,i)->r.getObject(1,UUID.class),fresh.owner,fresh.epoch,fresh.binding);
            UUID admitted;
            if(!bound.isEmpty()) admitted=bound.getFirst();
            else {
                if(selectedId==null)throw invalid();
                // Expired/revoked selections remain owner-bound and safe to retry while a slot is free.
                if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM logical_sign_ins WHERE id=? AND account_id=?)",Boolean.class,selectedId,fresh.owner)))throw invalid();
                revokeRow(fresh.owner,selectedId,now);
                if(!properties.unlimited() && activeCount(fresh.owner)>=properties.maximumActiveSessions())throw invalid();
                admitted=insert(fresh.owner,fresh.epoch,fresh.binding,fresh.description,now);
            }
            jdbc.update("UPDATE sign_in_challenges SET selected_id=?,admitted_id=? WHERE token_digest=?",selectedId,admitted,digest(token));
            return admission(fresh.owner,fresh.epoch,admitted);
        });
    }
    public void cancel(String token) {
        Challenge proof=challenge(token);locked(proof.owner,proof.epoch,()->{Challenge fresh=challenge(token);if(!fresh.expires.isAfter(now()))throw invalid();if(fresh.admitted==null)jdbc.update("UPDATE sign_in_challenges SET cancelled=true WHERE token_digest=?",digest(token));return null;});
    }
    public void revoke(UUID owner,long epoch,UUID currentId,UUID targetId) {
        locked(owner,epoch,()->{expire(owner,epoch,now());requireRecent(find(owner,currentId,currentId));
            if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM logical_sign_ins WHERE id=? AND account_id=?)",Boolean.class,targetId,owner)))throw invalid();
            revokeRow(owner,targetId,now());return null;});
    }
    /** Logout is always allowed, including an already ended or expired own sign-in. */
    public void terminate(UUID owner,long epoch,UUID currentId) {
        locked(owner,epoch,()->{
            if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM logical_sign_ins WHERE id=? AND account_id=?)",Boolean.class,currentId,owner)))throw unauthenticated();
            revokeRow(owner,currentId,now());return null;
        });
    }
    public void revokeOthers(UUID owner,long epoch,UUID currentId) {
        locked(owner,epoch,()->{expire(owner,epoch,now());requireRecent(find(owner,currentId,currentId));for(var value:inventory(owner,currentId))if(!value.current)revokeRow(owner,value.id,now());return null;});
    }
    public SignIn rename(UUID owner,long epoch,UUID currentId,UUID targetId,String label) {
        String clean=plain(label,80,"");return locked(owner,epoch,()->{expire(owner,epoch,now());find(owner,currentId,currentId);find(owner,targetId,currentId);jdbc.update("UPDATE logical_sign_ins SET label=? WHERE id=?",clean,targetId);return find(owner,targetId,currentId);});
    }
    private void requireRecent(SignIn value) {if(!value.recentAuthAt.plus(properties.recentAuthenticationLifetime()).isAfter(now()))throw new AccountFailure(403,"RECENT_AUTHENTICATION_REQUIRED","Sign in again before managing sign-ins.");}
    private Admission admission(UUID owner,long epoch,UUID id){return new Admission(owner,epoch,id,null,null);}
    private UUID insert(UUID owner,long epoch,String binding,String client,Instant now) {
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO logical_sign_ins(id,account_id,credential_epoch,binding_digest,created_at,last_active_at,recent_auth_at,client_description) VALUES(?,?,?,?,?,?,?,?)",id,owner,epoch,binding,ts(now),ts(now),ts(now),client);return id;
    }
    private int activeCount(UUID owner){return jdbc.queryForObject("SELECT count(*) FROM logical_sign_ins WHERE account_id=? AND revoked_at IS NULL",Integer.class,owner);}
    private List<SignIn> inventory(UUID owner,UUID current) {
        return jdbc.query("SELECT * FROM logical_sign_ins WHERE account_id=? AND revoked_at IS NULL ORDER BY created_at,id",(r,i)->new SignIn(r.getObject("id",UUID.class),Objects.equals(current,r.getObject("id",UUID.class)),r.getString("label"),r.getString("client_description"),r.getTimestamp("created_at").toInstant(),r.getTimestamp("last_active_at").toInstant(),r.getTimestamp("recent_auth_at").toInstant()),owner);
    }
    private SignIn find(UUID owner,UUID id,UUID current){return inventory(owner,current).stream().filter(v->v.id.equals(id)).findFirst().orElseThrow(SignInRegistry::unauthenticated);}
    private void expire(UUID owner,long epoch,Instant now) {
        jdbc.update("UPDATE logical_sign_ins SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL AND (credential_epoch<>? OR last_active_at<=? OR created_at<=?)",ts(now),owner,epoch,ts(now.minus(properties.idleLifetime())),ts(now.minus(properties.absoluteLifetime())));
        jdbc.update("DELETE FROM oauth2_authorization WHERE logical_sign_in_id IN (SELECT id FROM logical_sign_ins WHERE account_id=? AND revoked_at IS NOT NULL)",owner);
    }
    private void revokeRow(UUID owner,UUID id,Instant now){jdbc.update("UPDATE logical_sign_ins SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND account_id=?",ts(now),id,owner);jdbc.update("DELETE FROM oauth2_authorization WHERE logical_sign_in_id=?",id);}
    private Challenge challenge(String token) {
        var rows=jdbc.query("SELECT * FROM sign_in_challenges WHERE token_digest=?",(r,i)->new Challenge(r.getObject("account_id",UUID.class),r.getLong("credential_epoch"),r.getString("binding_digest"),r.getString("client_description"),r.getTimestamp("expires_at").toInstant(),r.getBoolean("cancelled"),r.getObject("selected_id",UUID.class),r.getObject("admitted_id",UUID.class)),digest(token));
        if(rows.isEmpty())throw invalid();return rows.getFirst();
    }
    private Challenge validChallenge(String token){Challenge value=challenge(token);if(value.cancelled||!value.expires.isAfter(now()))throw invalid();return value;}
    private <T>T locked(UUID owner,long epoch,Supplier<T> work){return transaction.execute(status->{var rows=jdbc.query("SELECT enabled,credential_epoch FROM accounts WHERE id=? FOR UPDATE",(r,i)->r.getBoolean(1)&&r.getLong(2)==epoch,owner);if(rows.size()!=1||!rows.getFirst())throw unauthenticated();return work.get();});}
    private Instant now(){return clock == null ? jdbc.queryForObject("SELECT clock_timestamp()",Timestamp.class).toInstant() : clock.instant();}
    private static Timestamp ts(Instant value){return Timestamp.from(value);}
    public static String digest(String token){if(token==null||token.length()>512)throw invalid();try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));}catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}}
    private static String randomToken(){byte[] value=new byte[32];new SecureRandom().nextBytes(value);return Base64.getUrlEncoder().withoutPadding().encodeToString(value);}
    private static String plain(String value,int maximum,String fallback){if(value==null)return fallback;String clean=value.strip();if(clean.codePointCount(0,clean.length())>maximum||clean.codePoints().anyMatch(c->Character.isISOControl(c)||c=='<'||c=='>'))throw new AccountFailure(400,"INVALID_SIGN_IN_LABEL","Use a short plain-text label.");return clean;}
    private static AccountFailure invalid(){return new AccountFailure(400,"SIGN_IN_CHALLENGE_INVALID","Sign in again to manage sign-ins.");}
    private static AccountFailure unauthenticated(){return new AccountFailure(401,"AUTHENTICATION_REQUIRED","Sign in again.");}
}
