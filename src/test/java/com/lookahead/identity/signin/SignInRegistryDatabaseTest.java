package com.lookahead.identity.signin;

import com.lookahead.identity.exception.AccountFailure;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ByteArrayResource;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

/** Disposable database only; creates and drops an isolated schema, never seed accounts. */
@EnabledIfEnvironmentVariable(named="DLV920_DATABASE_URL",matches=".+")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SignInRegistryDatabaseTest {
    JdbcTemplate jdbc,admin; DriverManagerDataSource source;String schema; MutableClock clock;
    SignInRegistry first,second;
    static final class MutableClock extends Clock {
        Instant value=Instant.parse("2026-09-19T12:00:00Z");
        public ZoneId getZone(){return ZoneOffset.UTC;} public Clock withZone(ZoneId zone){return this;} public Instant instant(){return value;}
        void advance(Duration duration){value=value.plus(duration);}
    }
    @BeforeAll void setup() throws Exception {
        String url=System.getenv("DLV920_DATABASE_URL");
        String password=System.getenv().getOrDefault("DLV920_DATABASE_PASSWORD","synthetic-session-test-only");
        admin=new JdbcTemplate(new DriverManagerDataSource(url,"postgres",password));
        schema="signin_"+UUID.randomUUID().toString().replace("-","");admin.execute("CREATE SCHEMA "+schema);
        source=new DriverManagerDataSource(url+(url.contains("?")?"&":"?")+"currentSchema="+schema,"postgres",password);
        jdbc=new JdbcTemplate(source);
        String sql=Files.readString(Path.of("src/main/resources/db/identity/V1__identity.sql")).split("REVOKE ALL")[0]+Files.readString(Path.of("src/main/resources/db/identity/V2__credential_epoch.sql"))+Files.readString(Path.of("src/main/resources/db/identity/V3__logical_sign_ins.sql")).split("GRANT SELECT")[0];
        new ResourceDatabasePopulator(new ByteArrayResource(sql.getBytes(StandardCharsets.UTF_8))).execute(source);
    }
    @BeforeEach void instances(){clock=new MutableClock();first=service();second=service();}
    SignInRegistry service(){return new SignInRegistry(jdbc,new DataSourceTransactionManager(source),SignInProperties.defaults(),clock);}
    SignInRegistry unlimited(){return new SignInRegistry(jdbc,new DataSourceTransactionManager(source),new SignInProperties(Duration.ofMinutes(30),Duration.ofDays(7),Duration.ofMinutes(5),0),clock);}
    @AfterAll void cleanup(){if(admin!=null&&schema!=null)admin.execute("DROP SCHEMA "+schema+" CASCADE");}
    UUID owner(){UUID id=UUID.randomUUID();jdbc.update("INSERT INTO accounts(id,username,display_name,password_hash) VALUES(?,?,?,?)",id,id+"@example.test","Synthetic","unused");return id;}
    SignInRegistry.Admission admit(SignInRegistry registry,UUID owner,String binding){return registry.admit(owner,0,SignInRegistry.digest(binding),"Browser");}
    void fails(Runnable operation,String code){assertThatThrownBy(operation::run).isInstanceOfSatisfying(AccountFailure.class,e->assertThat(e.code()).isEqualTo(code));}
    @Test void twoAdmissionsThirdRestrictedAndCancellationDoesNotRevoke(){
        UUID owner=owner();var one=admit(first,owner,"one");var two=admit(second,owner,"two");var challenge=admit(first,owner,"three");
        assertThat(one.signInId()).isNotNull();assertThat(two.signInId()).isNotNull();assertThat(challenge.signInId()).isNull();
        assertThat(first.challengeInventory(challenge.challengeToken())).hasSize(2);
        first.cancel(challenge.challengeToken());fails(()->second.replace(challenge.challengeToken(),one.signInId()),"SIGN_IN_CHALLENGE_INVALID");
        second.cancel(challenge.challengeToken());
        assertThat(second.list(owner,0,one.signInId())).hasSize(2);
    }
    @Test void localUnlimitedPolicyAdmitsMoreThanTwoIndependentBindings(){
        UUID owner=owner();var local=unlimited();UUID current=null;
        for(int index=0;index<6;index++){var admitted=admit(local,owner,"local-"+index);assertThat(admitted.signInId()).isNotNull();if(current==null)current=admitted.signInId();}
        assertThat(local.list(owner,0,current)).hasSize(6);
    }
    @Test void restartAndLostAdmissionResponseReuseBindingWithoutNewSlot(){
        UUID owner=owner();var one=admit(first,owner,"one");clock.advance(Duration.ofMinutes(1));
        var retry=admit(service(),owner,"one");assertThat(retry.signInId()).isEqualTo(one.signInId());
        assertThat(first.list(owner,0,one.signInId())).hasSize(1);assertThat(first.current(owner,0,one.signInId(),false).recentAuthAt()).isEqualTo(clock.instant());
    }
    @Test void replacementIsDurableIdempotentAndRejectsAnotherTarget(){
        UUID owner=owner();var one=admit(first,owner,"one");var two=admit(first,owner,"two");var challenge=admit(first,owner,"three");
        var admitted=first.replace(challenge.challengeToken(),one.signInId());
        assertThat(service().replace(challenge.challengeToken(),one.signInId()).signInId()).isEqualTo(admitted.signInId());
        fails(()->second.replace(challenge.challengeToken(),two.signInId()),"SIGN_IN_CHALLENGE_INVALID");
        fails(()->first.current(owner,0,one.signInId(),false),"AUTHENTICATION_REQUIRED");
        assertThat(first.list(owner,0,two.signInId())).hasSize(2);
    }
    @Test void ownerIsolationEpochRotationAndTokenRemoval(){
        UUID owner=owner(),other=owner();var one=admit(first,owner,"one");var two=admit(first,owner,"two");var unrelated=admit(first,other,"other");
        jdbc.update("INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type,logical_sign_in_id) VALUES (?,?,?,?,?)",UUID.randomUUID().toString(),"client",owner.toString(),"authorization_code",one.signInId());
        fails(()->first.revoke(owner,0,two.signInId(),unrelated.signInId()),"SIGN_IN_CHALLENGE_INVALID");
        first.revoke(owner,0,two.signInId(),one.signInId());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE logical_sign_in_id=?",Integer.class,one.signInId())).isZero();
        assertThat(first.current(other,0,unrelated.signInId(),false)).isNotNull();
        jdbc.update("UPDATE accounts SET credential_epoch=1 WHERE id=?",owner);
        fails(()->first.current(owner,0,two.signInId(),false),"AUTHENTICATION_REQUIRED");
        assertThat(first.admit(owner,1,SignInRegistry.digest("new"),"Browser").signInId()).isNotNull();
    }
    @Test void expiredChallengeAndRateLimitsFailClosed(){
        UUID owner=owner();admit(first,owner,"one");admit(first,owner,"two");var challenge=admit(first,owner,"three");
        clock.advance(Duration.ofMinutes(6));fails(()->first.challengeInventory(challenge.challengeToken()),"SIGN_IN_CHALLENGE_INVALID");
        for(int i=0;i<4;i++)admit(first,owner,"attempt"+i);
        fails(()->admit(first,owner,"over-limit"),"SIGN_IN_RATE_LIMITED");
        clock.advance(Duration.ofMinutes(16));assertThat(admit(first,owner,"after-window").challengeToken()).isNotNull();
    }
    @Test void idleAndAbsoluteExpiryCannotBeExtendedByReauthentication(){
        UUID owner=owner();var one=admit(first,owner,"one");clock.advance(Duration.ofMinutes(31));
        fails(()->first.current(owner,0,one.signInId(),true),"AUTHENTICATION_REQUIRED");
        var newer=admit(first,owner,"one");assertThat(newer.signInId()).isNotEqualTo(one.signInId());
        jdbc.update("UPDATE logical_sign_ins SET created_at=? WHERE id=?",java.sql.Timestamp.from(clock.instant().minus(Duration.ofDays(7))),newer.signInId());
        assertThat(admit(first,owner,"one").signInId()).isNotEqualTo(newer.signInId());
    }
    @Test void recentAuthenticationAndLabelsHaveBoundaries(){
        UUID owner=owner();var one=admit(first,owner,"one");var two=admit(first,owner,"two");
        assertThat(first.rename(owner,0,one.signInId(),two.signInId(),"  Work browser  ").label()).isEqualTo("Work browser");
        fails(()->first.rename(owner,0,one.signInId(),two.signInId(),"<script>"),"INVALID_SIGN_IN_LABEL");
        clock.advance(Duration.ofMinutes(6));fails(()->first.revokeOthers(owner,0,one.signInId()),"RECENT_AUTHENTICATION_REQUIRED");
        admit(first,owner,"one");first.revokeOthers(owner,0,one.signInId());assertThat(first.list(owner,0,one.signInId())).hasSize(1);
    }
    @Test void concurrentAdmissionAcrossInstancesNeverExceedsTwo() throws Exception {
        UUID owner=owner();var pool=Executors.newFixedThreadPool(8);var start=new CountDownLatch(1);
        try {
            var tasks=new ArrayList<Future<Boolean>>();
            for(int i=0;i<8;i++){final int n=i;tasks.add(pool.submit(()->{start.await();try{return admit(n%2==0?first:second,owner,"concurrent"+n).signInId()!=null;}catch(AccountFailure e){assertThat(e.code()).isEqualTo("SIGN_IN_RATE_LIMITED");return false;}}));}
            start.countDown();int admitted=0;for(var task:tasks)if(task.get(15,TimeUnit.SECONDS))admitted++;
            assertThat(admitted).isEqualTo(2);assertThat(jdbc.queryForObject("SELECT count(*) FROM logical_sign_ins WHERE account_id=? AND revoked_at IS NULL",Integer.class,owner)).isEqualTo(2);
        }finally{pool.shutdownNow();}
    }
    @Test void competingReplacementAndRetriesNeverOverAdmit() throws Exception {
        UUID owner=owner();var one=admit(first,owner,"one");admit(first,owner,"two");var a=admit(first,owner,"three");var b=admit(first,owner,"four");
        var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try {
            var tasks=new ArrayList<Future<Boolean>>();for(var challenge:List.of(a,b))tasks.add(pool.submit(()->{start.await();try{second.replace(challenge.challengeToken(),one.signInId());return true;}catch(AccountFailure e){assertThat(e.code()).isEqualTo("SIGN_IN_CHALLENGE_INVALID");return false;}}));
            start.countDown();int admitted=0;for(var task:tasks)if(task.get(15,TimeUnit.SECONDS))admitted++;
            assertThat(admitted).isEqualTo(1);assertThat(jdbc.queryForObject("SELECT count(*) FROM logical_sign_ins WHERE account_id=? AND revoked_at IS NULL",Integer.class,owner)).isEqualTo(2);
        }finally{pool.shutdownNow();}
    }
    @Test void failedReplacementRollsBackRevocationAndAdmitsNothing(){
        UUID owner=owner();var one=admit(first,owner,"one");var two=admit(first,owner,"two");var pending=admit(first,owner,"three");
        jdbc.execute("CREATE FUNCTION reject_sign_in_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic replacement failure'; END; $$");
        jdbc.execute("CREATE TRIGGER replacement_failure BEFORE INSERT ON logical_sign_ins FOR EACH ROW EXECUTE FUNCTION reject_sign_in_insert()");
        try {
            assertThatThrownBy(()->first.replace(pending.challengeToken(),one.signInId())).isInstanceOf(org.springframework.dao.DataAccessException.class);
            assertThat(second.list(owner,0,one.signInId())).extracting(SignInRegistry.SignIn::id).containsExactlyInAnyOrder(one.signInId(),two.signInId());
        } finally {
            jdbc.execute("DROP TRIGGER replacement_failure ON logical_sign_ins");
            jdbc.execute("DROP FUNCTION reject_sign_in_insert()");
        }
        assertThat(first.replace(pending.challengeToken(),one.signInId()).signInId()).isNotNull();
    }
    @Test void separateChallengesForSameBindingHaveSingleAdmission(){
        UUID owner=owner();var one=admit(first,owner,"one");var two=admit(first,owner,"two");var a=admit(first,owner,"three");var b=admit(first,owner,"three");
        var selected=first.replace(a.challengeToken(),one.signInId());
        assertThat(second.replace(b.challengeToken(),one.signInId()).signInId()).isEqualTo(selected.signInId());
        assertThat(first.list(owner,0,two.signInId())).hasSize(2);
    }
    @Test void logoutIsIdempotentAfterRecentAuthenticationExpires(){
        UUID owner=owner();var one=admit(first,owner,"one");var two=admit(first,owner,"two");
        clock.advance(Duration.ofMinutes(6));first.terminate(owner,0,one.signInId());second.terminate(owner,0,one.signInId());
        assertThat(first.list(owner,0,two.signInId())).hasSize(1);
    }
    @Test void challengeCannotSelectAnotherAccountEvenAfterBindingAdmitted(){
        UUID owner=owner(),other=owner();var one=admit(first,owner,"one");admit(first,owner,"two");
        var foreign=admit(first,other,"foreign");var a=admit(first,owner,"three");var b=admit(first,owner,"three");
        first.replace(a.challengeToken(),one.signInId());
        fails(()->second.replace(b.challengeToken(),foreign.signInId()),"SIGN_IN_CHALLENGE_INVALID");
    }
}
