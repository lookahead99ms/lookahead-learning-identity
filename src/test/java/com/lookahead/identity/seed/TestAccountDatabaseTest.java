package com.lookahead.identity.seed;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.assertj.core.api.Assertions.*;

@EnabledIfEnvironmentVariable(named="DLV919_DATABASE_URL",matches=".+")
class TestAccountDatabaseTest {
    JdbcTemplate jdbc; TransactionTemplate transaction; String schema; TestAccountService service;
    @BeforeEach void setup() throws Exception {
        String url=System.getenv("DLV919_DATABASE_URL");
        if(!url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/postgres"))
            throw new IllegalStateException("Use the disposable session-registry fixture");
        String password=System.getenv("DLV920_DATABASE_PASSWORD");
        var admin=new JdbcTemplate(new DriverManagerDataSource(url,"postgres",password));
        schema="test_accounts_"+UUID.randomUUID().toString().replace("-","");
        admin.execute("CREATE SCHEMA "+schema);
        var source=new DriverManagerDataSource(url+"?currentSchema="+schema,"postgres",password);
        jdbc=new JdbcTemplate(source); transaction=new TransactionTemplate(new DataSourceTransactionManager(source));
        var migrations=Path.of("src/main/resources/db/identity");
        jdbc.execute(Files.readString(migrations.resolve("V1__identity.sql")).split("REVOKE ALL")[0]);
        for(String file:List.of("V2__credential_epoch.sql","V3__logical_sign_ins.sql",
                "V4__account_preferences_and_links.sql","V5__test_account_registry.sql","V6__created_test_accounts.sql"))
            jdbc.execute(Files.readString(migrations.resolve(file)).split("GRANT SELECT")[0]);
        PasswordEncoder encoder=new PasswordEncoder() {
            public String encode(CharSequence value) { return "synthetic-test-hash:"+value; }
            public boolean matches(CharSequence value,String encoded) { return encode(value).equals(encoded); }
        };
        service=new TestAccountService(jdbc,encoder,new TestAccountPolicy(TestAccountPolicyTest.local()));
    }
    @AfterEach void cleanup() { if(jdbc!=null)jdbc.execute("DROP SCHEMA "+schema+" CASCADE"); }
    List<TestAccountService.Result> seed() {
        return transaction.execute(status -> service.seed("synthetic-learner-only", "synthetic-staff-only"));
    }
    @Test void repeatedSeedPreservesExistingLearnersAndOwnerByteForByte() {
        UUID owner=UUID.randomUUID();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",owner,"author@lookahead.test","Existing owner","untouched-owner-hash");
        var first=TestAccountRoster.entries().getFirst();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,7,0,NULL)",first.accountId(),first.username(),"Existing learner","untouched-learner-hash");
        var before=jdbc.queryForList("SELECT * FROM accounts ORDER BY username");
        assertThat(seed().stream().filter(TestAccountService.Result::created)).hasSize(34);
        assertThat(seed()).allMatch(r -> !r.created());
        var after=jdbc.queryForList("SELECT * FROM accounts WHERE id IN (?,?) ORDER BY username",owner,first.accountId());
        assertThat(after).isEqualTo(before);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM test_accounts",Integer.class)).isEqualTo(35);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM test_accounts WHERE account_id=?",Integer.class,owner)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM account_profiles WHERE account_id=?",Integer.class,first.accountId())).isZero();
        var rosterBefore=jdbc.queryForList("SELECT * FROM test_accounts ORDER BY username");
        seed();
        assertThat(jdbc.queryForList("SELECT * FROM test_accounts ORDER BY username")).isEqualTo(rosterBefore);
    }
    @Test void namespaceConflictRollsBackTheWholeBatch() {
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",UUID.randomUUID(),"learner13","Existing learner","preserved");
        assertThatThrownBy(this::seed).hasMessageContaining("reserved test username");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM accounts",Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM test_accounts",Integer.class)).isZero();
    }
    @Test void usernameAndEmailResolveTheSameAccountAndAmbiguousAliasesFailClosed() {
        var first=TestAccountRoster.entries().getFirst();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",first.accountId(),first.username(),"Preserved learner","preserved");
        seed();
        var repository=new com.lookahead.identity.repository.AccountRepository(jdbc);
        assertThat(repository.findByUsername("learner01").orElseThrow().accountId()).isEqualTo(first.accountId());
        assertThat(repository.findByUsername("learner01@lookahead.test").orElseThrow().accountId()).isEqualTo(first.accountId());
        assertThat(repository.findByUsername("learner27@lookahead.test").orElseThrow().username()).isEqualTo("learner27");
        assertThat(repository.findByUsername("unknown@lookahead.test")).isEmpty();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",UUID.randomUUID(),"learner01@lookahead.test","Alias conflict","preserved");
        assertThat(repository.findByUsername("learner01@lookahead.test")).isEmpty();
    }
    @Test void explicitRotationChangesOnlyTheManagedRosterAndInvalidatesCredentialEpochs() {
        UUID owner=UUID.randomUUID();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",owner,"author@lookahead.test","Existing owner","untouched-owner-hash");
        seed();
        int updated=transaction.execute(status -> service.rotate("rotated-synthetic-learners", "rotated-synthetic-staff"));
        assertThat(updated).isEqualTo(35);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,owner)).isEqualTo("untouched-owner-hash");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM accounts WHERE credential_epoch=1",Integer.class)).isEqualTo(35);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM accounts WHERE password_hash='synthetic-test-hash:rotated-synthetic-learners'",Integer.class)).isEqualTo(27);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM accounts WHERE password_hash='synthetic-test-hash:rotated-synthetic-staff'",Integer.class)).isEqualTo(8);
    }
    @Test void deletedStaffCannotSignInOrRegainCredentialsAfterSeedAndRotation() {
        seed();
        var staff=TestAccountRoster.entries().stream().filter(TestAccountRoster.Entry::staff).findFirst().orElseThrow();
        transaction.executeWithoutResult(status -> service.disable(staff.accountId(),staff.username()));
        assertThat(jdbc.queryForObject("SELECT enabled FROM accounts WHERE id=?",Boolean.class,staff.accountId())).isFalse();
        assertThat(jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,staff.accountId())).isEqualTo("deleted");
        seed();
        int rotated=transaction.execute(status -> service.rotate("rotated-synthetic-learners","rotated-synthetic-staff"));
        assertThat(rotated).isEqualTo(34);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,staff.accountId())).isEqualTo("deleted");
        assertThat(jdbc.queryForObject("SELECT creation_state FROM test_accounts WHERE account_id=?",String.class,staff.accountId())).isEqualTo("deleted");
    }
    @Test void createdIdentityRemainsDisabledUntilActivationAndDeletionRevokesIt() {
        UUID id=UUID.randomUUID();String username="test-0123456789abcdef01234567";
        transaction.execute(status -> service.provision(id,username,"synthetic-learner-fixture-only"));
        assertThat(jdbc.queryForObject("SELECT enabled FROM accounts WHERE id=?",Boolean.class,id)).isFalse();
        transaction.executeWithoutResult(status -> service.activate(id,username));
        assertThat(jdbc.queryForObject("SELECT enabled FROM accounts WHERE id=?",Boolean.class,id)).isTrue();
        jdbc.update("INSERT INTO account_preferences(account_id,theme) VALUES (?,'dark')",id);
        jdbc.update("INSERT INTO account_profile_links(account_id,kind,url) VALUES (?,'github','https://example.test/test')",id);
        UUID signInId=UUID.randomUUID();
        jdbc.update("INSERT INTO logical_sign_ins(id,account_id,credential_epoch,binding_digest,created_at,last_active_at,recent_auth_at) VALUES (?,?,0,'synthetic',now(),now(),now())",signInId,id);
        jdbc.update("INSERT INTO sign_in_challenges(token_digest,account_id,credential_epoch,binding_digest,client_description,created_at,expires_at,admitted_id) VALUES ('synthetic',?,0,'synthetic','Browser',now(),now()+interval '1 hour',?)",id,signInId);
        transaction.executeWithoutResult(status -> service.disable(id,username));
        assertThat(jdbc.queryForObject("SELECT enabled FROM accounts WHERE id=?",Boolean.class,id)).isFalse();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM account_profiles WHERE account_id=?",Integer.class,id)).isZero();
        for(String table:List.of("account_preferences","account_profile_links","logical_sign_ins","sign_in_challenges"))
            assertThat(jdbc.queryForObject("SELECT count(*) FROM "+table+" WHERE account_id=?",Integer.class,id)).as(table).isZero();
        assertThat(jdbc.queryForObject("SELECT creation_state FROM test_accounts WHERE account_id=?",String.class,id)).isEqualTo("deleted");
        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.activate(id,username))).hasMessageContaining("unavailable");
    }
    @Test void deletingNeverActivatedIdentityScrubsPasswordAndIsRepeatable() {
        UUID id=UUID.randomUUID();String username="test-fedcba9876543210fedcba98";
        transaction.executeWithoutResult(status -> service.provision(id,username,"synthetic-learner-fixture-only"));
        transaction.executeWithoutResult(status -> service.disable(id,username));
        assertThat(jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,id)).isEqualTo("deleted");
        assertThat(jdbc.queryForObject("SELECT credential_epoch FROM accounts WHERE id=?",Integer.class,id)).isEqualTo(1);
        transaction.executeWithoutResult(status -> service.disable(id,username));
        assertThat(jdbc.queryForObject("SELECT credential_epoch FROM accounts WHERE id=?",Integer.class,id)).isEqualTo(1);
    }
    @Test void realLearnerDeletionRevokesLoginAndScrubsProfileButProtectsAuthorAndRoster() {
        UUID real=UUID.randomUUID();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",real,"real-learner","Real Learner","synthetic-hash");
        jdbc.update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,'Real','Learner','real@example.test','US')",real);
        transaction.executeWithoutResult(status -> service.disableReal(real));
        assertThat(jdbc.queryForObject("SELECT enabled FROM accounts WHERE id=?",Boolean.class,real)).isFalse();
        assertThat(jdbc.queryForObject("SELECT username FROM accounts WHERE id=?",String.class,real)).startsWith("deleted-");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM account_profiles WHERE account_id=?",Integer.class,real)).isZero();
        transaction.executeWithoutResult(status -> service.disableReal(real));
        assertThat(jdbc.queryForObject("SELECT credential_epoch FROM accounts WHERE id=?",Integer.class,real)).isEqualTo(1);
        UUID author=UUID.randomUUID();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",author,"author@lookahead.test","Author","synthetic-hash");
        assertThatThrownBy(()->transaction.executeWithoutResult(status -> service.disableReal(author))).hasMessageContaining("cannot be deleted");
        var roster=TestAccountRoster.entries().getFirst();seed();
        assertThatThrownBy(()->transaction.executeWithoutResult(status -> service.disableReal(roster.accountId()))).hasMessageContaining("cannot be deleted");
    }
    @Test void directoryIncludesRealUnassignedAccountsAndSearchesLiteralText() {
        var directory=new com.lookahead.identity.verification.AccountDirectoryController(jdbc);
        for(int i=0;i<52;i++) jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",UUID.randomUUID(),String.format("real%02d",i),"Real Learner","synthetic-hash");
        UUID special=UUID.randomUUID();
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,true,0,0,NULL)",special,"literal_%","Literal","synthetic-hash");
        jdbc.update("INSERT INTO accounts VALUES (?,?,?, ?,false,0,0,NULL)",UUID.randomUUID(),"disabled","Hidden","synthetic-hash");
        var first=(com.lookahead.identity.verification.AccountDirectoryController.Page)directory.list("",0).getBody();
        var second=(com.lookahead.identity.verification.AccountDirectoryController.Page)directory.list("",1).getBody();
        assertThat(first.accounts()).hasSize(50);assertThat(first.hasNext()).isTrue();
        assertThat(second.accounts()).hasSize(3);assertThat(second.hasNext()).isFalse();
        assertThat(first.accounts()).doesNotContainAnyElementsOf(second.accounts());
        var match=(com.lookahead.identity.verification.AccountDirectoryController.Page)directory.list("_%",0).getBody();
        assertThat(match.accounts()).extracting(com.lookahead.identity.verification.AccountDirectoryController.Account::accountId).containsExactly(special);
    }
}
