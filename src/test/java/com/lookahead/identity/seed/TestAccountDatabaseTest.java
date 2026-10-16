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
                "V4__account_preferences_and_links.sql","V5__test_account_registry.sql"))
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
