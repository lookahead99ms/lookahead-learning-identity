package com.lookahead.identity.account;

import com.lookahead.identity.config.*;
import com.lookahead.identity.controller.*;
import com.lookahead.identity.dto.PasswordChangeRequest;
import com.lookahead.identity.handler.AccountErrorHandler;
import com.lookahead.identity.oauth.*;
import com.lookahead.identity.repository.AccountRepository;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.*;
import com.lookahead.identity.validator.LocalTestSeedGuard;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.transaction.PlatformTransactionManager;
import tools.jackson.databind.ObjectMapper;
import javax.sql.DataSource;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

/** Opt-in real PostgreSQL + two independent HTTP Identity instances. No shared stack or seed credentials. */
@EnabledIfEnvironmentVariable(named="DLV919_DATABASE_URL",matches=".+")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CredentialEpochDatabaseTest {
    static String url;
    static OAuthProperties oauthProperties;
    static final String CLIENT="epoch-test-client", SECRET="synthetic-oauth-client-test-only-long-secret";
    static volatile CountDownLatch loginCaptured, releaseLogin;
    ConfigurableApplicationContext first, second;
    JdbcTemplate jdbc;
    String schema;
    final ObjectMapper mapper=new ObjectMapper();
    final String legacy="legacy-pass12";
    @Configuration
    @EnableAutoConfiguration(excludeName={"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration","org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @Import({AccountSecurityConfig.class,AuthController.class,PasswordChangeController.class,
            AccountRepository.class,PasswordChangeService.class,AccountErrorHandler.class,LocalTestSeedGuard.class,AccountProfileService.class,AccountProfileController.class,OAuthServerConfiguration.class,OAuthClientConfiguration.class,OAuthKeyConfiguration.class,com.lookahead.identity.verification.TokenVerificationService.class})
    static class App {
        @Bean OAuthProperties oauthProperties() {return oauthProperties;}
        @Bean OAuthSettings oauthSettings() {return new OAuthSettings("https://example.test",CLIENT,SECRET,"https://example.test","https://example.test");}
        @Bean AccountUserDetailsService users(AccountRepository accounts) {
            return new AccountUserDetailsService(accounts) {
                @Override public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(String username) {
                    var snapshot=super.loadUserByUsername(username);
                    var captured=loginCaptured; var release=releaseLogin;
                    if(captured!=null && release!=null) {
                        captured.countDown();
                        try { if(!release.await(15,TimeUnit.SECONDS)) throw new IllegalStateException("test login gate timeout"); }
                        catch(InterruptedException error) {Thread.currentThread().interrupt();throw new IllegalStateException(error);}
                    }
                    return snapshot;
                }
            };
        }
        @Bean DataSource dataSource() {return new DriverManagerDataSource(url,"postgres","synthetic-epoch-test-only");}
        @Bean JdbcTemplate jdbc(DataSource source) {return new JdbcTemplate(source);}
        @Bean PlatformTransactionManager transactionManager(DataSource source) {return new DataSourceTransactionManager(source);}
    }
    @BeforeAll void start() throws Exception {
        schema="epoch_"+UUID.randomUUID().toString().replace("-","");
        var admin=new JdbcTemplate(new DriverManagerDataSource(System.getenv("DLV919_DATABASE_URL"),"postgres","synthetic-epoch-test-only"));
        admin.execute("CREATE SCHEMA "+schema);
        url=System.getenv("DLV919_DATABASE_URL")+"?currentSchema="+schema;
        var source=new DriverManagerDataSource(url,"postgres","synthetic-epoch-test-only"); jdbc=new JdbcTemplate(source);
        String sql=Files.readString(Path.of("src/main/resources/db/identity/V1__identity.sql")).split("REVOKE ALL")[0]
                +Files.readString(Path.of("src/main/resources/db/identity/V2__credential_epoch.sql"));
        new ResourceDatabasePopulator(new ByteArrayResource(sql.getBytes(StandardCharsets.UTF_8))).execute(source);
        var generator=java.security.KeyPairGenerator.getInstance("RSA");generator.initialize(3072);var keys=generator.generateKeyPair();
        Path directory=Files.createTempDirectory(Path.of("build"),"epoch-test-keys-");
        Path privateKey=directory.resolve("private.pem"),publicKey=directory.resolve("public.pem");
        Files.writeString(privateKey,"-----BEGIN " + "PRIVATE KEY-----\n"+Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded())+"\n-----END " + "PRIVATE KEY-----");
        Files.writeString(publicKey,"-----BEGIN PUBLIC KEY-----\n"+Base64.getEncoder().encodeToString(keys.getPublic().getEncoded())+"\n-----END PUBLIC KEY-----");
        oauthProperties=new OAuthProperties("https://example.test","https://example.test",SECRET,CLIENT,"https://example.test",privateKey,publicKey,java.time.Duration.ofSeconds(3),java.time.Duration.ofSeconds(7),java.time.Duration.ofMinutes(1),java.time.Duration.ofMinutes(5),java.time.Duration.ofHours(8));
        first=server(); second=server();
    }
    ConfigurableApplicationContext server() {
        return new SpringApplicationBuilder(App.class).profiles("accounts","oauth-server").properties("spring.config.name=epoch-test",
                "server.port=0","app.accounts.registration-enabled=true","app.deployment-environment=local",
                "spring.jackson.deserialization.fail-on-unknown-properties=false").run();
    }
    @AfterAll void stop() {
        if(first!=null)first.close();if(second!=null)second.close();
        if(jdbc!=null) jdbc.execute("DROP SCHEMA "+schema+" CASCADE");
        if(oauthProperties!=null) try { Files.deleteIfExists(oauthProperties.signingPrivateKey());Files.deleteIfExists(oauthProperties.signingPublicKey());Files.deleteIfExists(oauthProperties.signingPublicKey().getParent()); } catch(java.io.IOException error){throw new IllegalStateException(error);}
    }
    UUID account(String hash) {
        UUID id=UUID.randomUUID();String email=id+"@example.test";
        jdbc.update("INSERT INTO accounts(id,username,display_name,password_hash) VALUES (?,?,?,?)",id,email,"Synthetic",hash);
        jdbc.update("INSERT INTO account_profiles(account_id,first_name,last_name,email,country_code) VALUES (?,?,?,?,?)",id,"Synthetic","Learner",email,"US");return id;
    }
    UUID account() {return account(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(legacy));}
    AccountPrincipal principal(UUID id) {return new AccountPrincipal(id,id+"@example.test","Synthetic",null,true,0);}
    HttpClient browser() {return HttpClient.newBuilder().cookieHandler(new CookieManager(null,CookiePolicy.ACCEPT_ALL)).build();}
    HttpResponse<String> request(ConfigurableApplicationContext app,HttpClient browser,String method,String path,String body,String csrf,String type) throws Exception {
        int port=((WebServerApplicationContext)app).getWebServer().getPort();
        var builder=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path));
        if(csrf!=null)builder.header("X-CSRF-TOKEN",csrf);if(type!=null)builder.header("Content-Type",type);
        return browser.send(builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    String csrf(ConfigurableApplicationContext app,HttpClient browser)throws Exception{return mapper.readTree(request(app,browser,"GET","/api/v1/auth/csrf",null,null,null).body()).path("data").path("token").asText();}
    void login(ConfigurableApplicationContext app,HttpClient browser,UUID id,String password)throws Exception{
        assertThat(request(app,browser,"POST","/api/v1/auth/login","username="+URLEncoder.encode(id+"@example.test",StandardCharsets.UTF_8)+"&password="+URLEncoder.encode(password,StandardCharsets.UTF_8),csrf(app,browser),"application/x-www-form-urlencoded").statusCode()).isEqualTo(200);
    }
    String authorize(ConfigurableApplicationContext app,HttpClient browser,String verifier) throws Exception {
        String challenge=Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        var response=request(app,browser,"GET","/oauth2/authorize?response_type=code&client_id="+CLIENT+"&redirect_uri="+URLEncoder.encode("https://example.test/login/oauth2/code/lookahead",StandardCharsets.UTF_8)+"&scope=openid%20account&state=synthetic&code_challenge_method=S256&code_challenge="+challenge,null,null,null);
        assertThat(response.statusCode()).isEqualTo(302);
        String location=response.headers().firstValue("location").orElseThrow();
        assertThat(location).contains("code=");
        return Arrays.stream(URI.create(location).getRawQuery().split("&")).filter(v->v.startsWith("code=")).map(v->URLDecoder.decode(v.substring(5),StandardCharsets.UTF_8)).findFirst().orElseThrow();
    }
    HttpResponse<String> token(ConfigurableApplicationContext app,String body) throws Exception {
        int port=((WebServerApplicationContext)app).getWebServer().getPort();
        return browser().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/oauth2/token"))
                .header("Authorization","Basic "+Base64.getEncoder().encodeToString((CLIENT+":"+SECRET).getBytes(StandardCharsets.UTF_8)))
                .header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    String codeBody(String code,String verifier) {return "grant_type=authorization_code&code="+URLEncoder.encode(code,StandardCharsets.UTF_8)+"&redirect_uri="+URLEncoder.encode("https://example.test/login/oauth2/code/lookahead",StandardCharsets.UTF_8)+"&code_verifier="+verifier;}
    @Test void realOAuthCodeRefreshAndOldOAuthSessionFailAcrossInstances() throws Exception {
        UUID id=account();var browser1=browser();var browser2=browser();login(first,browser1,id,legacy);login(second,browser2,id,legacy);
        String verifier="v".repeat(64);String code=authorize(first,browser1,verifier);
        var exchange=token(second,codeBody(code,verifier));assertThat(exchange.statusCode()).isEqualTo(200);
        String refresh=mapper.readTree(exchange.body()).path("refresh_token").asText();assertThat(refresh).isNotBlank();
        var refreshed=token(first,"grant_type=refresh_token&refresh_token="+URLEncoder.encode(refresh,StandardCharsets.UTF_8));assertThat(refreshed.statusCode()).isEqualTo(200);
        String currentRefresh=mapper.readTree(refreshed.body()).path("refresh_token").asText();
        String access=mapper.readTree(refreshed.body()).path("access_token").asText();
        assertThat(second.getBean(com.lookahead.identity.verification.TokenVerificationService.class).verify(access).get("active")).isEqualTo(true);
        String outstanding=authorize(second,browser2,verifier);
        first.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,"oauth rotation password","oauth rotation password"));
        assertThat(token(first,codeBody(outstanding,verifier)).statusCode()).isEqualTo(400);
        assertThat(token(second,"grant_type=refresh_token&refresh_token="+URLEncoder.encode(currentRefresh,StandardCharsets.UTF_8)).statusCode()).isEqualTo(400);
        assertThat(second.getBean(com.lookahead.identity.verification.TokenVerificationService.class).verify(access).get("active")).isEqualTo(false);
        assertThat(request(second,browser2,"GET","/oauth2/authorize?response_type=code&client_id="+CLIENT,null,null,null).statusCode()).isEqualTo(401);
    }
    @Test void twoInstancesRejectAllOldSessionsAndPreserveUnrelatedAccount() throws Exception {
        UUID owner=account(),other=account();var browser1=browser();var browser2=browser();var unrelated=browser();
        login(first,browser1,owner,legacy);login(second,browser2,owner,legacy);login(second,unrelated,other,legacy);
        String next="😀".repeat(128);String body=mapper.writeValueAsString(new PasswordChangeRequest(legacy,next,next));
        assertThat(request(first,browser1,"POST","/api/v1/account/password",body,null,"application/json").statusCode()).isEqualTo(403);
        String forged=body.substring(0,body.length()-1)+",\"accountId\":\""+other+"\"}";
        assertThat(request(first,browser1,"POST","/api/v1/account/password",forged,csrf(first,browser1),"application/json").statusCode()).isEqualTo(422);
        var response=request(first,browser1,"POST","/api/v1/account/password",body,csrf(first,browser1),"application/json");
        assertThat(response.statusCode()).isEqualTo(200);assertThat(response.body()).contains("reauthenticationRequired");
        assertThat(request(first,browser1,"GET","/api/v1/auth/me",null,null,null).statusCode()).isEqualTo(401);
        assertThat(request(second,browser2,"GET","/api/v1/auth/me",null,null,null).statusCode()).isEqualTo(401);
        assertThat(request(second,unrelated,"GET","/api/v1/auth/me",null,null,null).statusCode()).isEqualTo(200);
        login(second,browser(),owner,next);
        var verifier=PasswordEncoderFactories.createDelegatingPasswordEncoder();var hash=jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,owner);
        assertThat(verifier.matches(next,hash)).isTrue();assertThat(verifier.matches(next.substring(0,72),hash)).isFalse();
    }
    @Test void registeredPbkdf2LegacyPasswordAndUnchangedRejection() throws Exception {
        var encoder=org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        UUID id=account("{pbkdf2@SpringSecurity_v5_8}"+encoder.encode(legacy));
        login(first,browser(),id,legacy);
        String next="a fresh registered password";
        first.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,next,next));
        login(second,browser(),id,next);
        var current=new AccountPrincipal(id,id+"@example.test","Synthetic",null,true,1);
        assertThatThrownBy(()->second.getBean(PasswordChangeService.class).change(current,new PasswordChangeRequest(next,next,next))).hasMessageContaining("different password");
        var oldBrowser=browser();
        assertThat(request(first,oldBrowser,"POST","/api/v1/auth/login","username="+URLEncoder.encode(id+"@example.test",StandardCharsets.UTF_8)+"&password="+legacy,csrf(first,oldBrowser),"application/x-www-form-urlencoded").statusCode()).isEqualTo(401);
    }
    @Test void durableFailureWindowAndStorageRollback() {
        UUID id=account();var service=first.getBean(PasswordChangeService.class);String next="a unique new password";
        for(int n=0;n<5;n++)assertThatThrownBy(()->service.change(principal(id),new PasswordChangeRequest("wrong",next,next))).hasMessageContaining("could not be verified");
        assertThatThrownBy(()->second.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,next,next))).hasMessageContaining("15 minutes");
        jdbc.update("UPDATE accounts SET password_failure_window=CURRENT_TIMESTAMP - INTERVAL '16 minutes' WHERE id=?",id);
        jdbc.execute("ALTER TABLE oauth2_authorization RENAME TO unavailable_authorizations");
        try{assertThatThrownBy(()->service.change(principal(id),new PasswordChangeRequest(legacy,next,next))).isInstanceOf(org.springframework.dao.DataAccessException.class);}
        finally{jdbc.execute("ALTER TABLE unavailable_authorizations RENAME TO oauth2_authorization");}
        assertThat(jdbc.queryForObject("SELECT credential_epoch FROM accounts WHERE id=?",Long.class,id)).isZero();
        service.change(principal(id),new PasswordChangeRequest(legacy,next,next));
        assertThat(jdbc.queryForObject("SELECT credential_epoch FROM accounts WHERE id=?",Long.class,id)).isEqualTo(1);
    }
    @Test void staleAuthorizationSaveCannotResurrectDeletedCodesOrTokens() throws Exception {
        UUID id=account();var clients=new JdbcRegisteredClientRepository(jdbc);
        var client=RegisteredClient.withId(UUID.randomUUID().toString()).clientId(UUID.randomUUID().toString()).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://example.test/callback").build();clients.save(client);
        var raw=new JdbcOAuth2AuthorizationService(jdbc,clients);
        var guarded=new EpochAuthorizationService(raw,jdbc,first.getBean(PlatformTransactionManager.class));
        var access=new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access-"+id,Instant.now(),Instant.now().plusSeconds(300));
        var refresh=new OAuth2RefreshToken("synthetic-refresh-"+id,Instant.now(),Instant.now().plusSeconds(300));
        var code=new OAuth2AuthorizationCode("synthetic-code-"+id,Instant.now(),Instant.now().plusSeconds(300));
        var auth=OAuth2Authorization.withRegisteredClient(client).principalName(id.toString()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).attribute(EpochAuthorizationService.EPOCH,"0").accessToken(access).refreshToken(refresh).token(code).build();
        guarded.save(auth);
        first.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,"another unique password","another unique password"));
        for(String token:List.of(access.getTokenValue(),refresh.getTokenValue(),code.getTokenValue()))assertThat(guarded.findByToken(token,null)).isNull();
        assertThatThrownBy(()->guarded.save(auth)).isInstanceOf(OAuth2AuthenticationException.class);
        assertThat(raw.findById(auth.getId())).isNull();
    }
    @Test void loginUsingOldCredentialSnapshotCannotSurviveRotation() throws Exception {
        UUID id=account();var browser=browser();String token=csrf(first,browser);var pool=Executors.newSingleThreadExecutor();
        loginCaptured=new CountDownLatch(1);releaseLogin=new CountDownLatch(1);
        try {
            var result=pool.submit(()->request(first,browser,"POST","/api/v1/auth/login","username="+URLEncoder.encode(id+"@example.test",StandardCharsets.UTF_8)+"&password="+legacy,token,"application/x-www-form-urlencoded"));
            assertThat(loginCaptured.await(10,TimeUnit.SECONDS)).isTrue();
            second.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,"login race new password","login race new password"));
            releaseLogin.countDown();assertThat(result.get(10,TimeUnit.SECONDS).statusCode()).isEqualTo(401);
            assertThat(request(first,browser,"GET","/api/v1/auth/me",null,null,null).statusCode()).isEqualTo(401);
        }finally{releaseLogin.countDown();loginCaptured=null;releaseLogin=null;pool.shutdownNow();}
    }
    @Test void authorizationSaveWaitingOnRotationLockFailsAfterCommit() throws Exception {
        UUID id=account();var client=RegisteredClient.withId(UUID.randomUUID().toString()).clientId(UUID.randomUUID().toString()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://example.test/callback").build();
        var authorization=OAuth2Authorization.withRegisteredClient(client).principalName(id.toString()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).attribute(EpochAuthorizationService.EPOCH,"0").build();
        var delegate=new InMemoryOAuth2AuthorizationService();
        var guarded=new EpochAuthorizationService(delegate,jdbc,second.getBean(PlatformTransactionManager.class));
        var held=new CountDownLatch(1);var release=new CountDownLatch(1);var saveStarted=new CountDownLatch(1);var pool=Executors.newFixedThreadPool(2);
        try {
            var rotation=pool.submit(()->new org.springframework.transaction.support.TransactionTemplate(first.getBean(PlatformTransactionManager.class)).executeWithoutResult(status->{
                first.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,"blocked race password","blocked race password"));
                held.countDown();try{if(!release.await(10,TimeUnit.SECONDS))throw new IllegalStateException("test lock timeout");}catch(InterruptedException error){throw new IllegalStateException(error);}
            }));
            assertThat(held.await(10,TimeUnit.SECONDS)).isTrue();
            var save=pool.submit(()->{saveStarted.countDown();guarded.save(authorization);});
            assertThat(saveStarted.await(10,TimeUnit.SECONDS)).isTrue();release.countDown();rotation.get(10,TimeUnit.SECONDS);
            assertThatThrownBy(()->save.get(10,TimeUnit.SECONDS)).hasCauseInstanceOf(OAuth2AuthenticationException.class);
            assertThat(delegate.findById(authorization.getId())).isNull();
        }finally{release.countDown();pool.shutdownNow();}
    }
    @Test void profilePersistsAndOldPrincipalCannotWriteAfterRotation() throws Exception {
        UUID id=account();var old=principal(id);var profiles=first.getBean(AccountProfileService.class);
        String hash=jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,id);
        assertThat(profiles.update(id,0,"  Updated learner  ").displayName()).isEqualTo("Updated learner");
        assertThat(second.getBean(AccountUserDetailsService.class).accountView(old).displayName()).isEqualTo("Updated learner");
        assertThat(jdbc.queryForObject("SELECT password_hash FROM accounts WHERE id=?",String.class,id)).isEqualTo(hash);
        assertThat(profiles.read(id,0).username()).isEqualTo(id+"@example.test");
        first.getBean(PasswordChangeService.class).change(old,new PasswordChangeRequest(legacy,"profile new password","profile new password"));
        assertThatThrownBy(()->profiles.update(id,0,"stale")).hasMessageContaining("Sign in");
        assertThat(profiles.read(id,1).displayName()).isEqualTo("Updated learner");
    }
    @Test void concurrentPasswordChangesHaveOneWinner() throws Exception {
        UUID id=account();var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try {
            var calls=new ArrayList<Future<Boolean>>();
            for(var app:List.of(first,second))calls.add(pool.submit(()->{start.await();try{app.getBean(PasswordChangeService.class).change(principal(id),new PasswordChangeRequest(legacy,"unique race password","unique race password"));return true;}catch(com.lookahead.identity.exception.AccountFailure expected){assertThat(expected.code()).isEqualTo("AUTHENTICATION_REQUIRED");return false;}}));
            start.countDown();int successes=0;for(var call:calls)if(call.get(20,TimeUnit.SECONDS))successes++;
            assertThat(successes).isEqualTo(1);assertThat(jdbc.queryForObject("SELECT credential_epoch FROM accounts WHERE id=?",Long.class,id)).isEqualTo(1);
        }finally{pool.shutdownNow();}
    }
}
