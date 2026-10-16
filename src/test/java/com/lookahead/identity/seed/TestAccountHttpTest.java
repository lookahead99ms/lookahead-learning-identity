package com.lookahead.identity.seed;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.*;
import org.springframework.test.context.ActiveProfiles;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(classes=TestAccountHttpTest.App.class, webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties={"spring.config.name=test-account-http", "app.deployment-environment=local",
                "app.test-accounts.enabled=true", "app.test-accounts.operator-secret=synthetic-test-account-operator-credential-only"})
@ActiveProfiles({"accounts", "local-test"})
class TestAccountHttpTest {
    @Configuration
    @EnableAutoConfiguration(excludeName={"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @ComponentScan(basePackageClasses=TestAccountSecurity.class, useDefaultFilters=false,
            includeFilters=@ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,classes=TestAccountSecurity.class))
    @Import({TestAccountPolicy.class, TestAccountController.class})
    static class App {
        @Bean TestAccountService service() {
            var service=mock(TestAccountService.class);
            when(service.seed("synthetic-learner-only", "synthetic-staff-only")).thenReturn(List.of());
            when(service.rotate("synthetic-learner-only", "synthetic-staff-only")).thenReturn(35);
            return service;
        }
    }
    @LocalServerPort int port;
    private HttpResponse<String> send(String method, String path, String credentials) throws Exception {
        var builder=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/internal/v1/test-accounts/"+path))
                .header("Content-Type", "application/json").header("Cookie", "JSESSIONID=forged");
        if(credentials!=null)builder.header("Authorization", "Basic "+Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        builder.method(method,HttpRequest.BodyPublishers.ofString(path.equals("disable-real")
                ? "{\"accountId\":\"00000000-0000-0000-0000-000000000001\"}"
                : "{\"learnerPassword\":\"synthetic-learner-only\",\"staffPassword\":\"synthetic-staff-only\"}"));
        return HttpClient.newHttpClient().send(builder.build(),HttpResponse.BodyHandlers.ofString());
    }
    private static final String OPERATOR="lookahead-test-account-operator:synthetic-test-account-operator-credential-only";
    @Test void onlyDedicatedCredentialCanSeedOrRotate() throws Exception {
        for(String path:List.of("seed","passwords")) {
            for(String credentials:new String[]{null,"lookahead-test-account-operator:wrong",
                    "lookahead-domain-verifier:synthetic-test-account-operator-credential-only"}) {
                var response=send("POST",path,credentials);
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().firstValue("set-cookie")).isEmpty();
                assertThat(response.headers().firstValue("location")).isEmpty();
            }
            var success=send("POST",path,OPERATOR);
            assertThat(success.statusCode()).isEqualTo(200);
            assertThat(success.headers().firstValue("cache-control")).contains("no-store");
            assertThat(success.headers().firstValue("set-cookie")).isEmpty();
            assertThat(success.body()).doesNotContain("synthetic-learner", "synthetic-staff");
        }
        assertThat(send("POST","passwords",OPERATOR).body()).contains("\"updated\":35");
    }
    @Test void safeMethodsAndUnlistedOperationsCannotMutate() throws Exception {
        assertThat(send("GET","seed",OPERATOR).statusCode()).isEqualTo(403);
        assertThat(send("POST","reset",OPERATOR).statusCode()).isEqualTo(403);
        assertThat(new TestAccountController.Passwords("private-one","private-two").toString())
                .doesNotContain("private-one","private-two");
    }
    @Test void creationAndDeletionEndpointsRequireTheOperatorAndDoNotExposePasswords() throws Exception {
        for (String operation : List.of("provision", "activate", "disable", "disable-real")) {
            assertThat(send("POST",operation,null).statusCode()).isEqualTo(401);
            var success=send("POST",operation,OPERATOR);
            assertThat(success.statusCode()).isEqualTo(200);
            assertThat(success.headers().firstValue("cache-control")).contains("no-store");
            assertThat(success.body()).doesNotContain("synthetic-learner-only");
        }
        assertThat(new TestAccountController.Provision(java.util.UUID.randomUUID(),"test-0123456789abcdef01234567","private-password").toString())
                .doesNotContain("private-password");
    }
}
