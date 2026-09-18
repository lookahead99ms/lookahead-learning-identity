package com.lookahead.identity.security;

import com.lookahead.identity.config.AccountSecurityConfig;
import com.lookahead.identity.controller.*;
import com.lookahead.identity.dto.*;
import com.lookahead.learning.content.dto.*;
import com.lookahead.identity.handler.AccountErrorHandler;
import com.lookahead.identity.repository.AccountRepository;
import com.lookahead.identity.model.AccountCredentials;
import com.lookahead.identity.service.*;
import com.lookahead.identity.validator.LocalTestSeedGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.ObjectMapper;
import java.net.*;
import java.net.http.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

@SpringBootTest(classes = RegistrationSecurityIntegrationTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=security-test", "app.accounts.registration-enabled=true", "app.deployment-environment=local"})
@ActiveProfiles("accounts")
class RegistrationSecurityIntegrationTest {
    @LocalServerPort int port;
    @Autowired ObjectMapper mapper;
    @Configuration
    @EnableAutoConfiguration(excludeName = {"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration", "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @Import({AccountSecurityConfig.class, AuthController.class, RegistrationController.class, RegistrationService.class, AccountUserDetailsService.class, AccountErrorHandler.class, LocalTestSeedGuard.class})
    static class App {
        @Bean JdbcTemplate jdbc() { return mock(JdbcTemplate.class); }
        @Bean AccountRepository accounts() {
            var repo = mock(AccountRepository.class);
            var registeredId = UUID.randomUUID();
            var syntheticId = UUID.randomUUID();
            var hash = PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("long test passphrase");
            when(repo.findByUsername(anyString())).thenAnswer(call -> {
                String email = call.getArgument(0);
                return Optional.of(new AccountCredentials(email.equals("synthetic") ? syntheticId : registeredId, email, "Avery Learner", hash, true));
            });
            when(repo.hasRegistrationProfile(registeredId)).thenReturn(true);
            return repo;
        }
    }
    HttpClient client(CookieManager cookies) { return HttpClient.newBuilder().cookieHandler(cookies).build(); }
    HttpResponse<String> request(HttpClient client, String method, String path, String body, String token, String type) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/auth" + path));
        if (token != null) builder.header("X-CSRF-TOKEN", token);
        if (body != null) builder.header("Content-Type", type);
        return client.send(builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
    String token(HttpClient client) throws Exception { return mapper.readTree(request(client,"GET","/csrf",null,null,null).body()).path("data").path("token").asText(); }
    @Test void registrationRequiresCsrfAndCountryThenCreatesARotatedSession() throws Exception {
        var cookies = new CookieManager(null,CookiePolicy.ACCEPT_ALL); var client=client(cookies);
        String csrf=token(client); String originalSession=cookies.getCookieStore().getCookies().getFirst().getValue();
        var fields=new HashMap<String,String>(Map.of("firstName","Avery","lastName","Learner","email","avery@example.test","password","long test passphrase","confirmPassword","long test passphrase"));
        assertThat(request(client,"POST","/register",mapper.writeValueAsString(fields),null,"application/json").statusCode()).isEqualTo(403);
        assertThat(request(client,"POST","/register",mapper.writeValueAsString(fields),csrf,"application/json").statusCode()).isEqualTo(422);
        fields.put("countryCode","US");
        var result=request(client,"POST","/register",mapper.writeValueAsString(fields),csrf,"application/json");
        assertThat(result.statusCode()).isEqualTo(201);
        assertThat(result.body()).contains("avery@example.test").doesNotContain("password", "passphrase");
        assertThat(result.headers().firstValue("cache-control")).contains("no-store");
        assertThat(cookies.getCookieStore().getCookies().getFirst().getValue()).isNotEqualTo(originalSession);
        assertThat(request(client,"GET","/me",null,null,null).statusCode()).isEqualTo(200);
        assertThat(request(client,"POST","/logout","",csrf,"application/x-www-form-urlencoded").statusCode()).isEqualTo(403);
        assertThat(request(client,"POST","/logout","",token(client),"application/x-www-form-urlencoded").statusCode()).isEqualTo(204);
        assertThat(request(client,"GET","/me",null,null,null).statusCode()).isEqualTo(401);
    }
    @Test void emailLoginDoesNotEnableSyntheticCredentialsOutsideLocalTest() throws Exception {
        var client=client(new CookieManager(null,CookiePolicy.ACCEPT_ALL));
        assertThat(request(client,"POST","/login","username=synthetic&password=long+test+passphrase",token(client),"application/x-www-form-urlencoded").statusCode()).isEqualTo(401);
        assertThat(request(client,"POST","/login","username=avery%40example.test&password=long+test+passphrase",token(client),"application/x-www-form-urlencoded").statusCode()).isEqualTo(200);
    }
}
