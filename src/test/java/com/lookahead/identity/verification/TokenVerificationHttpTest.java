package com.lookahead.identity.verification;

import com.lookahead.identity.filter.OAuthStorageFailureFilter;
import com.lookahead.identity.handler.AccountErrorHandler;
import com.lookahead.identity.oauth.OAuthSettings;
import com.lookahead.identity.repository.AccountRepository;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

@SpringBootTest(classes = TokenVerificationHttpTest.Application.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=verification-test",
                "app.identity.verifier-secret=synthetic-verifier-secret-with-32-characters",
                "app.oauth.client-secret=synthetic-gateway-secret-with-32-characters"})
@ActiveProfiles({"accounts", "oauth-server"})
class TokenVerificationHttpTest {
    @LocalServerPort int port;
    @Configuration
    @EnableAutoConfiguration(excludeName = {"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @org.springframework.context.annotation.ComponentScan(basePackageClasses = TokenVerificationSecurity.class,
            useDefaultFilters = false, includeFilters = @org.springframework.context.annotation.ComponentScan.Filter(
                    type = org.springframework.context.annotation.FilterType.ASSIGNABLE_TYPE,
                    classes = TokenVerificationSecurity.class))
    @Import({TokenVerificationService.class, TokenVerificationController.class,
            OAuthStorageFailureFilter.class, AccountErrorHandler.class})
    static class Application {
        @Bean JwtDecoder decoder() {
            return token -> {
                if (token.equals("outage")) return Jwt.withTokenValue(token).header("alg", "RS256")
                        .subject(UUID.randomUUID().toString()).audience(List.of("lookahead-api"))
                        .claim("client_id", "lookahead-web-gateway").build();
                throw new BadJwtException("sensitive parser message");
            };
        }
        @Bean OAuthSettings settings() { return new OAuthSettings("https://example.test", "lookahead-web-gateway",
                "synthetic-gateway-secret-with-32-characters", "http://identity:8080", "https://example.test"); }
        @Bean OAuth2AuthorizationService authorizations() {
            var service = mock(OAuth2AuthorizationService.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
            when(service.findByToken(anyString(), any())).thenThrow(new DataAccessResourceFailureException("private SQL detail"));
            return service;
        }
        @Bean RegisteredClientRepository clients() { return mock(RegisteredClientRepository.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS)); }
        @Bean AccountRepository accounts() { return mock(AccountRepository.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS)); }
    }
    private HttpResponse<String> send(String credentials, String token) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/internal/v1/tokens/verify"))
                .header("Content-Type", "application/x-www-form-urlencoded");
        if (credentials != null) request.header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                .send(request.POST(HttpRequest.BodyPublishers.ofString("token=" + token)).build(), HttpResponse.BodyHandlers.ofString());
    }
    @Test void privateEndpointRequiresItsOwnCredentialsAndNeverRedirects() throws Exception {
        for (String credentials : new String[]{null, "lookahead-platform-verifier:wrong",
                "lookahead-platform-verifier:synthetic-gateway-secret-with-32-characters",
                "lookahead-web-gateway:synthetic-verifier-secret-with-32-characters"}) {
            var response = send(credentials, "bad");
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("location")).isEmpty();
            assertThat(response.headers().firstValue("cache-control")).contains("no-store");
        }
    }
    @Test void invalidTokensReturnInactiveWithoutCsrfOrSessionAndWithoutParserDetails() throws Exception {
        var response = send("lookahead-platform-verifier:synthetic-verifier-secret-with-32-characters", "bad");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("{\"active\":false}");
        assertThat(response.headers().firstValue("cache-control")).contains("no-store");
        assertThat(response.headers().firstValue("set-cookie")).isEmpty();
    }
    @Test void storageFailureReturnsSafe503() throws Exception {
        var response = send("lookahead-platform-verifier:synthetic-verifier-secret-with-32-characters", "outage");
        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.body()).contains("ACCOUNT_STORAGE_UNAVAILABLE").doesNotContain("private SQL", "outage");
        assertThat(response.headers().firstValue("cache-control")).contains("no-store");
    }
}
