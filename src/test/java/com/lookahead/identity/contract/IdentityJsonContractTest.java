package com.lookahead.identity.contract;

import com.lookahead.identity.repository.AccountRepository;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.AccountUserDetailsService;
import com.lookahead.learning.content.dto.AccountView;
import com.lookahead.learning.content.dto.ApiError;
import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.dto.ApplicationStatus;
import com.lookahead.learning.content.dto.CsrfView;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.exc.MismatchedInputException;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/** Provider wire compatibility after replacing the shared records with app-owned records. */
@SpringBootTest(classes = IdentityJsonContractTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = "spring.config.name=wire-contract-test")
class IdentityJsonContractTest {
    private static final UUID ACCOUNT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant TIMESTAMP = Instant.parse("2026-09-18T12:34:56Z");

    @Autowired ObjectMapper mapper;

    @Configuration
    @EnableAutoConfiguration(excludeName = {
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    static class App { }

    @Test
    void accountResponsePreservesFieldsUuidAndSetValues() {
        var account = new AccountView(ACCOUNT_ID, "learner@example.test", "Learner",
                Set.of("learn:java"), Set.of("lesson:java-basics"), false);
        String json = mapper.writeValueAsString(new ApiResponse<>(account, TIMESTAMP));
        assertThat(mapper.readTree(json)).isEqualTo(mapper.readTree("""
                {"data":{"accountId":"00000000-0000-0000-0000-000000000001",
                 "username":"learner@example.test","displayName":"Learner",
                 "topicGrants":["learn:java"],"contentGrants":["lesson:java-basics"],
                 "authorPreview":false},"timestamp":"2026-09-18T12:34:56Z"}
                """));
        assertThat(mapper.treeToValue(mapper.readTree(json).path("data"), AccountView.class))
                .isEqualTo(account);
    }

    @Test
    void identityProjectionNeverSerializesCredentialsOrProductPrivileges() {
        var principal = new AccountPrincipal(ACCOUNT_ID, "learner@example.test", "Learner",
                "synthetic-password-hash-not-for-a-real-account", true);
        var users = new AccountUserDetailsService(mock(AccountRepository.class));
        String json = mapper.writeValueAsString(users.accountView(principal));
        assertThat(mapper.readTree(json)).isEqualTo(mapper.readTree("""
                {"accountId":"00000000-0000-0000-0000-000000000001",
                 "username":"learner@example.test","displayName":"Learner",
                 "topicGrants":[],"contentGrants":[],"authorPreview":false}
                """));
        assertThat(json).doesNotContain("password", "hash", "authorities", "enabled", "secret");
    }

    @Test
    void missingOptionalFieldsKeepExistingRecordDefaults() {
        var account = mapper.readValue("""
                {"accountId":"00000000-0000-0000-0000-000000000001",
                 "username":"learner@example.test","authorPreview":false}
                """, AccountView.class);
        assertThat(account.accountId()).isEqualTo(ACCOUNT_ID);
        assertThat(account.displayName()).isNull();
        assertThat(account.topicGrants()).isNull();
        assertThat(account.contentGrants()).isNull();
        assertThat(account.authorPreview()).isFalse();
    }

    @Test
    void missingOrNullPrimitiveRetainsTheExistingDeserializationRejection() {
        assertThatThrownBy(() -> mapper.readValue("{}", AccountView.class))
                .isInstanceOf(MismatchedInputException.class)
                .hasMessageContaining("authorPreview");
        assertThatThrownBy(() -> mapper.readValue("{\"authorPreview\":null}", AccountView.class))
                .isInstanceOf(MismatchedInputException.class)
                .hasMessageContaining("authorPreview");
    }

    @Test
    void explicitNullsAndEmptyResponseRetainTheirWireRepresentation() {
        var account = mapper.readValue("""
                {"accountId":null,"username":null,"displayName":null,
                 "topicGrants":null,"contentGrants":null,"authorPreview":false}
                """, AccountView.class);
        assertThat(mapper.readTree(mapper.writeValueAsString(account))).isEqualTo(mapper.readTree("""
                {"accountId":null,"username":null,"displayName":null,
                 "topicGrants":null,"contentGrants":null,"authorPreview":false}
                """));
        assertThat(mapper.readTree(mapper.writeValueAsString(new ApiResponse<>(null, TIMESTAMP))))
                .isEqualTo(mapper.readTree("{\"data\":null,\"timestamp\":\"2026-09-18T12:34:56Z\"}"));
    }

    @Test
    void errorContractPreservesStatusDetailsAndIsoTimestamp() {
        var error = new ApiError(400, "Bad Request", "Request validation failed",
                "/api/v1/auth/register", List.of("countryCode: must not be blank"), TIMESTAMP);
        String json = mapper.writeValueAsString(error);
        assertThat(mapper.readTree(json)).isEqualTo(mapper.readTree("""
                {"status":400,"error":"Bad Request","message":"Request validation failed",
                 "path":"/api/v1/auth/register","details":["countryCode: must not be blank"],
                 "timestamp":"2026-09-18T12:34:56Z"}
                """));
        assertThat(mapper.readValue(json, ApiError.class)).isEqualTo(error);
    }

    @Test
    void csrfNamesRemainCompatibleWithBrowserClients() {
        var csrf = new CsrfView("synthetic-csrf-token", "X-CSRF-TOKEN", "_csrf");
        String json = mapper.writeValueAsString(csrf);
        assertThat(mapper.readTree(json)).isEqualTo(mapper.readTree("""
                {"token":"synthetic-csrf-token","headerName":"X-CSRF-TOKEN","parameterName":"_csrf"}
                """));
        assertThat(mapper.readValue(json, CsrfView.class)).isEqualTo(csrf);
    }

    @Test
    void statusNamesRemainCompatibleWithExistingClients() {
        var status = new ApplicationStatus("lookahead-identity", "UP", "0.0.1-SNAPSHOT");
        String json = mapper.writeValueAsString(status);
        assertThat(mapper.readTree(json)).isEqualTo(mapper.readTree("""
                {"application":"lookahead-identity","status":"UP","version":"0.0.1-SNAPSHOT"}
                """));
        assertThat(mapper.readValue(json, ApplicationStatus.class)).isEqualTo(status);
    }
}
