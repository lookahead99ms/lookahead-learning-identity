package com.lookahead.identity.service;

import com.lookahead.identity.controller.AccountProfileController;
import com.lookahead.identity.dto.AccountProfileView;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.identity.security.AccountPrincipal;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class AccountProfileServiceTest {
    @Test void trimsNamesAndCountsUnicodeCodePoints() {
        assertThat(AccountProfileService.validate("  Avery Learner  ")).isEqualTo("Avery Learner");
        assertThat(AccountProfileService.validate("😀".repeat(160))).hasSize(320);
        assertThatThrownBy(() -> AccountProfileService.validate("😀".repeat(161))).isInstanceOf(AccountFailure.class);
        assertThatThrownBy(() -> AccountProfileService.validate(null)).isInstanceOf(AccountFailure.class);
    }
    @ParameterizedTest @ValueSource(strings={"", "   ", "A\nB", "A\tB", "A\u0000B"})
    void rejectsInvalidNames(String name) {
        assertThatThrownBy(() -> AccountProfileService.validate(name)).isInstanceOf(AccountFailure.class);
    }
    @Test void rejectsMassAssignmentAndCallerSelectedOwner() {
        var service=mock(AccountProfileService.class);
        var controller=new AccountProfileController(service);
        var principal=new AccountPrincipal(UUID.randomUUID(),"learner@example.test","Old",null,true);
        for (String field:List.of("accountId","username","email","enabled","roles","grants","author","password")) {
            var body=new HashMap<String,Object>(); body.put("displayName","Avery"); body.put(field,"injected");
            assertThatThrownBy(() -> controller.update(principal,body,new MockHttpServletResponse())).isInstanceOf(AccountFailure.class);
        }
        verifyNoInteractions(service);
    }
    @Test void responseUsesFreshDatabaseIdentityAndSessionOwnerOnly() {
        var service=mock(AccountProfileService.class);
        var controller=new AccountProfileController(service);
        UUID owner=UUID.randomUUID();
        var principal=new AccountPrincipal(owner,"learner@example.test","Old",null,true);
        var authoritative=new AccountProfileView(owner,"learner@example.test","New");
        when(service.update(owner,0,"New")).thenReturn(authoritative);
        var response=new MockHttpServletResponse();
        assertThat(controller.update(principal,Map.of("displayName","New"),response).data()).isEqualTo(authoritative);
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        verify(service).update(owner,0,"New");
    }
    @Test void anonymousCannotInvokeProfileService() {
        var service=mock(AccountProfileService.class); var controller=new AccountProfileController(service);
        assertThatThrownBy(() -> controller.read(null,new MockHttpServletResponse())).isInstanceOf(AccountFailure.class);
        assertThatThrownBy(() -> controller.update(null,Map.of("displayName","Avery"),new MockHttpServletResponse())).isInstanceOf(AccountFailure.class);
        verifyNoInteractions(service);
    }
    @Test void disabledOrMissingAccountsFailClosed() {
        var jdbc=mock(JdbcTemplate.class);var service=new AccountProfileService(jdbc);
        assertThatThrownBy(() -> service.read(UUID.randomUUID(),0)).isInstanceOf(AccountFailure.class);
        assertThatThrownBy(() -> service.update(UUID.randomUUID(),0,"Avery")).isInstanceOf(AccountFailure.class);
    }
}
