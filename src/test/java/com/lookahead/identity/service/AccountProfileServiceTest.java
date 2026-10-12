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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
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
        var jdbc=mock(JdbcTemplate.class);var service=new AccountProfileService(jdbc,new RecordingTransactions());
        assertThatThrownBy(() -> service.read(UUID.randomUUID(),0)).isInstanceOf(AccountFailure.class);
        assertThatThrownBy(() -> service.update(UUID.randomUUID(),0,"Avery")).isInstanceOf(AccountFailure.class);
        assertThatThrownBy(() -> service.updateTheme(UUID.randomUUID(),0,"dark")).isInstanceOf(AccountFailure.class);
        assertThatThrownBy(() -> service.updateLinks(UUID.randomUUID(),0,links(null,null,null,null))).isInstanceOf(AccountFailure.class);
        verify(jdbc,never()).update(anyString(),any(Object[].class));
    }
    @Test void profileViewDefaultsThemeAndAlwaysCarriesEveryLinkKey() {
        var view=new AccountProfileView(UUID.randomUUID(),"learner@example.test","Learner");
        assertThat(view.themePreference()).isEqualTo("system");
        assertThat(view.links()).isEqualTo(new AccountProfileView.ProfileLinks(null,null,null,null));
        assertThat(new AccountProfileView(view.accountId(),"u","n",null,null)).isEqualTo(new AccountProfileView(view.accountId(),"u","n"));
    }

    static Map<String,String> links(String github,String linkedin,String x,String website) {
        var links=new HashMap<String,String>();links.put("github",github);links.put("linkedin",linkedin);links.put("x",x);links.put("website",website);return links;
    }
    static Map<String,Object> body(Object... pairs) {
        var body=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)body.put((String)pairs[i],pairs[i+1]);return body;
    }
    static AccountPrincipal principal(UUID owner) {return new AccountPrincipal(owner,"learner@example.test","Old",null,true,3);}

    @Test void themeAcceptsOnlyTheExactBodyAndDelegatesWithSessionOwnerAndEpoch() {
        var service=mock(AccountProfileService.class);var controller=new AccountProfileController(service);
        UUID owner=UUID.randomUUID();
        var authoritative=new AccountProfileView(owner,"learner@example.test","Learner","dark",AccountProfileView.ProfileLinks.EMPTY);
        when(service.updateTheme(owner,3,"dark")).thenReturn(authoritative);
        var response=new MockHttpServletResponse();
        assertThat(controller.preferences(principal(owner),body("theme","dark"),response).data()).isEqualTo(authoritative);
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        verify(service).updateTheme(owner,3,"dark");
        for(Object invalid:new Object[]{null,"dark",List.of("dark"),body(),body("theme","Dark"),body("theme","sepia"),body("theme",""),
                body("theme",null),body("theme",1),body("theme",List.of("dark")),body("theme","dark","accountId",owner.toString()),body("Theme","dark")}) {
            assertThatThrownBy(() -> controller.preferences(principal(owner),invalid,new MockHttpServletResponse()))
                    .isInstanceOfSatisfying(AccountFailure.class,f->{assertThat(f.status()).isEqualTo(422);assertThat(f.code()).isEqualTo("INVALID_PREFERENCES");
                        assertThat(f.getMessage()).isEqualTo("Choose light, dark or system.");});
        }
        verifyNoMoreInteractions(service);
    }
    @Test void linksRequireExactlyTheFourKeysWithStringOrNullValues() {
        var service=mock(AccountProfileService.class);var controller=new AccountProfileController(service);
        UUID owner=UUID.randomUUID();var response=new MockHttpServletResponse();
        var accepted=body("github","https://github.com/avery","linkedin",null,"x","","website","https://avery.example.dev");
        var expected=new HashMap<String,String>();expected.put("github","https://github.com/avery");expected.put("linkedin",null);expected.put("x","");expected.put("website","https://avery.example.dev");
        var authoritative=new AccountProfileView(owner,"learner@example.test","Learner");
        when(service.updateLinks(owner,3,expected)).thenReturn(authoritative);
        assertThat(controller.links(principal(owner),accepted,response).data()).isEqualTo(authoritative);
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        for(Object invalid:new Object[]{null,"x",List.of(),body(),body("github",null,"linkedin",null,"x",null),
                body("github",null,"linkedin",null,"x",null,"website",null,"mastodon",null),
                body("github",null,"linkedin",null,"twitter",null,"website",null),
                body("github",1,"linkedin",null,"x",null,"website",null),
                body("github",null,"linkedin",List.of("https://linkedin.com/in/a"),"x",null,"website",null),
                body("github",null,"linkedin",null,"x",Map.of("url","https://x.com/a"),"website",null),
                body("github",null,"linkedin",null,"x",null,"website",true)}) {
            assertThatThrownBy(() -> controller.links(principal(owner),invalid,new MockHttpServletResponse()))
                    .isInstanceOfSatisfying(AccountFailure.class,f->{assertThat(f.code()).isEqualTo("INVALID_PROFILE_LINK");
                        assertThat(f.getMessage()).isEqualTo("Provide the github, linkedin, x and website fields.");});
        }
        verify(service).updateLinks(owner,3,expected);verifyNoMoreInteractions(service);
    }
    @Test void anonymousCannotChangePreferencesOrLinks() {
        var service=mock(AccountProfileService.class);var controller=new AccountProfileController(service);
        assertThatThrownBy(() -> controller.preferences(null,body("theme","dark"),new MockHttpServletResponse()))
                .isInstanceOfSatisfying(AccountFailure.class,f->assertThat(f.code()).isEqualTo("AUTHENTICATION_REQUIRED"));
        assertThatThrownBy(() -> controller.links(null,body("github",null,"linkedin",null,"x",null,"website",null),new MockHttpServletResponse()))
                .isInstanceOfSatisfying(AccountFailure.class,f->assertThat(f.code()).isEqualTo("AUTHENTICATION_REQUIRED"));
        verifyNoInteractions(service);
    }
    @Test void serviceValidatesBeforeTouchingStorage() {
        var jdbc=mock(JdbcTemplate.class);var manager=new RecordingTransactions();var service=new AccountProfileService(jdbc,manager);
        UUID owner=UUID.randomUUID();
        for(String theme:new String[]{null,"","Dark","sepia"})
            assertThatThrownBy(() -> service.updateTheme(owner,0,theme)).isInstanceOfSatisfying(AccountFailure.class,f->assertThat(f.code()).isEqualTo("INVALID_PREFERENCES"));
        assertThatThrownBy(() -> service.updateLinks(owner,0,null)).hasMessage("Provide the github, linkedin, x and website fields.");
        assertThatThrownBy(() -> service.updateLinks(owner,0,Map.of("github","https://github.com/a"))).hasMessage("Provide the github, linkedin, x and website fields.");
        assertThatThrownBy(() -> service.updateLinks(owner,0,links("https://github.com/a",null,"https://evil.test/a",null))).hasMessage("Use an https://x.com/… address for X.");
        verifyNoInteractions(jdbc);assertThat(manager.events).isEmpty();
    }
    @SuppressWarnings("unchecked")
    @Test void linksReplaceAllRowsInsideOneLockedTransaction() {
        var jdbc=mock(JdbcTemplate.class);var manager=new RecordingTransactions();var service=new AccountProfileService(jdbc,manager);
        UUID owner=UUID.randomUUID();
        var view=new AccountProfileView(owner,"learner@example.test","Learner");
        when(jdbc.query(contains("FOR UPDATE"),any(RowMapper.class),eq(owner))).thenReturn(List.of(true));
        when(jdbc.query(contains("account_profile_links"),any(RowMapper.class),eq(owner),eq(0L))).thenReturn(List.of(view));
        assertThat(service.updateLinks(owner,0,links(" https://github.com/a ","",null,"https://a.example"))).isSameAs(view);
        var order=inOrder(jdbc);
        order.verify(jdbc).query(contains("FOR UPDATE"),any(RowMapper.class),eq(owner));
        order.verify(jdbc).update("DELETE FROM account_profile_links WHERE account_id=?",owner);
        order.verify(jdbc).update(contains("INSERT INTO account_profile_links"),eq(owner),eq("github"),eq("https://github.com/a"));
        order.verify(jdbc).update(contains("INSERT INTO account_profile_links"),eq(owner),eq("website"),eq("https://a.example"));
        assertThat(manager.events).containsExactly("begin","commit");
        verify(jdbc,times(3)).update(anyString(),any(Object[].class));
        assertThat(service.updateTheme(owner,0,"light")).isSameAs(view);
        verify(jdbc).update(contains("ON CONFLICT (account_id) DO UPDATE"),eq(owner),eq("light"));
    }
    @SuppressWarnings("unchecked")
    @Test void staleEpochRollsBackWithoutWriting() {
        var jdbc=mock(JdbcTemplate.class);var manager=new RecordingTransactions();var service=new AccountProfileService(jdbc,manager);
        UUID owner=UUID.randomUUID();
        when(jdbc.query(contains("FOR UPDATE"),any(RowMapper.class),eq(owner))).thenReturn(List.of(false));
        assertThatThrownBy(() -> service.updateTheme(owner,0,"dark")).isInstanceOfSatisfying(AccountFailure.class,f->assertThat(f.status()).isEqualTo(401));
        verify(jdbc,never()).update(anyString(),any(Object[].class));
        assertThat(manager.events).containsExactly("begin","rollback");
    }
    /** A plain fake: Mockito interface mocks can clash with the inline mock maker used by Spring tests. */
    static final class RecordingTransactions implements PlatformTransactionManager {
        final List<String> events=new ArrayList<>();
        @Override public TransactionStatus getTransaction(TransactionDefinition definition) {events.add("begin");return new SimpleTransactionStatus();}
        @Override public void commit(TransactionStatus status) {events.add("commit");}
        @Override public void rollback(TransactionStatus status) {events.add("rollback");}
    }
}
