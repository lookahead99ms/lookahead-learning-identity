package com.lookahead.identity.verification;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
class AccountDirectoryTest {
 @Test void paginatesAndNormalizesWithoutWildcardExpansion() {
  var jdbc=mock(JdbcTemplate.class);var rows=new ArrayList<AccountDirectoryController.Account>();
  for(int i=0;i<51;i++)rows.add(new AccountDirectoryController.Account(UUID.randomUUID(),"u"+i,"User",null));
  when(jdbc.query(anyString(),any(RowMapper.class),eq("a_%"),eq("a_%"),eq("a_%"),eq("a_%"),eq(50))).thenReturn(rows);
  var response=new AccountDirectoryController(jdbc).list(" A_% ",1);
  var page=(AccountDirectoryController.Page)response.getBody();
  assertThat(page.accounts()).hasSize(50);assertThat(page.hasNext()).isTrue();assertThat(page.page()).isEqualTo(1);
  assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
 }
 @Test void validatesBeforeQueryAndReturnsEmptyTerminalPage() {
  var jdbc=mock(JdbcTemplate.class);var controller=new AccountDirectoryController(jdbc);
  for(String query:List.of("x".repeat(255),"a\nb"))assertThat(controller.list(query,0).getStatusCode().value()).isEqualTo(422);
  for(int page:List.of(-1,100001))assertThat(controller.list("",page).getStatusCode().value()).isEqualTo(422);
  verifyNoInteractions(jdbc);
  assertThat(((AccountDirectoryController.Page)controller.list("",0).getBody()).hasNext()).isFalse();
 }
 @Test void byIdReturnsOnlyAnEnabledExactAccount() {
  var jdbc=mock(JdbcTemplate.class);var controller=new AccountDirectoryController(jdbc);UUID id=UUID.randomUUID();
  assertThat(controller.byId(id).getStatusCode().value()).isEqualTo(404);
  var account=new AccountDirectoryController.Account(id,"real-user","Real User",null);
  when(jdbc.query(anyString(),any(RowMapper.class),eq(id))).thenReturn(List.of(account));
  assertThat(controller.byId(id).getBody()).isEqualTo(account);
  assertThat(controller.byId(id).getHeaders().getCacheControl()).isEqualTo("no-store");
 }
}
