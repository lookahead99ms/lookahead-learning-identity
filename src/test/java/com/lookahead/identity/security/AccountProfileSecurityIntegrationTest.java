package com.lookahead.identity.security;

import com.lookahead.identity.controller.AccountProfileController;
import com.lookahead.identity.dto.AccountProfileView;
import com.lookahead.identity.service.AccountProfileService;
import java.net.*;
import java.net.http.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.*;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.ObjectMapper;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

@SpringBootTest(classes=AccountProfileSecurityIntegrationTest.App.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,
 properties={"spring.config.name=security-test","app.accounts.registration-enabled=true","app.deployment-environment=local"})
@ActiveProfiles("accounts")
class AccountProfileSecurityIntegrationTest {
 @Configuration @Import({RegistrationSecurityIntegrationTest.App.class,AccountProfileController.class})
 static class App {
  @Bean AccountProfileService profiles() { return mock(AccountProfileService.class); }
 }
 @LocalServerPort int port;
 @Autowired ObjectMapper mapper;
 @Autowired AccountProfileService profiles;
 HttpClient browser() { return HttpClient.newBuilder().cookieHandler(new CookieManager(null,CookiePolicy.ACCEPT_ALL)).build(); }
 HttpResponse<String> request(HttpClient client,String method,String path,String body,String csrf,String type) throws Exception {
  var req=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path));
  if(csrf!=null)req.header("X-CSRF-TOKEN",csrf);
  if(type!=null)req.header("Content-Type",type);
  return client.send(req.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
 }
 String csrf(HttpClient client) throws Exception {return mapper.readTree(request(client,"GET","/api/v1/auth/csrf",null,null,null).body()).path("data").path("token").asText();}
 @Test void realSessionEnforcesCsrfAllowlistAndStorageFailureWithoutReturningSecrets() throws Exception {
  reset(profiles);
  var first=browser();var second=browser();String path="/api/v1/account/profile";
  assertThat(request(first,"GET",path,null,null,null).statusCode()).isEqualTo(401);
  assertThat(request(first,"POST","/api/v1/auth/login","username=avery%40example.test&password=long+test+passphrase",csrf(first),"application/x-www-form-urlencoded").statusCode()).isEqualTo(200);
  when(profiles.read(any(),anyLong())).thenAnswer(c->new AccountProfileView(c.getArgument(0),"avery@example.test","Fresh"));
  when(profiles.update(any(),anyLong(),eq("New"))).thenAnswer(c->new AccountProfileView(c.getArgument(0),"avery@example.test","New"));
  assertThat(request(first,"GET",path,null,null,null).body()).contains("Fresh");
  assertThat(request(first,"POST",path,"{\"displayName\":\"New\"}",null,"application/json").statusCode()).isEqualTo(403);
  assertThat(request(first,"POST",path,"{\"displayName\":\"New\"}",csrf(second),"application/json").statusCode()).isEqualTo(403);
  String token=csrf(first);
  assertThat(request(first,"POST",path,"{\"displayName\":\"New\",\"accountId\":\"another\"}",token,"application/json").statusCode()).isEqualTo(422);
  var updated=request(first,"POST",path,"{\"displayName\":\"New\"}",token,"application/json");
  assertThat(updated.statusCode()).isEqualTo(200);assertThat(updated.body()).contains("New");
  assertThat(updated.headers().firstValue("cache-control")).contains("no-store");
  assertThat(request(second,"GET",path,null,null,null).statusCode()).isEqualTo(401);
  when(profiles.update(any(),anyLong(),eq("New"))).thenThrow(new DataAccessResourceFailureException("private database detail"));
  var failed=request(first,"POST",path,"{\"displayName\":\"New\"}",token,"application/json");
  assertThat(failed.statusCode()).isEqualTo(503);assertThat(failed.body()).contains("ACCOUNT_STORAGE_UNAVAILABLE").doesNotContain("private database detail");
 }
}
