package com.lookahead.identity.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

@Configuration
@Profile("oauth-server")
public class OAuthServerConfiguration {
    @Bean AuthorizationServerSettings authorizationServerSettings(OAuthSettings settings) {
        return AuthorizationServerSettings.builder().issuer(settings.issuer()).build();
    }
    @Bean @Order(1) SecurityFilterChain oauthAuthorizationSecurity(HttpSecurity http, OAuthSettings settings, com.lookahead.identity.repository.AccountRepository accounts) throws Exception {
        http.addFilterAfter(new com.lookahead.identity.filter.CredentialEpochFilter(accounts), org.springframework.security.web.context.SecurityContextHolderFilter.class);
        var server=new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(server.getEndpointsMatcher())
                .with(server,configurer->configurer.oidc(oidc->oidc.logoutEndpoint(logout->logout
                        .errorResponseHandler((request,response,error)->{
                            var oauthError=((OAuth2AuthenticationException)error).getError();
                            org.slf4j.LoggerFactory.getLogger(OAuthServerConfiguration.class).warn("OIDC logout rejected: {}",oauthError.getErrorCode());
                            response.setStatus(400);response.setContentType("application/json");response.setHeader("Cache-Control","no-store");
                            response.getWriter().write("{\"code\":\"LOGOUT_REJECTED\",\"message\":\"Sign out could not be completed. Return to the account page and retry.\"}");
                        }))))
                .authorizeHttpRequests(auth->auth.anyRequest().authenticated())
                .requestCache(cache->cache.requestCache(new HttpSessionRequestCache()))
                .exceptionHandling(errors->errors.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(settings.frontend()+"/sign-in?oauth=continue")));
        return http.build();
    }
}
