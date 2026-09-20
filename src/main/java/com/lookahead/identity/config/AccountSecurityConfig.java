package com.lookahead.identity.config;

import com.lookahead.identity.service.AccountUserDetailsService;
import com.lookahead.identity.validator.LocalTestSeedGuard;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;


@Configuration
@Profile("accounts")
@org.springframework.boot.context.properties.EnableConfigurationProperties(AccountSecurityProperties.class)
@org.springframework.context.annotation.Import(AccountSecurityHandlers.class)
public class AccountSecurityConfig {
    @Bean
    PasswordEncoder accountPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @org.springframework.core.annotation.Order(3)
    SecurityFilterChain accountSecurity(HttpSecurity http, AccountUserDetailsService users,
                                        PasswordEncoder encoder, AccountSecurityHandlers handlers, AccountSecurityProperties properties, Environment environment,
                                        LocalTestSeedGuard localTestGuard, com.lookahead.identity.repository.AccountRepository accounts, com.lookahead.identity.signin.SignInRegistry signIns) throws Exception {
        boolean localPasswordLogin = environment.acceptsProfiles(Profiles.of("local-test"))
                && "local".equals(environment.getProperty("app.deployment-environment"))
                && !environment.acceptsProfiles(Profiles.of("prod", "production"));
        boolean registrationEnabled = properties.registrationEnabled();
        boolean passwordLogin = localPasswordLogin || registrationEnabled;
        http.addFilterAfter(new com.lookahead.identity.filter.CredentialEpochFilter(accounts,signIns), org.springframework.security.web.context.SecurityContextHolderFilter.class);
        http.cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()))
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
                .requestCache(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionFixation(fixation -> fixation.changeSessionId()))
                .authorizeHttpRequests(auth -> {
                    if (passwordLogin) auth.requestMatchers("/api/v1/auth/login").permitAll();
                    else auth.requestMatchers("/api/v1/auth/login").denyAll();
                    if (registrationEnabled) auth.requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll();
                    else auth.requestMatchers("/api/v1/auth/register").denyAll();
                    auth.requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf", "/api/v1/status",
                                "/api/v1/auth/options",
                                "/actuator/health", "/actuator/health/**", "/actuator/info",
                                "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.GET,"/api/v1/auth/sign-in-challenge").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.POST,"/api/v1/auth/sign-in-challenge/replace","/api/v1/auth/sign-in-challenge/cancel").permitAll()
                        .requestMatchers("/api/v1/auth/logout").permitAll()
                        .requestMatchers("/api/v1/account/sign-ins","/api/v1/account/sign-ins/revoke","/api/v1/account/sign-ins/revoke-others","/api/v1/account/sign-ins/label").authenticated()
                        .requestMatchers("/api/v1/auth/continue", "/api/v1/auth/me", "/api/v1/account/profile", "/api/v1/account/password").authenticated()
                        .anyRequest().denyAll();
                })
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(handlers::authenticationRequired)
                        .accessDeniedHandler(handlers::accessDenied))
                .logout(logout -> logout.logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler((request,response,authentication)->{
                            if(authentication!=null && authentication.getPrincipal() instanceof com.lookahead.identity.security.AccountPrincipal principal && principal.signInId()!=null)
                                signIns.terminate(principal.accountId(),principal.credentialEpoch(),principal.signInId());
                        })
                        .invalidateHttpSession(true).clearAuthentication(true)
                        .deleteCookies(environment.getProperty("server.servlet.session.cookie.name", "JSESSIONID"))
                        .logoutSuccessHandler((request, response, authentication) -> response.setStatus(204)));
        if (passwordLogin) {
            var provider = new DaoAuthenticationProvider(users);
            provider.setPasswordEncoder(encoder);
            http.authenticationProvider(provider)
                    .formLogin(login -> login.loginProcessingUrl("/api/v1/auth/login")
                            .successHandler(handlers::loginSucceeded)
                            .failureHandler(handlers::loginFailed));
        } else {
            // Identity is disabled unless registration or the guarded local fixture login is enabled.
            http.formLogin(AbstractHttpConfigurer::disable);
        }
        return http.build();
    }

}
