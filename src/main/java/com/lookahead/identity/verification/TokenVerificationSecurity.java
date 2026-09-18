package com.lookahead.identity.verification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class TokenVerificationSecurity {
    public static final String USERNAME = "lookahead-platform-verifier";
    private final byte[] expectedSecret;
    public TokenVerificationSecurity(@Value("${app.identity.verifier-secret}") String secret,
            @Value("${app.oauth.client-secret}") String gatewaySecret) {
        if (secret == null || secret.isBlank() || secret.length() < 32)
            throw new IllegalStateException("Identity verifier requires a separate secret of at least 32 characters");
        if (secret.equals(gatewaySecret))
            throw new IllegalStateException("Identity verifier must not reuse the Gateway client secret");
        expectedSecret = secret.getBytes(StandardCharsets.UTF_8);
    }

    @Bean @Order(0)
    SecurityFilterChain tokenVerificationFilterChain(HttpSecurity http) throws Exception {
        AuthenticationProvider provider = new AuthenticationProvider() {
            @Override public Authentication authenticate(Authentication request) {
                byte[] actual = String.valueOf(request.getCredentials()).getBytes(StandardCharsets.UTF_8);
                boolean matches = MessageDigest.isEqual(expectedSecret, actual);
                if (!USERNAME.equals(request.getName()) || !matches) throw new BadCredentialsException("Invalid verifier credentials");
                return UsernamePasswordAuthenticationToken.authenticated(USERNAME, null,
                        List.of(new SimpleGrantedAuthority("ROLE_TOKEN_VERIFIER")));
            }
            @Override public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
            }
        };
        http.securityMatcher("/internal/v1/tokens/verify")
                .authenticationManager(new ProviderManager(provider))
                .csrf(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(access -> access
                        .requestMatchers(HttpMethod.POST, "/internal/v1/tokens/verify").hasRole("TOKEN_VERIFIER")
                        .anyRequest().denyAll())
                .httpBasic(basic -> basic.authenticationEntryPoint((request, response, error) -> {
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.setHeader("Cache-Control", "no-store");
                    response.setHeader("WWW-Authenticate", "Basic realm=\"identity-verifier\"");
                    response.getWriter().write("{\"code\":\"VERIFIER_AUTHENTICATION_REQUIRED\"}");
                }));
        return http.build();
    }
}
