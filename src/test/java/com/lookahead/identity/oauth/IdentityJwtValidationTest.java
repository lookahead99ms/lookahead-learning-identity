package com.lookahead.identity.oauth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import static org.assertj.core.api.Assertions.*;

class IdentityJwtValidationTest {
    @Test void actualDecoderRejectsExpiredWrongIssuerAndWrongSignatureTokens() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(3072);
        var signingPair = generator.generateKeyPair();
        var key = new RSAKey.Builder((RSAPublicKey) signingPair.getPublic())
                .privateKey((RSAPrivateKey) signingPair.getPrivate()).keyID("identity-key").build();
        JWKSource<SecurityContext> source = (selector, context) -> selector.select(new JWKSet(key));
        var settings = new OAuthSettings("https://example.test", "lookahead-web-gateway",
                "synthetic-client-secret-at-least-32", "http://identity:8080", "https://example.test");
        var decoder = new OAuthKeyConfiguration().authorizationJwtDecoder(source, settings);
        var encoder = new NimbusJwtEncoder(source);
        for (String[] values : List.of(new String[]{settings.issuer(), "-120"}, new String[]{"https://other.example", "300"})) {
            var claims = JwtClaimsSet.builder().issuer(values[0]).subject(UUID.randomUUID().toString())
                    .issuedAt(Instant.now().minusSeconds(600)).expiresAt(Instant.now().plusSeconds(Integer.parseInt(values[1]))).build();
            String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        }
        var otherPair = generator.generateKeyPair();
        var otherKey = new RSAKey.Builder((RSAPublicKey) otherPair.getPublic())
                .privateKey((RSAPrivateKey) otherPair.getPrivate()).keyID("identity-key").build();
        JWKSource<SecurityContext> otherSource = (selector, context) -> selector.select(new JWKSet(otherKey));
        var validClaims = JwtClaimsSet.builder().issuer(settings.issuer()).subject(UUID.randomUUID().toString())
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
        String forged = new NimbusJwtEncoder(otherSource).encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(), validClaims)).getTokenValue();
        assertThatThrownBy(() -> decoder.decode(forged)).isInstanceOf(JwtException.class);
        String valid = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), validClaims)).getTokenValue();
        assertThat(decoder.decode(valid).getIssuer().toString()).isEqualTo(settings.issuer());
    }
}
