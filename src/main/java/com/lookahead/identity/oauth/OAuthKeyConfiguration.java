package com.lookahead.identity.oauth;

import com.lookahead.identity.security.AccountPrincipal;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Configuration
@Profile("oauth-server")
public class OAuthKeyConfiguration {
    @Bean JWKSource<SecurityContext> signingKeys(OAuthProperties properties) throws Exception {
        byte[] privateBytes=pem(requiredKey(properties.signingPrivateKey(), "app.oauth.signing-private-key"),"PRIVATE KEY");
        byte[] publicBytes=pem(requiredKey(properties.signingPublicKey(), "app.oauth.signing-public-key"),"PUBLIC KEY");
        var factory=KeyFactory.getInstance("RSA");
        var privateKey=(RSAPrivateKey)factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        var publicKey=(RSAPublicKey)factory.generatePublic(new X509EncodedKeySpec(publicBytes));
        if(publicKey.getModulus().bitLength()<3072 || !publicKey.getModulus().equals(privateKey.getModulus()))
            throw new IllegalStateException("OAuth requires matching RSA signing keys of at least 3072 bits");
        var kid=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicBytes)).substring(0,24);
        var key=new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).build();
        var keys=new JWKSet(key);
        return (selector,context)->selector.select(keys);
    }
    private static byte[] pem(Path path,String kind) throws Exception {
        String value=Files.readString(path).replace("-----BEGIN "+kind+"-----","").replace("-----END "+kind+"-----","").replaceAll("\\s","");
        return Base64.getDecoder().decode(value);
    }
    @Bean JwtDecoder authorizationJwtDecoder(JWKSource<SecurityContext> keys, OAuthSettings settings) throws Exception {
        var publicKey=keys.get(new JWKSelector(new JWKMatcher.Builder().keyType(KeyType.RSA).build()),null).getFirst().toRSAKey().toRSAPublicKey();
        var decoder=NimbusJwtDecoder.withPublicKey(publicKey).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(settings.issuer()));
        return decoder;
    }
    @Bean OAuth2TokenCustomizer<JwtEncodingContext> accountTokenClaims(OAuthSettings settings) {
        return context->{
            String id=context.getPrincipal().getPrincipal() instanceof AccountPrincipal principal ? principal.accountId().toString() : context.getAuthorization().getPrincipalName();
            context.getClaims().subject(id);
            if("id_token".equals(context.getTokenType().getValue()) && context.getAuthorization()!=null) {
                String sessionHash=context.getAuthorization().getAttribute("lookahead.identity-session-hash");
                if(sessionHash!=null)context.getClaims().claim("sid",sessionHash);
            }
            if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                // JDBC's strict security mapper supports ArrayList, not JDK List.of implementation types.
                context.getClaims().audience(new ArrayList<>(List.of("lookahead-api")));
                context.getClaims().claim("client_id",context.getRegisteredClient().getClientId());
            }
        };
    }
    private static Path requiredKey(Path path, String property) {
        if (path == null) throw new IllegalStateException(property + " is required");
        return path;
    }
}
