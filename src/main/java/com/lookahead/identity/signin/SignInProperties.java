package com.lookahead.identity.signin;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("app.sign-ins")
public record SignInProperties(@DefaultValue("30m") Duration idleLifetime,
        @DefaultValue("7d") Duration absoluteLifetime,
        @DefaultValue("5m") Duration recentAuthenticationLifetime) {
    public SignInProperties {
        bounded(idleLifetime, Duration.ofMinutes(1), Duration.ofHours(24));
        bounded(absoluteLifetime, Duration.ofMinutes(5), Duration.ofDays(30));
        bounded(recentAuthenticationLifetime, Duration.ofSeconds(30), Duration.ofMinutes(15));
        if (idleLifetime.compareTo(absoluteLifetime) > 0) throw new IllegalArgumentException("Idle lifetime exceeds absolute lifetime");
    }
    private static void bounded(Duration value, Duration minimum, Duration maximum) {
        if(value == null || value.compareTo(minimum)<0 || value.compareTo(maximum)>0)
            throw new IllegalArgumentException("Sign-in lifetime outside supported range");
    }
    public static SignInProperties defaults() {
        return new SignInProperties(Duration.ofMinutes(30),Duration.ofDays(7),Duration.ofMinutes(5));
    }
}
