package com.lookahead.identity.signin;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.assertj.core.api.Assertions.*;
class SignInPropertiesTest {
    @Test void defaultsAreBounded(){assertThat(SignInProperties.defaults().idleLifetime()).isEqualTo(Duration.ofMinutes(30));}
    @Test void rejectsUnboundedAndInvertedLifetimes(){
        assertThatThrownBy(()->new SignInProperties(Duration.ZERO,Duration.ofDays(7),Duration.ofMinutes(5))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new SignInProperties(Duration.ofHours(1),Duration.ofMinutes(5),Duration.ofMinutes(5))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new SignInProperties(Duration.ofMinutes(30),Duration.ofDays(40),Duration.ofMinutes(5))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new SignInProperties(Duration.ofMinutes(30),Duration.ofDays(7),Duration.ofHours(1))).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void challengeHashIsFixedWidthAndRejectsOversize(){assertThat(SignInRegistry.digest("synthetic-proof")).hasSize(64);assertThatThrownBy(()->SignInRegistry.digest("a".repeat(513))).isInstanceOf(com.lookahead.identity.exception.AccountFailure.class);}
}
