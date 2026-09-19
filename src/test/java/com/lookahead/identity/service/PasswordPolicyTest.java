package com.lookahead.identity.service;
import com.lookahead.identity.dto.PasswordChangeRequest;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class PasswordPolicyTest {
    @Test void countsUnicodeCodePointsAndNeverTrims() {
        for(String value : new String[]{"a".repeat(15), "😀".repeat(15), "😀".repeat(128), " ".repeat(15)})
            assertThatCode(()->PasswordChangeService.validate(new PasswordChangeRequest("legacy123456",value,value))).doesNotThrowAnyException();
        for(String value : new String[]{"a".repeat(14),"😀".repeat(14),"a".repeat(129),"😀".repeat(129)})
            assertThatThrownBy(()->PasswordChangeService.validate(new PasswordChangeRequest("legacy123456",value,value))).hasMessageContaining("15 to 128");
    }
    @Test void rejectsBoundedCommonListAndMalformedUnicode() {
        assertThatThrownBy(()->PasswordChangeService.validate(new PasswordChangeRequest("legacy123456","password123456789","password123456789"))).hasMessageContaining("less common");
        String malformed="x".repeat(15)+"\uD800";
        assertThatThrownBy(()->PasswordChangeService.validate(new PasswordChangeRequest("legacy123456",malformed,malformed))).hasMessageContaining("15 to 128");
    }
    @Test void requiresConfirmationAndRedactsCredentials() {
        var request=new PasswordChangeRequest("sensitive-current", "sensitive-new-value", "different");
        assertThatThrownBy(()->PasswordChangeService.validate(request)).hasMessageContaining("match");
        assertThat(request.toString()).doesNotContain("sensitive");
    }
}
