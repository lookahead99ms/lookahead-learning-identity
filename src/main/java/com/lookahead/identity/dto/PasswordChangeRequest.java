package com.lookahead.identity.dto;

public record PasswordChangeRequest(String currentPassword, String newPassword, String confirmPassword) {
    @Override public String toString() { return "PasswordChangeRequest[redacted]"; }
}
