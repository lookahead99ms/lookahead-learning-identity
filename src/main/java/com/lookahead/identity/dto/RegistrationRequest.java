package com.lookahead.identity.dto;

/** Password confirmation is validated and discarded; neither password is logged or returned. */
public record RegistrationRequest(String firstName, String lastName, String email,
                                  String password, String confirmPassword, String countryCode) {
    @Override public String toString() { return "RegistrationRequest[redacted]"; }
}
