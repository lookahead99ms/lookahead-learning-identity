package com.lookahead.learning.content.dto;

public record CsrfView(String token, String headerName, String parameterName) {}
