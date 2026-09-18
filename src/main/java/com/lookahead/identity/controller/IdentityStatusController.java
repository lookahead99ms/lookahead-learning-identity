package com.lookahead.identity.controller;

import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.dto.ApplicationStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IdentityStatusController {
    private final String version;
    public IdentityStatusController(@Value("${app.version}") String version) { this.version = version; }
    @GetMapping("/api/v1/status")
    public ApiResponse<ApplicationStatus> status() {
        return ApiResponse.success(new ApplicationStatus("lookahead-identity", "UP", version));
    }
}
