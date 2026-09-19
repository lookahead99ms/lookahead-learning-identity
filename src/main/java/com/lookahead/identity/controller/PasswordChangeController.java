package com.lookahead.identity.controller;

import com.lookahead.identity.dto.PasswordChangeRequest;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.PasswordChangeService;
import com.lookahead.learning.content.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@Profile("accounts")
public class PasswordChangeController {
    private final PasswordChangeService passwords;
    public PasswordChangeController(PasswordChangeService passwords) {this.passwords=passwords;}
    @PostMapping("/api/v1/account/password")
    ResponseEntity<?> change(@AuthenticationPrincipal AccountPrincipal principal,@RequestBody Map<String,Object> body,HttpServletRequest servlet) {
        if(principal==null) throw new com.lookahead.identity.exception.AccountFailure(401,"AUTHENTICATION_REQUIRED","Sign in to continue");
        if(body==null || !body.keySet().equals(java.util.Set.of("currentPassword","newPassword","confirmPassword"))
                || !(body.get("currentPassword") instanceof String) || !(body.get("newPassword") instanceof String) || !(body.get("confirmPassword") instanceof String))
            throw new com.lookahead.identity.exception.AccountFailure(422,"INVALID_PASSWORD","Provide only currentPassword, newPassword and confirmPassword");
        var request=new PasswordChangeRequest((String)body.get("currentPassword"),(String)body.get("newPassword"),(String)body.get("confirmPassword"));
        passwords.change(principal,request);
        SecurityContextHolder.clearContext();
        var session=servlet.getSession(false); if(session!=null) session.invalidate();
        return ResponseEntity.ok().header("Cache-Control","no-store").body(ApiResponse.success(Map.of("reauthenticationRequired",true)));
    }
}
