package com.lookahead.identity.controller;

import com.lookahead.identity.signin.*;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.service.AccountUserDetailsService;
import com.lookahead.identity.exception.AccountFailure;
import com.lookahead.learning.content.dto.ApiResponse;
import jakarta.servlet.http.*;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.time.Instant;

@RestController
@Profile("accounts")
public class SignInController {
    private final SignInRegistry registry;
    private final SignInSessionSupport sessions;
    private final AccountUserDetailsService users;
    public SignInController(SignInRegistry registry,SignInSessionSupport sessions,AccountUserDetailsService users) {
        this.registry=registry;this.sessions=sessions;this.users=users;
    }
    public record Entry(UUID signInId,boolean current,String label,String clientDescription,Instant createdAt,Instant lastActiveAt) {}
    public record Inventory(int limit,List<Entry> entries) {}
    public record Challenge(int limit,List<Entry> entries,Instant expiresAt) {}
    @GetMapping("/api/v1/account/sign-ins")
    public ApiResponse<Inventory> inventory(@AuthenticationPrincipal AccountPrincipal principal,HttpServletResponse response) {
        noStore(response);require(principal);return ApiResponse.success(new Inventory(2,entries(registry.list(principal.accountId(),principal.credentialEpoch(),principal.signInId()))));
    }
    @PostMapping("/api/v1/account/sign-ins/revoke")
    public ApiResponse<Map<String,Boolean>> revoke(@AuthenticationPrincipal AccountPrincipal principal,@RequestBody Map<String,Object> body,HttpServletRequest request,HttpServletResponse response) {
        noStore(response);require(principal);UUID target=target(body);
        registry.revoke(principal.accountId(),principal.credentialEpoch(),principal.signInId(),target);
        boolean current=target.equals(principal.signInId());if(current)SignInSessionSupport.clear(request);
        return ApiResponse.success(Map.of("reauthenticationRequired",current));
    }
    @PostMapping("/api/v1/account/sign-ins/revoke-others")
    public ApiResponse<Map<String,Boolean>> revokeOthers(@AuthenticationPrincipal AccountPrincipal principal,@RequestBody Map<String,Object> body,HttpServletResponse response) {
        noStore(response);require(principal);empty(body);registry.revokeOthers(principal.accountId(),principal.credentialEpoch(),principal.signInId());
        return ApiResponse.success(Map.of("reauthenticationRequired",false));
    }
    @PostMapping("/api/v1/account/sign-ins/label")
    public ApiResponse<Entry> label(@AuthenticationPrincipal AccountPrincipal principal,@RequestBody Map<String,Object> body,HttpServletResponse response) {
        noStore(response);require(principal);
        if(body==null||!body.keySet().equals(Set.of("label"))||!(body.get("label") instanceof String label))throw invalid();
        return ApiResponse.success(entry(registry.rename(principal.accountId(),principal.credentialEpoch(),principal.signInId(),principal.signInId(),label)));
    }
    @GetMapping("/api/v1/auth/sign-in-challenge")
    public ApiResponse<Challenge> challenge(HttpServletRequest request,HttpServletResponse response) {
        noStore(response);String token=challengeToken(request);
        return ApiResponse.success(new Challenge(2,entries(registry.challengeInventory(token)),registry.challengeExpiresAt(token)));
    }
    @PostMapping("/api/v1/auth/sign-in-challenge/replace")
    public ApiResponse<?> replace(@RequestBody Map<String,Object> body,HttpServletRequest request,HttpServletResponse response) {
        noStore(response);var admission=registry.replace(challengeToken(request),target(body));
        var principal=sessions.complete(admission,request,response);return ApiResponse.success(users.accountView(principal));
    }
    @PostMapping("/api/v1/auth/sign-in-challenge/cancel")
    public ApiResponse<Map<String,Boolean>> cancel(@RequestBody Map<String,Object> body,HttpServletRequest request,HttpServletResponse response) {
        noStore(response);empty(body);challengeToken(request);sessions.cancel(request,response);return ApiResponse.success(Map.of("cancelled",true));
    }
    private String challengeToken(HttpServletRequest request) {
        String token=sessions.challenge(request);
        var authentication=org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if(authentication!=null && authentication.getPrincipal() instanceof AccountPrincipal principal
                && !registry.challengeAccount(token).equals(principal.accountId()))
            throw new AccountFailure(400,"SIGN_IN_CHALLENGE_INVALID","Sign in again.");
        return token;
    }
    private static Entry entry(SignInRegistry.SignIn value) {return new Entry(value.id(),value.current(),value.label(),value.clientDescription(),value.createdAt(),value.lastActiveAt());}
    private static List<Entry> entries(List<SignInRegistry.SignIn> values){return values.stream().map(SignInController::entry).toList();}
    private static void require(AccountPrincipal principal){if(principal==null||principal.signInId()==null)throw new AccountFailure(401,"AUTHENTICATION_REQUIRED","Sign in again.");}
    private static UUID target(Map<String,Object> body){try{if(body==null||!body.keySet().equals(Set.of("signInId"))||!(body.get("signInId") instanceof String value))throw invalid();UUID id=UUID.fromString(value);if(!id.toString().equals(value))throw invalid();return id;}catch(IllegalArgumentException error){throw invalid();}}
    private static void empty(Map<String,Object> body){if(body==null||!body.isEmpty())throw invalid();}
    private static AccountFailure invalid(){return new AccountFailure(400,"INVALID_SIGN_IN_REQUEST","The sign-in request is invalid.");}
    private static void noStore(HttpServletResponse response){response.setHeader("Cache-Control","no-store");}
}
