package com.lookahead.identity.signin;

import com.lookahead.identity.repository.AccountRepository;
import com.lookahead.identity.security.AccountPrincipal;
import com.lookahead.identity.exception.AccountFailure;
import jakarta.servlet.http.*;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.csrf.*;
import java.security.SecureRandom;
import java.util.*;

/** Durable browser association is usable only after fresh credential proof, never as authentication. */
@Component
@Profile("accounts")
public class SignInSessionSupport {
    private final SignInRegistry registry;
    private final AccountRepository accounts;
    private final String bindingName;
    private final String challengeName;
    private final boolean secure;
    public SignInSessionSupport(SignInRegistry registry, AccountRepository accounts, Environment environment) {
        this.registry=registry;this.accounts=accounts;
        bindingName=environment.getProperty("app.sign-ins.binding-cookie-name","LOOKAHEAD_SIGNIN_BINDING");
        challengeName=environment.getProperty("app.sign-ins.challenge-cookie-name","LOOKAHEAD_SIGNIN_CHALLENGE");
        String sessionName=environment.getProperty("server.servlet.session.cookie.name","LOOKAHEAD_SESSION");
        if(!bindingName.matches("[A-Z][A-Z0-9_]{2,63}")||!challengeName.matches("[A-Z][A-Z0-9_]{2,63}")
                ||Set.of(bindingName,challengeName,sessionName).size()!=3)throw new IllegalStateException("Distinct sign-in cookie names required");
        secure=environment.getProperty("server.servlet.session.cookie.secure",Boolean.class,true);
    }
    public SignInRegistry.Admission admit(AccountPrincipal principal,HttpServletRequest request,HttpServletResponse response) {
        String binding=cookie(request,bindingName);
        if(binding==null || !binding.matches("[A-Za-z0-9_-]{43}")) {
            byte[] random=new byte[32];new SecureRandom().nextBytes(random);binding=Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        }
        var admission=registry.admit(principal.accountId(),principal.credentialEpoch(),SignInRegistry.digest(binding),client(request.getHeader("User-Agent")));
        setCookie(response,bindingName,binding,30L*24*60*60);
        if(admission.signInId()==null) {
            clear(request);
            setCookie(response,challengeName,admission.challengeToken(),300);
        } else {
            install(principal.withSignIn(admission.signInId()),request,response);
            setCookie(response,challengeName,"",0);
        }
        return admission;
    }
    public String challenge(HttpServletRequest request) {
        String token=cookie(request,challengeName);
        if(token==null || !token.matches("[A-Za-z0-9_-]{43}"))throw new AccountFailure(400,"SIGN_IN_CHALLENGE_INVALID","Sign in again.");
        return token;
    }
    public AccountPrincipal complete(SignInRegistry.Admission admission,HttpServletRequest request,HttpServletResponse response) {
        var current=accounts.findById(admission.accountId()).filter(a->a.enabled()&&a.credentialEpoch()==admission.credentialEpoch())
                .orElseThrow(()->new AccountFailure(401,"AUTHENTICATION_REQUIRED","Sign in again."));
        registry.current(admission.accountId(),admission.credentialEpoch(),admission.signInId(),false);
        var principal=new AccountPrincipal(current.accountId(),current.username(),current.displayName(),null,true,current.credentialEpoch(),admission.signInId());
        install(principal,request,response);
        // Retain the short-lived proof cookie until expiry so a lost success response can retry idempotently.
        return principal;
    }
    public void cancel(HttpServletRequest request,HttpServletResponse response) {
        registry.cancel(challenge(request));setCookie(response,challengeName,"",0);
    }
    public static void clear(HttpServletRequest request) {
        SecurityContextHolder.clearContext();var session=request.getSession(false);if(session!=null)session.invalidate();
    }
    private void install(AccountPrincipal principal,HttpServletRequest request,HttpServletResponse response) {
        var authentication=UsernamePasswordAuthenticationToken.authenticated(principal,null,principal.getAuthorities());
        new ChangeSessionIdAuthenticationStrategy().onAuthentication(authentication,request,response);
        new CsrfAuthenticationStrategy(new HttpSessionCsrfTokenRepository()).onAuthentication(authentication,request,response);
        var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(authentication);SecurityContextHolder.setContext(context);
        new HttpSessionSecurityContextRepository().saveContext(context,request,response);
    }
    private void setCookie(HttpServletResponse response,String name,String value,long seconds) {
        response.addHeader("Set-Cookie",ResponseCookie.from(name,value).path("/").httpOnly(true).secure(secure).sameSite("Lax").maxAge(seconds).build().toString());
    }
    private static String cookie(HttpServletRequest request,String name) {
        if(request.getCookies()!=null)for(var cookie:request.getCookies())if(name.equals(cookie.getName()))return cookie.getValue();return null;
    }
    private static String client(String ua) {
        if(ua==null)return "Browser";
        String family=ua.contains("Edg/")?"Edge":ua.contains("Firefox/")?"Firefox":ua.contains("Chrome/")?"Chrome":ua.contains("Safari/")?"Safari":"Browser";
        String system=ua.contains("Android")?"Android":ua.contains("iPhone")||ua.contains("iPad")?"iOS":ua.contains("Windows")?"Windows":ua.contains("Macintosh")?"macOS":ua.contains("Linux")?"Linux":"unknown system";
        return family+" on "+system;
    }
}
