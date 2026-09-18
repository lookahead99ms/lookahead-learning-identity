package com.lookahead.identity.oauth;

import jakarta.servlet.http.*;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import java.net.URI;

@RestController
@Profile("oauth-server")
public class OAuthContinueController {
    private final OAuthSettings settings;
    public OAuthContinueController(OAuthSettings settings) { this.settings=settings; }
    @GetMapping("/api/v1/auth/continue")
    public void resume(HttpServletRequest request,HttpServletResponse response) throws java.io.IOException {
        var cache=new HttpSessionRequestCache(); var saved=cache.getRequest(request,response);
        String target=settings.frontend()+"/bff/login";
        if(saved!=null) {
            URI uri=URI.create(saved.getRedirectUrl());
            if("/oauth2/authorize".equals(uri.getPath())) target=settings.frontend()+uri.getRawPath()+"?"+uri.getRawQuery();
            cache.removeRequest(request,response);
        }
        response.setHeader("Cache-Control","no-store"); response.sendRedirect(target);
    }
}
