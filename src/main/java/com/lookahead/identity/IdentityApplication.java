package com.lookahead.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Identity classes are physically isolated from Gateway and Learning Domain API artifacts. */
@SpringBootApplication(exclude = org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration.class)
public class IdentityApplication {
    public static void main(String[] args) {
        var application = new SpringApplication(IdentityApplication.class);
        application.setAdditionalProfiles("accounts", "oauth-server");
        application.run(args);
    }
}
