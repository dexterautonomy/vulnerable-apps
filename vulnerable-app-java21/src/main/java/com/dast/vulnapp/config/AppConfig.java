package com.dast.vulnapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * Shared beans used by the (self-contained) vulnerable controllers.
 * Intentionally uses a default RestTemplate with no SSRF protections,
 * no allow-list, and follows redirects.
 */
@Configuration
public class AppConfig {

    @Bean
    public RestTemplate restTemplate() {
        // No timeouts, no proxy restrictions, no host allow-list: intentional (SSRF target).
        return new RestTemplate();
    }
}
