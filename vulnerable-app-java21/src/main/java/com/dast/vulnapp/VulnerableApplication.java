package com.dast.vulnapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ============================================================================
 *  INTENTIONALLY VULNERABLE APPLICATION - FOR DAST SCANNER VALIDATION ONLY
 * ----------------------------------------------------------------------------
 *  This application deliberately contains a wide range of security flaws
 *  (OWASP Top 10 2021 + OWASP API Security Top 10 2023). It exists solely as
 *  a test target to verify that a DAST scanner correctly detects them.
 *
 *  DO NOT deploy on any network reachable by untrusted parties.
 *  DO NOT reuse any of this code in a real application.
 *  Run only inside an isolated lab / container environment.
 * ============================================================================
 */
@SpringBootApplication
public class VulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}
