package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SecurityMisconfigController
 * INTENTIONALLY VULNERABLE — DAST test target.
 * Security Misconfiguration & Improper Inventory Management.
 * OWASP A05:2021 (Security Misconfiguration) / API8:2023 (Security Misconfiguration) / API9:2023 (Improper Inventory Management).
 */
@RestController
@RequestMapping("/api/config")
public class SecurityMisconfigController {

    private final JdbcTemplate jdbc;

    // VULN: hardcoded secrets baked into source
    private static final String JWT_SECRET = "s3cr3t-jwt-signing-key-do-not-share-2024";
    private static final String MASTER_KEY = "MASTER-AES-KEY-0123456789ABCDEF0123456789ABCDEF";
    private static final String DB_PASSWORD = "Pr0dDbP@ssw0rd!";

    public SecurityMisconfigController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // OWASP A05:2021 Security Misconfiguration — leaks the full server environment
    @GetMapping("/env")
    public Object env() {
        // VULN: exposes all environment variables (may include cloud creds, tokens)
        return System.getenv();
    }

    // OWASP A05:2021 — leaks all JVM system properties
    @GetMapping("/props")
    public Object props() {
        // VULN: dumps every system property (paths, user, classpath, versions)
        Map<Object, Object> out = new LinkedHashMap<>(System.getProperties());
        return out;
    }

    // OWASP A05:2021 / API8:2023 — returns hardcoded application secrets
    @GetMapping("/secrets")
    public Object secrets() {
        // VULN: hands out JWT signing key, master encryption key, and DB password
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jwt_secret", JWT_SECRET);
        out.put("master_key", MASTER_KEY);
        out.put("db_password", DB_PASSWORD);
        out.put("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE");
        out.put("aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        return out;
    }

    // OWASP A05:2021 — debug endpoint that dumps internal runtime state
    @GetMapping("/debug")
    public Object debug() {
        // VULN: exposes memory, thread, and datasource internals plus live secrets
        Runtime rt = Runtime.getRuntime();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("freeMemory", rt.freeMemory());
        out.put("totalMemory", rt.totalMemory());
        out.put("maxMemory", rt.maxMemory());
        out.put("availableProcessors", rt.availableProcessors());
        out.put("activeThreads", Thread.activeCount());
        out.put("workingDir", System.getProperty("user.dir"));
        out.put("jwtSecretLoaded", JWT_SECRET);
        try {
            out.put("dbUrl", jdbc.getDataSource().getConnection().getMetaData().getURL());
        } catch (Exception e) {
            out.put("dbUrlError", e.getMessage());
        }
        return out;
    }

    // OWASP API9:2023 Improper Inventory Management — deprecated undocumented v1-beta admin route still live
    @GetMapping("/v1-beta/admin/users")
    public Object v1BetaAdminUsers() {
        try {
            // VULN: old unauthenticated beta admin endpoint left in production, dumps all users
            return jdbc.queryForList("SELECT id, username, password, email, role, ssn, credit_card, api_key FROM users");
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API9:2023 — shadow API listing that advertises every internal/debug route
    @GetMapping("/routes")
    public Object routes() {
        // VULN: discloses hidden/internal/debug endpoints to any caller
        List<String> routes = List.of(
            "GET  /api/config/env",
            "GET  /api/config/props",
            "GET  /api/config/secrets",
            "GET  /api/config/debug",
            "GET  /api/config/v1-beta/admin/users   (deprecated, still live)",
            "GET  /api/config/defaults              (default credentials)",
            "GET  /api/config/error                 (verbose stack traces)",
            "POST /internal/admin/reset-db          (undocumented)",
            "POST /internal/admin/impersonate       (undocumented)",
            "GET  /actuator/heapdump                (unprotected)"
        );
        return Map.of("internalRoutes", routes);
    }

    // OWASP A05:2021 / API8:2023 — default-credentials check that reveals the defaults
    @GetMapping("/defaults")
    public Object defaults() {
        // VULN: exposes shipped default credentials that were never rotated
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("admin_username", "admin");
        out.put("admin_password", "admin");
        out.put("service_username", "service");
        out.put("service_password", "changeme");
        out.put("note", "default credentials are still active");
        return out;
    }

    // OWASP A05:2021 — verbose error endpoint returning full stack trace + server/build info
    @GetMapping("/error")
    public Object verboseError(@RequestParam(defaultValue = "boom") String trigger) {
        try {
            // VULN: deliberately throws, then returns internal details to the client
            throw new IllegalStateException("Unhandled failure processing: " + trigger);
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("message", e.getMessage());
            out.put("stackTrace", sw.toString());
            out.put("javaVersion", System.getProperty("java.version"));
            out.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version"));
            out.put("serverVersion", "vulnapp/1.0.0 (Spring Boot 3.2.5)");
            out.put("buildInfo", "build=2024-06-01T12:00:00Z commit=deadbeef branch=main");
            return out;
        }
    }
}
