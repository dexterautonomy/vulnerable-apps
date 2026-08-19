package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.util.*;

@RestController
@RequestMapping("/api/data")
public class SensitiveDataExposureController {

    private final JdbcTemplate jdbc;
    private final DataSource dataSource;

    public SensitiveDataExposureController(JdbcTemplate jdbc, DataSource dataSource) {
        this.jdbc = jdbc;
        this.dataSource = dataSource;
    }

    // OWASP A01:2021 / API3:2023 — dump ALL users including password, ssn, credit_card, api_key
    @GetMapping("/users")
    public List<Map<String,Object>> allUsers() {
        return jdbc.queryForList("SELECT * FROM users");
    }

    // OWASP A01:2021 / API3:2023 — user profile returns full row incl secrets (no property filtering)
    @GetMapping("/profile")
    public List<Map<String,Object>> profile(@RequestParam String id) {
        return jdbc.queryForList("SELECT * FROM users WHERE id = " + id);
    }

    // OWASP A01:2021 — dump all accounts with balances and account numbers
    @GetMapping("/accounts")
    public List<Map<String,Object>> allAccounts() {
        return jdbc.queryForList("SELECT * FROM accounts");
    }

    // OWASP A01:2021 — dump all api_clients including client_secret
    @GetMapping("/api-clients")
    public List<Map<String,Object>> allApiClients() {
        return jdbc.queryForList("SELECT id, client_id, client_secret, scopes, owner_id FROM api_clients");
    }

    // OWASP A02:2021 — search that returns password and ssn columns
    @GetMapping("/search")
    public List<Map<String,Object>> search(@RequestParam String q) {
        return jdbc.queryForList(
            "SELECT id, username, email, password, ssn, credit_card FROM users WHERE username LIKE '%" + q + "%'");
    }

    // OWASP A02:2021 — CSV export of users with full PII
    @GetMapping("/export-csv")
    public String exportCsv() {
        List<Map<String,Object>> rows = jdbc.queryForList(
            "SELECT id, username, email, password, ssn, credit_card, api_key FROM users");
        StringBuilder sb = new StringBuilder("id,username,email,password,ssn,credit_card,api_key\n");
        for (Map<String,Object> row : rows) {
            sb.append(row.get("id")).append(",")
              .append(row.get("username")).append(",")
              .append(row.get("email")).append(",")
              .append(row.get("password")).append(",")
              .append(row.get("ssn")).append(",")
              .append(row.get("credit_card")).append(",")
              .append(row.get("api_key")).append("\n");
        }
        return sb.toString();
    }

    // OWASP A05:2021 — debug endpoint leaking JVM system properties and environment variables
    @GetMapping("/debug")
    public Map<String,Object> debug() {
        Map<String,Object> r = new HashMap<>();
        Map<String,Object> props = new HashMap<>();
        for (Map.Entry<Object,Object> e : System.getProperties().entrySet())
            props.put(String.valueOf(e.getKey()), e.getValue());
        r.put("systemProperties", props);
        r.put("environment", System.getenv());
        return r;
    }

    // OWASP A02:2021 — leak database connection URL and credentials from DataSource metadata
    @GetMapping("/db-info")
    public Map<String,Object> dbInfo() {
        Map<String,Object> r = new HashMap<>();
        try (Connection con = dataSource.getConnection()) {
            DatabaseMetaData md = con.getMetaData();
            r.put("url", md.getURL());
            r.put("username", md.getUserName());
            r.put("driver", md.getDriverName());
            r.put("driverVersion", md.getDriverVersion());
            r.put("databaseProduct", md.getDatabaseProductName());
        } catch (Exception e) {
            r.put("error", e.getMessage());
        }
        return r;
    }

    // OWASP A05:2021 — verbose error returning a full stack trace to the client
    @GetMapping("/verbose-error")
    public Map<String,Object> verboseError(@RequestParam String value) {
        Map<String,Object> r = new HashMap<>();
        try {
            int n = Integer.parseInt(value);
            r.put("result", 100 / n);
        } catch (Exception e) {
            leakStackTrace(r, e);
        }
        return r;
    }

    private void leakStackTrace(Map<String,Object> r, Exception e) {
        StringBuilder sb = new StringBuilder(e.toString()).append("\n");
        for (StackTraceElement el : e.getStackTrace()) sb.append("\tat ").append(el).append("\n");
        r.put("exception", e.getClass().getName());
        r.put("message", e.getMessage());
        r.put("stackTrace", sb.toString());
    }

    // OWASP A01:2021 — backup dump of documents.content (contains embedded secrets)
    @GetMapping("/backup")
    public List<Map<String,Object>> backup() {
        return jdbc.queryForList("SELECT id, owner_id, filename, filepath, content, is_public FROM documents");
    }

    // OWASP A02:2021 — leak reset_token for any user by username
    @GetMapping("/reset-token")
    public List<Map<String,Object>> resetToken(@RequestParam String username) {
        return jdbc.queryForList(
            "SELECT id, username, reset_token FROM users WHERE username = '" + username + "'");
    }

    // OWASP A01:2021 — echo all request headers back including Authorization
    @GetMapping("/echo-headers")
    public Map<String,Object> echoHeaders(HttpServletRequest request) {
        Map<String,Object> r = new HashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            r.put(name, request.getHeader(name));
        }
        return r;
    }

    // OWASP A02:2021 — return hardcoded application secrets
    @GetMapping("/app-secrets")
    public Map<String,Object> appSecrets() {
        Map<String,Object> r = new HashMap<>();
        r.put("jwtSigningKey", "super-secret-jwt-key-do-not-share-12345");
        r.put("awsAccessKeyId", "AKIAIOSFODNN7EXAMPLE");
        r.put("awsSecretAccessKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        r.put("stripeApiKey", "sk_live_51H8xR2eZvKYlo2C0examplekey");
        r.put("dbPassword", "postgres_prod_password");
        return r;
    }

    // OWASP A01:2021 / API3:2023 — return full unmasked credit_card by user id
    @GetMapping("/credit-card")
    public List<Map<String,Object>> creditCard(@RequestParam String userId) {
        return jdbc.queryForList(
            "SELECT id, username, credit_card FROM users WHERE id = " + userId);
    }

}
