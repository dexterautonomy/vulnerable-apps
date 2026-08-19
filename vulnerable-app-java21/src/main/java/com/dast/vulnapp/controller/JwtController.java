package com.dast.vulnapp.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.util.*;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Demonstrates OWASP A02/A07:2021 and API2:2023 - JWT / token handling flaws.
 */
@RestController
@RequestMapping("/api/jwt")
public class JwtController {

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper = new ObjectMapper();

    // Hardcoded, weak signing secret committed in source.
    private static final String SECRET = "supersecretkey1234567890supersecretkey";
    private final SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());

    public JwtController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public static class TokenRequest {
        public String token;
        public String username;
        public String role;
    }

    // Helper: manually base64-decode the JWT payload WITHOUT verifying the signature.
    private Map<String, Object> decodePayload(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return Collections.emptyMap();
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = mapper.readValue(payload, Map.class);
            return claims;
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    // OWASP A02: Issue a token signed with a hardcoded weak secret.
    @PostMapping("/issue")
    public Map<String, Object> issue(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        String jwt = Jwts.builder()
                .setSubject(req.username)
                .claim("role", req.role == null ? "USER" : req.role)
                .signWith(key)
                .compact();
        resp.put("token", jwt);
        return resp;
    }

    // OWASP A02: Accept a JWT and read claims WITHOUT verifying the signature.
    @PostMapping("/read")
    public Map<String, Object> read(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        // Signature never checked - forged tokens are trusted.
        resp.put("claims", decodePayload(req.token));
        return resp;
    }

    // OWASP A02: Accept alg=none tokens; decode payload, ignore signature, trust role/admin claims.
    @PostMapping("/verify-none")
    public Map<String, Object> verifyNone(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        Map<String, Object> claims = decodePayload(req.token);
        Object role = claims.get("role");
        Object admin = claims.get("admin");
        boolean isAdmin = "ADMIN".equals(role) || Boolean.TRUE.equals(admin) || "true".equals(String.valueOf(admin));
        resp.put("claims", claims);
        resp.put("admin", isAdmin);
        resp.put("access", isAdmin ? "GRANTED_ADMIN" : "user");
        return resp;
    }

    // OWASP A02: Token with NO expiry set (never expires).
    @PostMapping("/issue-noexpiry")
    public Map<String, Object> issueNoExpiry(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        // No setExpiration(...) call -> the token is valid forever.
        String jwt = Jwts.builder()
                .setSubject(req.username)
                .claim("role", req.role == null ? "USER" : req.role)
                .signWith(key)
                .compact();
        resp.put("token", jwt);
        resp.put("note", "no expiry");
        return resp;
    }

    // OWASP A02: Expiry claim is present but ignored during validation.
    @PostMapping("/verify-ignore-exp")
    public Map<String, Object> verifyIgnoreExp(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        Map<String, Object> claims = decodePayload(req.token);
        // 'exp' is read but never enforced -> expired tokens still accepted.
        resp.put("claims", claims);
        resp.put("status", "accepted (expiry not enforced)");
        return resp;
    }

    // OWASP A02 + A01: Issue a token embedding sensitive data (ssn, password) in the claims.
    @PostMapping("/issue-sensitive")
    public Map<String, Object> issueSensitive(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM users WHERE username = ?", req.username);
        Map<String, Object> user = rows.isEmpty() ? new HashMap<>() : rows.get(0);
        String jwt = Jwts.builder()
                .setSubject(req.username)
                .claim("ssn", user.get("ssn"))
                .claim("password", user.get("password"))
                .claim("credit_card", user.get("credit_card"))
                .signWith(key)
                .compact();
        resp.put("token", jwt);
        resp.put("decodedClaims", decodePayload(jwt));
        return resp;
    }

    // OWASP A02 + A09: Accept a JWT in a URL query parameter (leaked in logs / history).
    @GetMapping("/read-url")
    public Map<String, Object> readUrl(@RequestParam String token) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("claims", decodePayload(token));
        return resp;
    }

    // OWASP A02: Refresh that never validates the old token, just mints a new one from its claims.
    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        Map<String, Object> claims = decodePayload(req.token);
        String subject = String.valueOf(claims.get("sub"));
        String jwt = Jwts.builder()
                .setSubject(subject)
                .claim("role", claims.get("role"))
                .signWith(key)
                .compact();
        resp.put("token", jwt);
        resp.put("note", "old token signature never validated");
        return resp;
    }

    // OWASP A02: "Verify" that only checks the token string is non-empty.
    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        boolean valid = req.token != null && !req.token.trim().isEmpty();
        resp.put("valid", valid);
        resp.put("claims", valid ? decodePayload(req.token) : Collections.emptyMap());
        return resp;
    }

    // OWASP A02: Privilege escalation - edit the role claim and re-accept the unsigned token.
    @PostMapping("/escalate")
    public Map<String, Object> escalate(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        Map<String, Object> claims = new HashMap<>(decodePayload(req.token));
        // Caller-supplied role overwrites the claim; token is re-issued/trusted without verification.
        claims.put("role", req.role == null ? "ADMIN" : req.role);
        claims.put("admin", true);
        resp.put("claims", claims);
        resp.put("access", "GRANTED as " + claims.get("role"));
        return resp;
    }

    // OWASP A02: Long-lived token (100 years) signed with the weak secret.
    @PostMapping("/issue-longlived")
    public Map<String, Object> issueLongLived(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        long farFuture = System.currentTimeMillis() + (100L * 365 * 24 * 60 * 60 * 1000);
        String jwt = Jwts.builder()
                .setSubject(req.username)
                .claim("role", req.role == null ? "USER" : req.role)
                .setExpiration(new Date(farFuture))
                .signWith(key)
                .compact();
        resp.put("token", jwt);
        resp.put("expiresAt", new Date(farFuture).toString());
        return resp;
    }

    // OWASP A02 + A05: Secret disclosure - returns the JWT signing secret to any caller.
    @GetMapping("/secret")
    public Map<String, Object> secret() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("signingSecret", SECRET);
        resp.put("algorithm", "HS256");
        return resp;
    }

    // OWASP A02: Decode-any endpoint dumps arbitrary token claims without any verification.
    @PostMapping("/decode-any")
    public Map<String, Object> decodeAny(@RequestBody TokenRequest req) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("payload", decodePayload(req.token));
        // Also attempt a signed parse but swallow failures so unsigned/forged tokens still return data.
        try {
            Claims c = Jwts.parserBuilder().setSigningKey(key).build()
                    .parseClaimsJws(req.token).getBody();
            resp.put("verified", true);
            resp.put("verifiedClaims", c);
        } catch (Exception e) {
            resp.put("verified", false);
        }
        return resp;
    }
}
