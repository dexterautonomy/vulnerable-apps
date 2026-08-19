package com.dast.vulnapp.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Demonstrates OWASP A07:2021 - Identification and Authentication Failures
 * and API2:2023 - Broken Authentication.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final JdbcTemplate jdbc;

    public AuthenticationController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ---- Inner DTOs ----
    public static class LoginRequest {
        public String username;
        public String password;
        public String email;
        public String otp;
        public String oldPassword;
        public String newPassword;
        public String resetToken;
        public String sessionId;
    }

    // OWASP A07: Plaintext password comparison, NO rate limiting / lockout (brute-forceable).
    // Password stored and compared as plaintext straight from the DB.
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM users WHERE username = ?", req.username);
        if (rows.isEmpty()) {
            resp.put("status", "error");
            resp.put("message", "login failed");
            return resp;
        }
        Map<String, Object> user = rows.get(0);
        String dbPassword = String.valueOf(user.get("password"));
        // No lockout, no attempt counter -> unlimited brute force.
        if (dbPassword.equals(req.password)) {
            resp.put("status", "ok");
            resp.put("token", Base64.getEncoder().encodeToString(req.username.getBytes()));
        } else {
            resp.put("status", "error");
            resp.put("message", "login failed");
        }
        return resp;
    }

    // OWASP A07 + A03: Login that concatenates credentials directly into SQL (SQL injection auth bypass).
    @PostMapping("/login-sql")
    public Map<String, Object> loginSql(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        String sql = "SELECT * FROM users WHERE username = '" + req.username
                + "' AND password = '" + req.password + "'";
        try {
            List<Map<String, Object>> rows = jdbc.queryForList(sql);
            if (!rows.isEmpty()) {
                resp.put("status", "ok");
                resp.put("user", rows.get(0));
            } else {
                resp.put("status", "error");
                resp.put("message", "invalid credentials");
            }
        } catch (Exception e) {
            resp.put("status", "error");
            resp.put("message", e.getMessage());
        }
        return resp;
    }

    // OWASP A07: User enumeration - distinct messages for unknown user vs wrong password.
    @PostMapping("/login-enum")
    public Map<String, Object> loginEnum(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM users WHERE username = ?", req.username);
        if (rows.isEmpty()) {
            resp.put("status", "error");
            resp.put("message", "No account exists with username '" + req.username + "'");
            return resp;
        }
        String dbPassword = String.valueOf(rows.get(0).get("password"));
        if (!dbPassword.equals(req.password)) {
            resp.put("status", "error");
            resp.put("message", "Incorrect password for user '" + req.username + "'");
        } else {
            resp.put("status", "ok");
        }
        return resp;
    }

    // OWASP A07 + A09: Login via GET with credentials in the URL (logged in access logs / history).
    @GetMapping("/login-get")
    public Map<String, Object> loginGet(@RequestParam String username,
                                        @RequestParam String password) {
        Map<String, Object> resp = new HashMap<>();
        // Credentials leaked in query string; also logged to audit table in cleartext.
        jdbc.update("INSERT INTO audit_logs(action, username, ip, detail, created_at) VALUES (?,?,?,?, CURRENT_TIMESTAMP)",
                "login-get", username, "n/a", "pw=" + password);
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM users WHERE username = ? AND password = ?", username, password);
        resp.put("status", rows.isEmpty() ? "error" : "ok");
        return resp;
    }

    // OWASP A07: Password reset that accepts a guessable/short reset_token (and resets to arbitrary value).
    @PostMapping("/reset-password")
    public Map<String, Object> resetPassword(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM users WHERE username = ? AND reset_token = ?",
                req.username, req.resetToken);
        // Tokens are short/guessable and never expire; any match resets the password (plaintext).
        if (!rows.isEmpty()) {
            jdbc.update("UPDATE users SET password = ? WHERE username = ?", req.newPassword, req.username);
            resp.put("status", "ok");
            resp.put("message", "password updated");
        } else {
            resp.put("status", "error");
            resp.put("message", "invalid token");
        }
        return resp;
    }

    // OWASP A07: Password reset with NO token at all - anyone can reset any user's password.
    @PostMapping("/reset-password-notoken")
    public Map<String, Object> resetPasswordNoToken(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        jdbc.update("UPDATE users SET password = ? WHERE username = ?", req.newPassword, req.username);
        resp.put("status", "ok");
        resp.put("message", "password for " + req.username + " reset without verification");
        return resp;
    }

    // OWASP A07: Registration with NO password policy, stores plaintext password.
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        // Accepts any password ("1", "", etc.) and stores it in cleartext.
        jdbc.update("INSERT INTO users(username, password, email, role, is_admin, balance) VALUES (?,?,?,?,?,?)",
                req.username, req.password, req.email, "USER", false, 0);
        resp.put("status", "ok");
        resp.put("message", "registered " + req.username + " with plaintext password");
        return resp;
    }

    // OWASP A07: Change password WITHOUT verifying the old password.
    @PostMapping("/change-password")
    public Map<String, Object> changePassword(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        // oldPassword is never checked -> account takeover if session/username is known.
        jdbc.update("UPDATE users SET password = ? WHERE username = ?", req.newPassword, req.username);
        resp.put("status", "ok");
        resp.put("message", "password changed without old-password check");
        return resp;
    }

    // OWASP A07: "Forgot username" reveals whether an email exists (account enumeration).
    @GetMapping("/forgot-username")
    public Map<String, Object> forgotUsername(@RequestParam String email) {
        Map<String, Object> resp = new HashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT username FROM users WHERE email = ?", email);
        if (rows.isEmpty()) {
            resp.put("exists", false);
            resp.put("message", "No account with that email");
        } else {
            resp.put("exists", true);
            resp.put("username", rows.get(0).get("username"));
        }
        return resp;
    }

    // OWASP A07: Remember-me token = base64(username) - trivially forgeable.
    @PostMapping("/remember-me")
    public Map<String, Object> rememberMe(@RequestBody LoginRequest req, HttpServletResponse response) {
        Map<String, Object> resp = new HashMap<>();
        String token = Base64.getEncoder().encodeToString(req.username.getBytes());
        Cookie cookie = new Cookie("remember_me", token);
        cookie.setPath("/");
        response.addCookie(cookie);
        resp.put("status", "ok");
        resp.put("remember_me", token);
        return resp;
    }

    // OWASP A07: Authenticate purely from a forgeable remember-me cookie (base64 username).
    @GetMapping("/remember-me-auth")
    public Map<String, Object> rememberMeAuth(@CookieValue(value = "remember_me", required = false) String token) {
        Map<String, Object> resp = new HashMap<>();
        if (token == null) {
            resp.put("status", "error");
            return resp;
        }
        String username = new String(Base64.getDecoder().decode(token));
        resp.put("status", "ok");
        resp.put("authenticatedAs", username);
        return resp;
    }

    // OWASP A07: Session fixation - accepts a caller-supplied session id from a parameter.
    @GetMapping("/session")
    public Map<String, Object> session(@RequestParam String sessionId,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        Map<String, Object> resp = new HashMap<>();
        // Attacker-chosen session id is set as the session cookie -> session fixation.
        Cookie cookie = new Cookie("JSESSIONID", sessionId);
        cookie.setPath("/");
        response.addCookie(cookie);
        resp.put("status", "ok");
        resp.put("session", sessionId);
        return resp;
    }

    // OWASP A07 + A01: Login response returns password and api_key (sensitive data exposure).
    @PostMapping("/login-verbose")
    public Map<String, Object> loginVerbose(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM users WHERE username = ? AND password = ?", req.username, req.password);
        if (rows.isEmpty()) {
            resp.put("status", "error");
            return resp;
        }
        Map<String, Object> user = rows.get(0);
        resp.put("status", "ok");
        resp.put("password", user.get("password"));
        resp.put("api_key", user.get("api_key"));
        resp.put("ssn", user.get("ssn"));
        return resp;
    }

    // OWASP A07: verify-otp accepts ANY 6-digit code or the hardcoded 000000 backdoor.
    @PostMapping("/verify-otp")
    public Map<String, Object> verifyOtp(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        String otp = req.otp == null ? "" : req.otp;
        boolean ok = otp.equals("000000") || otp.matches("\\d{6}");
        resp.put("status", ok ? "ok" : "error");
        resp.put("message", ok ? "otp accepted" : "invalid otp");
        return resp;
    }

    // OWASP A07: Admin login backdoor - hardcoded master password bypasses the DB entirely.
    @PostMapping("/admin-login")
    public Map<String, Object> adminLogin(@RequestBody LoginRequest req) {
        Map<String, Object> resp = new HashMap<>();
        if ("admin".equals(req.username) && "letmein-admin-2021".equals(req.password)) {
            resp.put("status", "ok");
            resp.put("role", "ADMIN");
            resp.put("token", Base64.getEncoder().encodeToString("admin".getBytes()));
        } else {
            resp.put("status", "error");
        }
        return resp;
    }

    // OWASP A07: Logout that does not invalidate any session/token (cookie left intact).
    @PostMapping("/logout")
    public Map<String, Object> logout() {
        Map<String, Object> resp = new HashMap<>();
        // No session invalidation, no token revocation - the token stays valid forever.
        resp.put("status", "ok");
        resp.put("message", "logged out (token still valid)");
        return resp;
    }

}
