package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

@RestController
@RequestMapping("/api/sqli")
public class SqlInjectionController {

    private final JdbcTemplate jdbc;

    public SqlInjectionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // OWASP A03:2021 Injection — username search, raw concatenation
    @GetMapping("/user-search")
    public List<Map<String,Object>> userSearch(@RequestParam String username) {
        return jdbc.queryForList("SELECT * FROM users WHERE username = '" + username + "'");
    }

    // OWASP A03:2021 Injection — product search with LIKE injection
    @GetMapping("/product-search")
    public List<Map<String,Object>> productSearch(@RequestParam String name) {
        return jdbc.queryForList("SELECT * FROM products WHERE name LIKE '%" + name + "%'");
    }

    // OWASP A03:2021 Injection — login with username + password concatenated
    @GetMapping("/login")
    public List<Map<String,Object>> login(@RequestParam String username, @RequestParam String password) {
        return jdbc.queryForList("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'");
    }

    // OWASP A03:2021 Injection — ORDER BY column injection from param
    @GetMapping("/user-sort")
    public List<Map<String,Object>> userSort(@RequestParam String sortColumn) {
        return jdbc.queryForList("SELECT id, username, email FROM users ORDER BY " + sortColumn);
    }

    // OWASP A03:2021 Injection — numeric id injection (no quoting)
    @GetMapping("/account-by-id")
    public List<Map<String,Object>> accountById(@RequestParam String id) {
        return jdbc.queryForList("SELECT * FROM accounts WHERE id = " + id);
    }

    // OWASP A03:2021 Injection — filter by role
    @GetMapping("/users-by-role")
    public List<Map<String,Object>> usersByRole(@RequestParam String role) {
        return jdbc.queryForList("SELECT id, username, role FROM users WHERE role = '" + role + "'");
    }

    // OWASP A03:2021 Injection — second-order: store a comment then use it in a query
    @PostMapping("/comment-store")
    public Map<String,Object> commentStore(@RequestParam String author, @RequestParam String body) {
        jdbc.update("INSERT INTO comments (author, body, created_at) VALUES ('" + author + "', '" + body + "', CURRENT_TIMESTAMP)");
        Map<String,Object> r = new HashMap<>();
        r.put("stored", author);
        return r;
    }

    // OWASP A03:2021 Injection — second-order use of stored author value
    @GetMapping("/comment-recall")
    public List<Map<String,Object>> commentRecall(@RequestParam String author) {
        String stored = jdbc.queryForList("SELECT author FROM comments WHERE author = '" + author + "'")
                .stream().map(m -> String.valueOf(m.get("author"))).findFirst().orElse(author);
        return jdbc.queryForList("SELECT * FROM users WHERE username = '" + stored + "'");
    }

    // OWASP A03:2021 Injection — boolean/blind style
    @GetMapping("/blind")
    public Map<String,Object> blind(@RequestParam String id) {
        List<Map<String,Object>> rows = jdbc.queryForList("SELECT id FROM users WHERE id = " + id + " AND is_admin = true");
        Map<String,Object> r = new HashMap<>();
        r.put("exists", !rows.isEmpty());
        return r;
    }

    // OWASP A03:2021 Injection — error-based (leaks DB errors)
    @GetMapping("/error-based")
    public Map<String,Object> errorBased(@RequestParam String id) {
        Map<String,Object> r = new HashMap<>();
        try {
            r.put("row", jdbc.queryForMap("SELECT * FROM users WHERE id = " + id));
        } catch (Exception e) {
            r.put("error", e.getMessage());
        }
        return r;
    }

    // OWASP A03:2021 Injection — multi-param WHERE clause
    @GetMapping("/multi-filter")
    public List<Map<String,Object>> multiFilter(@RequestParam String role, @RequestParam String email) {
        return jdbc.queryForList("SELECT * FROM users WHERE role = '" + role + "' AND email = '" + email + "'");
    }

    // OWASP A03:2021 Injection — DELETE with concatenated id
    @DeleteMapping("/comment-delete")
    public Map<String,Object> commentDelete(@RequestParam String id) {
        int n = jdbc.update("DELETE FROM comments WHERE id = " + id);
        Map<String,Object> r = new HashMap<>();
        r.put("deleted", n);
        return r;
    }

    // OWASP A03:2021 Injection — UPDATE with concatenated values
    @PutMapping("/user-update-email")
    public Map<String,Object> userUpdateEmail(@RequestParam String id, @RequestParam String email) {
        int n = jdbc.update("UPDATE users SET email = '" + email + "' WHERE id = " + id);
        Map<String,Object> r = new HashMap<>();
        r.put("updated", n);
        return r;
    }

    // OWASP A03:2021 Injection — search in messages by subject
    @GetMapping("/message-search")
    public List<Map<String,Object>> messageSearch(@RequestParam String subject) {
        return jdbc.queryForList("SELECT * FROM messages WHERE subject LIKE '%" + subject + "%'");
    }

    // OWASP A03:2021 Injection — search documents by filename
    @GetMapping("/document-search")
    public List<Map<String,Object>> documentSearch(@RequestParam String filename) {
        return jdbc.queryForList("SELECT * FROM documents WHERE filename = '" + filename + "'");
    }

    // OWASP A03:2021 Injection — search orders by status
    @GetMapping("/order-search")
    public List<Map<String,Object>> orderSearch(@RequestParam String status) {
        return jdbc.queryForList("SELECT * FROM orders WHERE status = '" + status + "'");
    }

    // OWASP A03:2021 Injection — search accounts by account_number
    @GetMapping("/account-search")
    public List<Map<String,Object>> accountSearch(@RequestParam String accountNumber) {
        return jdbc.queryForList("SELECT * FROM accounts WHERE account_number = '" + accountNumber + "'");
    }

    // OWASP A03:2021 Injection — sort direction injection (ASC/DESC concatenated)
    @GetMapping("/product-sort")
    public List<Map<String,Object>> productSort(@RequestParam String direction) {
        return jdbc.queryForList("SELECT * FROM products ORDER BY price " + direction);
    }

    // OWASP A03:2021 Injection — LIMIT injection
    @GetMapping("/user-limit")
    public List<Map<String,Object>> userLimit(@RequestParam String limit) {
        return jdbc.queryForList("SELECT id, username FROM users LIMIT " + limit);
    }

    // OWASP A03:2021 Injection — header sourced value concatenated
    @GetMapping("/by-header")
    public List<Map<String,Object>> byHeader(HttpServletRequest request) {
        String apiKey = request.getHeader("X-Api-Key");
        return jdbc.queryForList("SELECT id, username FROM users WHERE api_key = '" + apiKey + "'");
    }

    // OWASP A03:2021 Injection — JSON body field concatenated into SQL
    @PostMapping("/json-lookup")
    public List<Map<String,Object>> jsonLookup(@RequestBody LookupRequest body) {
        return jdbc.queryForList("SELECT * FROM users WHERE ssn = '" + body.ssn + "'");
    }

    // OWASP A03:2021 Injection — path variable concatenated
    @GetMapping("/user/{id}")
    public List<Map<String,Object>> userByPath(@PathVariable String id) {
        return jdbc.queryForList("SELECT * FROM users WHERE id = " + id);
    }

    public static class LookupRequest {
        public String ssn;
        public String username;
    }

}
