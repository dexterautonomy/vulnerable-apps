package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * MassAssignmentController
 * INTENTIONALLY VULNERABLE — DAST test target.
 * Mass Assignment / Broken Object Property Level Authorization (BOPLA).
 * OWASP API3:2023 (Broken Object Property Level Authorization) / A01:2021 (Broken Access Control).
 */
@RestController
@RequestMapping("/api/mass")
public class MassAssignmentController {

    private final JdbcTemplate jdbc;

    public MassAssignmentController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // OWASP API3:2023 Broken Object Property Level Authorization — register user, body can set is_admin/role/balance
    @PostMapping("/register")
    public Object register(@RequestBody Map<String, Object> body) {
        try {
            // VULN: blindly persists every client-supplied property including privileged ones
            jdbc.update(
                "INSERT INTO users(username, password, email, role, is_admin, balance) VALUES (?,?,?,?,?,?)",
                body.get("username"),
                body.get("password"),
                body.get("email"),
                body.getOrDefault("role", "user"),
                body.getOrDefault("is_admin", false),
                body.getOrDefault("balance", 0)
            );
            return Map.of("status", "registered", "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 — update profile that also lets client write role/is_admin
    @PutMapping("/profile/{id}")
    public Object updateProfile(@PathVariable int id, @RequestBody Map<String, Object> body) {
        try {
            // VULN: privileged columns role & is_admin taken straight from the request body
            jdbc.update(
                "UPDATE users SET email=?, role=?, is_admin=? WHERE id=?",
                body.get("email"),
                body.get("role"),
                body.get("is_admin"),
                id
            );
            return Map.of("status", "updated", "id", id, "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 — create product with arbitrary owner_id and client-chosen price (e.g. 0)
    @PostMapping("/product")
    public Object createProduct(@RequestBody Map<String, Object> body) {
        try {
            // VULN: client controls owner_id and price, can set price=0 or steal ownership
            jdbc.update(
                "INSERT INTO products(name, description, price, owner_id, stock) VALUES (?,?,?,?,?)",
                body.get("name"),
                body.get("description"),
                body.getOrDefault("price", 0),
                body.get("owner_id"),
                body.getOrDefault("stock", 0)
            );
            return Map.of("status", "created", "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 — update account letting the client set its own balance
    @PutMapping("/account/{id}")
    public Object updateAccount(@PathVariable int id, @RequestBody Map<String, Object> body) {
        try {
            // VULN: balance is directly assignable by the client
            jdbc.update(
                "UPDATE accounts SET account_number=?, balance=?, type=? WHERE id=?",
                body.get("account_number"),
                body.get("balance"),
                body.get("type"),
                id
            );
            return Map.of("status", "updated", "id", id, "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 — update order letting client set total and status=PAID
    @PutMapping("/order/{id}")
    public Object updateOrder(@PathVariable int id, @RequestBody Map<String, Object> body) {
        try {
            // VULN: client can force status=PAID and set an arbitrary total
            jdbc.update(
                "UPDATE orders SET quantity=?, total=?, status=? WHERE id=?",
                body.get("quantity"),
                body.get("total"),
                body.getOrDefault("status", "PAID"),
                id
            );
            return Map.of("status", "updated", "id", id, "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 + A03 Injection — PATCH user merging every provided key into a dynamic UPDATE
    @PatchMapping("/user/{id}")
    public Object patchUser(@PathVariable int id, @RequestBody Map<String, Object> body) {
        try {
            // VULN: SET clause built from arbitrary client keys — mass assignment AND SQL injection
            StringBuilder sql = new StringBuilder("UPDATE users SET ");
            List<Object> params = new ArrayList<>();
            int i = 0;
            for (Map.Entry<String, Object> e : body.entrySet()) {
                if (i++ > 0) sql.append(", ");
                sql.append(e.getKey()).append("=?"); // column name injected verbatim
                params.add(e.getValue());
            }
            sql.append(" WHERE id=").append(id); // id concatenated — also injectable
            jdbc.update(sql.toString(), params.toArray());
            return Map.of("status", "patched", "sql", sql.toString(), "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 — create api_client with client-chosen scopes including admin
    @PostMapping("/apiclient")
    public Object createApiClient(@RequestBody Map<String, Object> body) {
        try {
            // VULN: scopes (incl. "admin") and owner_id taken directly from the client
            jdbc.update(
                "INSERT INTO api_clients(client_id, client_secret, scopes, owner_id) VALUES (?,?,?,?)",
                body.get("client_id"),
                body.get("client_secret"),
                body.getOrDefault("scopes", "admin"),
                body.get("owner_id")
            );
            return Map.of("status", "created", "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 + A03 Injection — "settings" update that writes to ANY column the client names
    @PostMapping("/settings/{id}")
    public Object updateSettings(@PathVariable int id, @RequestBody Map<String, Object> body) {
        try {
            // VULN: arbitrary column name + value from the body, no allow-list at all
            String column = String.valueOf(body.get("column"));
            Object value = body.get("value");
            String sql = "UPDATE users SET " + column + "=? WHERE id=" + id;
            jdbc.update(sql, value);
            return Map.of("status", "settings-updated", "sql", sql);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 — import user from JSON, populating ALL sensitive columns from the body
    @PostMapping("/import")
    public Object importUser(@RequestBody Map<String, Object> body) {
        try {
            // VULN: ssn, credit_card, api_key, reset_token, is_admin, balance all client-controlled
            jdbc.update(
                "INSERT INTO users(username, password, email, role, ssn, credit_card, api_key, reset_token, is_admin, balance) " +
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                body.get("username"),
                body.get("password"),
                body.get("email"),
                body.getOrDefault("role", "admin"),
                body.get("ssn"),
                body.get("credit_card"),
                body.get("api_key"),
                body.get("reset_token"),
                body.getOrDefault("is_admin", true),
                body.getOrDefault("balance", 0)
            );
            return Map.of("status", "imported", "applied", body);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API3:2023 + A03 Injection — bulk update via a list of maps, each dynamically applied
    @PostMapping("/bulk")
    public Object bulkUpdate(@RequestBody List<Map<String, Object>> items) {
        List<Object> results = new ArrayList<>();
        try {
            for (Map<String, Object> body : items) {
                // VULN: every field of every item merged blindly into a dynamic UPDATE
                StringBuilder sql = new StringBuilder("UPDATE users SET ");
                List<Object> params = new ArrayList<>();
                int i = 0;
                Object id = body.get("id");
                for (Map.Entry<String, Object> e : body.entrySet()) {
                    if ("id".equals(e.getKey())) continue;
                    if (i++ > 0) sql.append(", ");
                    sql.append(e.getKey()).append("=?");
                    params.add(e.getValue());
                }
                sql.append(" WHERE id=").append(id);
                jdbc.update(sql.toString(), params.toArray());
                results.add(sql.toString());
            }
            return Map.of("status", "bulk-updated", "count", results.size(), "statements", results);
        } catch (Exception e) {
            return Map.of("error", e.getMessage(), "partial", results);
        }
    }
}
