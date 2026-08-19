package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * ResourceConsumptionController
 * INTENTIONALLY VULNERABLE — DAST test target.
 * Unrestricted Resource Consumption — no pagination, no limits, no rate control.
 * OWASP API4:2023 (Unrestricted Resource Consumption).
 */
@RestController
@RequestMapping("/api/limits")
public class ResourceConsumptionController {

    private final JdbcTemplate jdbc;

    public ResourceConsumptionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // OWASP API4:2023 Unrestricted Resource Consumption — list ALL rows, no pagination
    @GetMapping("/users/all")
    public Object listAllUsers() {
        try {
            // VULN: returns every user row with no LIMIT / paging
            return jdbc.queryForList("SELECT * FROM users");
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API4:2023 — client 'limit' param used unbounded (attacker can request millions)
    @GetMapping("/products")
    public Object listProducts(@RequestParam(defaultValue = "1000000") int limit) {
        try {
            // VULN: limit concatenated with no upper bound / validation
            return jdbc.queryForList("SELECT * FROM products LIMIT " + limit);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API4:2023 — allocates an array sized by a client param (memory DoS)
    @GetMapping("/allocate")
    public Object allocate(@RequestParam int size) {
        // VULN: no cap on allocation size — trivial OutOfMemoryError
        long[] hog = new long[size];
        for (int i = 0; i < hog.length; i++) hog[i] = i;
        return Map.of("allocated", hog.length, "lastValue", hog[hog.length - 1]);
    }

    // OWASP API4:2023 — CPU DoS: loop runs param-many iterations
    @GetMapping("/spin")
    public Object spin(@RequestParam long iterations) {
        // VULN: unbounded busy loop burns CPU for as long as the client wants
        long acc = 0;
        for (long i = 0; i < iterations; i++) {
            acc += (i * 31L) ^ (i >> 3);
        }
        return Map.of("iterations", iterations, "acc", acc);
    }

    // OWASP API4:2023 — ReDoS: user-supplied regex matched against user-supplied input
    @GetMapping("/regex")
    public Object regexMatch(@RequestParam String pattern, @RequestParam String input) {
        try {
            // VULN: catastrophic backtracking possible from attacker-controlled pattern
            boolean matched = Pattern.compile(pattern).matcher(input).matches();
            return Map.of("pattern", pattern, "matched", matched);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API4:2023 — exponential recursion (fibonacci) driven by a client param
    @GetMapping("/fib")
    public Object fib(@RequestParam int n) {
        // VULN: naive exponential recursion, no bound — fib(60) hangs the thread
        return Map.of("n", n, "value", fibonacci(n));
    }

    private long fibonacci(int n) {
        if (n < 2) return n;
        return fibonacci(n - 1) + fibonacci(n - 2);
    }

    // OWASP API4:2023 — bulk export with no cap (dumps every table row set)
    @GetMapping("/export")
    public Object export() {
        try {
            // VULN: loads all users, accounts, products, orders into memory at once, unbounded
            Map<String, Object> dump = new java.util.HashMap<>();
            dump.put("users", jdbc.queryForList("SELECT * FROM users"));
            dump.put("accounts", jdbc.queryForList("SELECT * FROM accounts"));
            dump.put("products", jdbc.queryForList("SELECT * FROM products"));
            dump.put("orders", jdbc.queryForList("SELECT * FROM orders"));
            return dump;
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API4:2023 — expensive report, no rate limit, heavy per-request work
    @GetMapping("/report")
    public Object report(@RequestParam(defaultValue = "1000000") int depth) {
        // VULN: expensive computation on every hit, no throttling / caching
        double total = 0;
        for (int i = 1; i <= depth; i++) {
            total += Math.sqrt(i) * Math.log(i + 1) / Math.sin(i + 1.0001);
        }
        return Map.of("depth", depth, "score", total);
    }

    // OWASP API4:2023 — 'repeat' concatenates a string param N times (memory DoS)
    @GetMapping("/repeat")
    public Object repeat(@RequestParam String text, @RequestParam int times) {
        // VULN: no bound on 'times' — builds an arbitrarily huge string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) sb.append(text);
        return Map.of("length", sb.length(), "times", times);
    }

    // OWASP API4:2023 — batch endpoint accepting an unbounded list, processes all
    @PostMapping("/batch")
    public Object batch(@RequestBody List<Map<String, Object>> items) {
        List<Object> results = new ArrayList<>();
        try {
            // VULN: no cap on list size; a DB write per element regardless of count
            for (Map<String, Object> item : items) {
                jdbc.update(
                    "INSERT INTO products(name, description, price, owner_id, stock) VALUES (?,?,?,?,?)",
                    item.get("name"),
                    item.get("description"),
                    item.getOrDefault("price", 0),
                    item.get("owner_id"),
                    item.getOrDefault("stock", 0)
                );
                results.add(item.get("name"));
            }
            return Map.of("processed", results.size());
        } catch (Exception e) {
            return Map.of("error", e.getMessage(), "processed", results.size());
        }
    }
}
