package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Map;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Demonstrates reflected and stored Cross-Site Scripting (XSS).
 */
@RestController
@RequestMapping("/api/xss")
public class XssController {

    private final JdbcTemplate jdbc;

    public XssController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // OWASP A03:2021 Injection (Reflected XSS) - search term reflected unescaped
    @GetMapping(value = "/search", produces = "text/html")
    public String search(@RequestParam(defaultValue = "") String q) {
        return "<html><body><h1>Search results for: " + q + "</h1></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - greeting name reflected unescaped
    @GetMapping(value = "/greeting", produces = "text/html")
    public String greeting(@RequestParam(defaultValue = "guest") String name) {
        return "<html><body><p>Hello, " + name + "! Welcome back.</p></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - error message reflected unescaped
    @GetMapping(value = "/error", produces = "text/html")
    public String error(@RequestParam(defaultValue = "") String msg) {
        return "<html><body><div class='error'>Error: " + msg + "</div></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - redirect note reflected unescaped
    @GetMapping(value = "/redirect-note", produces = "text/html")
    public String redirectNote(@RequestParam(defaultValue = "/") String url) {
        return "<html><body>Redirecting you to <a href='" + url + "'>" + url + "</a></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - welcome name reflected unescaped
    @GetMapping(value = "/welcome", produces = "text/html")
    public String welcome(@RequestParam(defaultValue = "") String user) {
        return "<html><body><h2>Welcome " + user + "</h2><p>Enjoy your stay.</p></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - comment preview reflected unescaped
    @GetMapping(value = "/preview", produces = "text/html")
    public String preview(@RequestParam(defaultValue = "") String comment) {
        return "<html><body><h3>Comment preview</h3><div>" + comment + "</div></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - color reflected into <style> context
    @GetMapping(value = "/theme", produces = "text/html")
    public String theme(@RequestParam(defaultValue = "black") String color) {
        return "<html><head><style>body { color: " + color + "; }</style></head>"
                + "<body>Themed page</body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - value reflected into HTML attribute context
    @GetMapping(value = "/attr", produces = "text/html")
    public String attr(@RequestParam(defaultValue = "") String value) {
        return "<html><body><input type='text' value='" + value + "'></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - Referer header reflected unescaped
    @GetMapping(value = "/referer", produces = "text/html")
    public String referer(@RequestHeader(value = "Referer", required = false) String referer) {
        return "<html><body>You came from: " + referer + "</body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - User-Agent header reflected unescaped
    @GetMapping(value = "/user-agent", produces = "text/html")
    public String userAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return "<html><body>Your browser: " + ua + "</body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - path variable reflected unescaped
    @GetMapping(value = "/profile/{username}", produces = "text/html")
    public String profilePath(@PathVariable String username) {
        return "<html><body><h1>Profile of " + username + "</h1></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - JSON param injected into <script> context
    @GetMapping(value = "/script-context", produces = "text/html")
    public String scriptContext(@RequestParam(defaultValue = "{}") String data) {
        return "<html><body><script>var payload = " + data + ";</script></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - text/html attribute injection, no default escaping
    @GetMapping(value = "/link", produces = "text/html")
    public String link(@RequestParam(defaultValue = "#") String href) {
        return "<html><body><a href=\"" + href + "\" onclick=\"track()\">Click here</a></body></html>";
    }

    // OWASP A03:2021 Injection (Reflected XSS) - reflected into inline event handler / script
    @GetMapping(value = "/callback", produces = "text/html")
    public String callback(@RequestParam(defaultValue = "cb") String fn) {
        return "<html><body><script>window." + fn + "();</script></body></html>";
    }

    // OWASP A03:2021 Injection (Stored XSS) - persist comment body verbatim
    @PostMapping(value = "/comment", produces = "text/html")
    public String addComment(@RequestParam String author, @RequestParam String body) {
        jdbc.update("INSERT INTO comments(author, body, created_at) VALUES (?, ?, NOW())",
                author, body);
        return "<html><body>Comment saved. Thanks " + author + "!</body></html>";
    }

    // OWASP A03:2021 Injection (Stored XSS) - render all stored comment bodies as raw HTML
    @GetMapping(value = "/comments", produces = "text/html")
    public String listComments() {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT author, body FROM comments ORDER BY created_at DESC");
        StringBuilder sb = new StringBuilder("<html><body><h1>Comments</h1>");
        for (Map<String, Object> row : rows) {
            sb.append("<div><b>").append(row.get("author")).append("</b>: ")
                    .append(row.get("body")).append("</div>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    // OWASP A03:2021 Injection (Stored XSS) - persist profile bio into products.description
    @PostMapping(value = "/bio", produces = "text/html")
    public String saveBio(@RequestParam String name, @RequestParam String bio) {
        jdbc.update("INSERT INTO products(name, description, price, owner_id, stock) "
                + "VALUES (?, ?, 0, 0, 0)", name, bio);
        return "<html><body>Bio saved for " + name + "</body></html>";
    }

    // OWASP A03:2021 Injection (Stored XSS) - render stored product descriptions unescaped
    @GetMapping(value = "/bios", produces = "text/html")
    public String listBios() {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT name, description FROM products ORDER BY id DESC");
        StringBuilder sb = new StringBuilder("<html><body><h1>Profiles</h1>");
        for (Map<String, Object> row : rows) {
            sb.append("<section><h3>").append(row.get("name")).append("</h3><p>")
                    .append(row.get("description")).append("</p></section>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

}
