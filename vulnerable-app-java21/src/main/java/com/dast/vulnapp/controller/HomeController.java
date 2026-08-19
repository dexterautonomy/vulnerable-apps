package com.dast.vulnapp.controller;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Landing page + API inventory for the vulnerable test target.
 * The /api/inventory endpoint dumps every registered route, and other
 * endpoints leak version/config details — OWASP API9:2023 Improper Inventory
 * Management and A05:2021 Security Misconfiguration.
 */
@RestController
public class HomeController {

    private final RequestMappingHandlerMapping handlerMapping;

    @Value("${app.jwt.secret:}")
    private String jwtSecret;

    public HomeController(@Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping) {
        this.handlerMapping = handlerMapping;
    }

    // Landing page (text/html) linking to Swagger UI and the raw route inventory.
    @GetMapping(value = "/", produces = "text/html")
    public String index() {
        return "<html><body>"
             + "<h1>Vulnerable DAST Test Target (Java 21 / Spring Boot 3)</h1>"
             + "<p><b>WARNING:</b> intentionally insecure. Run only in an isolated lab.</p>"
             + "<ul>"
             + "<li><a href=\"/swagger-ui.html\">Swagger UI</a></li>"
             + "<li><a href=\"/v3/api-docs\">OpenAPI JSON</a></li>"
             + "<li><a href=\"/api/inventory\">Full route inventory</a></li>"
             + "<li><a href=\"/actuator\">Actuator (open)</a></li>"
             + "</ul></body></html>";
    }

    // OWASP API9:2023 — dumps the complete route inventory (incl. hidden/beta routes).
    @GetMapping("/api/inventory")
    public List<String> inventory() {
        return handlerMapping.getHandlerMethods().keySet().stream()
                .map(RequestMappingInfo::toString)
                .sorted()
                .collect(Collectors.toList());
    }

    // OWASP A05:2021 — version / build / runtime disclosure.
    @GetMapping("/api/version")
    public Map<String, Object> version() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("application", "vulnerable-app-java21");
        m.put("version", "1.0.0");
        m.put("springBoot", "3.2.5");
        m.put("java", System.getProperty("java.version"));
        m.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version"));
        m.put("user", System.getProperty("user.name"));
        return m;
    }

    // OWASP A05 — robots file that advertises "hidden" admin/debug paths.
    @GetMapping(value = "/robots.txt", produces = "text/plain")
    public String robots() {
        return "User-agent: *\n"
             + "Disallow: /api/bfla\n"
             + "Disallow: /api/config/secrets\n"
             + "Disallow: /actuator/env\n"
             + "Disallow: /api/deser\n";
    }

    // OWASP A05 — status endpoint that leaks the JWT signing secret.
    @GetMapping("/api/status")
    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", "UP");
        m.put("jwtSecret", jwtSecret);
        m.put("threads", Thread.activeCount());
        m.put("freeMemory", Runtime.getRuntime().freeMemory());
        return m;
    }
}
