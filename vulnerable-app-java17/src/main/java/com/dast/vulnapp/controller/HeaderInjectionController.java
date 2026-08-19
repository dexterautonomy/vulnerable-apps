package com.dast.vulnapp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.HashMap;
import java.util.Map;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Demonstrates response-header injection, CRLF / response splitting,
 * host-header trust, and cache poisoning.
 */
@RestController
@RequestMapping("/api/headers")
public class HeaderInjectionController {

    // OWASP A03:2021 Injection (CRLF / Response Splitting) - arbitrary header from param
    @GetMapping("/custom")
    public Map<String, Object> custom(@RequestParam String value, HttpServletResponse response) {
        response.setHeader("X-Custom", value);
        Map<String, Object> out = new HashMap<>();
        out.put("set", "X-Custom");
        out.put("value", value);
        return out;
    }

    // OWASP A01:2021 Broken Access Control (Open Redirect via header injection) - Location from param
    @GetMapping("/location")
    public Map<String, Object> location(@RequestParam String url, HttpServletResponse response) {
        response.setStatus(302);
        response.setHeader("Location", url);
        Map<String, Object> out = new HashMap<>();
        out.put("redirectingTo", url);
        return out;
    }

    // OWASP A03:2021 Injection (Host Header Injection) - trust Host header to build absolute URL
    @GetMapping("/reset-link")
    public Map<String, Object> resetLink(HttpServletRequest request) {
        String host = request.getHeader("Host");
        String link = "http://" + host + "/reset?token=abc123";
        Map<String, Object> out = new HashMap<>();
        out.put("resetLink", link);
        return out;
    }

    // OWASP A03:2021 Injection (Host Header Injection) - trust X-Forwarded-Host header
    @GetMapping("/absolute-url")
    public Map<String, Object> absoluteUrl(
            @RequestHeader(value = "X-Forwarded-Host", required = false) String xfh) {
        String base = "https://" + xfh + "/dashboard";
        Map<String, Object> out = new HashMap<>();
        out.put("absoluteUrl", base);
        return out;
    }

    // OWASP A03:2021 Injection (Cookie injection / CRLF) - cookie value from param unencoded
    @GetMapping("/set-cookie")
    public Map<String, Object> setCookie(@RequestParam String name, @RequestParam String value,
            HttpServletResponse response) {
        Cookie cookie = new Cookie(name, value);
        response.addCookie(cookie);
        Map<String, Object> out = new HashMap<>();
        out.put("cookie", name + "=" + value);
        return out;
    }

    // OWASP A03:2021 Injection (Header injection) - Content-Disposition filename from param
    @GetMapping("/download")
    public Map<String, Object> download(@RequestParam String filename, HttpServletResponse response) {
        response.setHeader("Content-Disposition", "attachment; filename=" + filename);
        response.setContentType("application/octet-stream");
        Map<String, Object> out = new HashMap<>();
        out.put("filename", filename);
        return out;
    }

    // OWASP A03:2021 Injection (Header injection) - Content-Type from param
    @GetMapping("/content-type")
    public Map<String, Object> contentType(@RequestParam String type, HttpServletResponse response) {
        response.setHeader("Content-Type", type);
        Map<String, Object> out = new HashMap<>();
        out.put("contentType", type);
        return out;
    }

    // OWASP A05:2021 Security Misconfiguration (Cache Poisoning) - body varies by unkeyed header
    @GetMapping("/cache")
    public Map<String, Object> cache(
            @RequestHeader(value = "X-Forwarded-Host", required = false) String xfh,
            HttpServletResponse response) {
        response.setHeader("Cache-Control", "public, max-age=600");
        Map<String, Object> out = new HashMap<>();
        out.put("resourceHost", xfh);
        out.put("content", "<link href='//" + xfh + "/app.css'>");
        return out;
    }

    // OWASP A03:2021 Injection (Header injection) - Link header from param
    @GetMapping("/link-header")
    public Map<String, Object> linkHeader(@RequestParam String rel, HttpServletResponse response) {
        response.addHeader("Link", "<" + rel + ">; rel=preload");
        Map<String, Object> out = new HashMap<>();
        out.put("link", rel);
        return out;
    }

    // OWASP A03:2021 Injection (Header injection) - Refresh header from param, reflect XFF
    @GetMapping("/refresh")
    public Map<String, Object> refresh(@RequestParam String target,
            @RequestHeader(value = "X-Forwarded-For", required = false) String xff,
            HttpServletResponse response) {
        response.setHeader("Refresh", "0; url=" + target);
        response.setHeader("X-Client-IP", xff);
        Map<String, Object> out = new HashMap<>();
        out.put("refreshTo", target);
        out.put("clientIp", xff);
        return out;
    }
}
