package com.dast.vulnapp.controller;

import javax.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Open Redirect sink collection (OWASP A01:2021).
 */
@RestController
@RequestMapping("/api/redirect")
public class OpenRedirectController {

    // OWASP A01:2021 Open Redirect - redirect to unvalidated user-supplied url
    @GetMapping("/go")
    public void go(@RequestParam("url") String url, HttpServletResponse response) {
        try {
            response.sendRedirect(url);
        } catch (Exception e) {
            response.setStatus(500);
        }
    }

    // OWASP A01:2021 Open Redirect - "out" bounce link to arbitrary destination
    @GetMapping("/out")
    public void out(@RequestParam("to") String to, HttpServletResponse response) {
        try {
            response.sendRedirect(to);
        } catch (Exception e) {
            response.setStatus(500);
        }
    }

    // OWASP A01:2021 Open Redirect - post-login redirect to unvalidated next param
    @GetMapping("/login")
    public ResponseEntity<Void> loginRedirect(@RequestParam("next") String next) {
        return ResponseEntity.status(302).location(URI.create(next)).build();
    }

    // OWASP A01:2021 Open Redirect - logout returnTo redirect to arbitrary url
    @GetMapping("/logout")
    public ResponseEntity<Void> logoutRedirect(@RequestParam("returnTo") String returnTo) {
        return ResponseEntity.status(302).location(URI.create(returnTo)).build();
    }

    // OWASP A01:2021 Open Redirect - click tracking redirect to arbitrary target
    @GetMapping("/click")
    public void clickTracking(@RequestParam("target") String target, HttpServletResponse response) {
        try {
            response.sendRedirect(target);
        } catch (Exception e) {
            response.setStatus(500);
        }
    }

    // OWASP A01:2021 Open Redirect - OAuth callback trusts redirect_uri blindly
    @GetMapping("/oauth-callback")
    public ResponseEntity<Void> oauthCallback(@RequestParam("redirect_uri") String redirectUri,
                                              @RequestParam(value = "code", required = false) String code) {
        return ResponseEntity.status(302).location(URI.create(redirectUri)).build();
    }

    // OWASP A01:2021 Open Redirect - Location header set directly from user param
    @GetMapping("/header")
    public void headerRedirect(@RequestParam("dest") String dest, HttpServletResponse response) {
        response.setStatus(302);
        response.setHeader("Location", dest);
    }

    // OWASP A01:2021 Open Redirect - meta refresh HTML pointing at user-supplied url
    @GetMapping(value = "/meta-refresh", produces = MediaType.TEXT_HTML_VALUE)
    public String metaRefresh(@RequestParam("url") String url) {
        return "<html><head><meta http-equiv=\"refresh\" content=\"0; url=" + url + "\">"
                + "</head><body>Redirecting to " + url + "...</body></html>";
    }
}
