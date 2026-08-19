package com.dast.vulnapp.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.Base64;

/**
 * INTENTIONALLY VULNERABLE controller — insecure deserialization test target.
 * OWASP A08:2021 - Software and Data Integrity Failures (Insecure Deserialization).
 */
@RestController
@RequestMapping("/api/deser")
public class DeserializationController {

    // Small concrete Serializable DTO to make ObjectInputStream usage real.
    public static class UserSession implements Serializable {
        private static final long serialVersionUID = 1L;
        public String username;
        public String role;
        public long expiresAt;

        @Override
        public String toString() {
            return "UserSession{username=" + username + ", role=" + role + ", expiresAt=" + expiresAt + "}";
        }
    }

    public static class SavedState implements Serializable {
        private static final long serialVersionUID = 2L;
        public String data;
        public int version;
    }

    // OWASP A08:2021 - Native Java deserialization of base64 request body (untrusted).
    @PostMapping("/java/body")
    public String deserBody(@RequestBody String base64) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64.trim());
            // VULNERABLE: readObject on untrusted stream — no look-ahead / allow-list.
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Native Java deserialization from request parameter.
    @GetMapping("/java/param")
    public String deserParam(@RequestParam("data") String data) {
        try {
            byte[] bytes = Base64.getDecoder().decode(data);
            // VULNERABLE: untrusted param deserialized directly.
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Native Java deserialization from HTTP header.
    @GetMapping("/java/header")
    public String deserHeader(@RequestHeader("X-Serialized-Object") String header) {
        try {
            byte[] bytes = Base64.getDecoder().decode(header);
            // VULNERABLE: attacker-controlled header deserialized.
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized from header: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - "Session restore" from base64 cookie via native deserialization.
    @GetMapping("/java/cookie")
    public String deserCookie(HttpServletRequest request) {
        try {
            String value = null;
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie c : cookies) {
                    if ("session_state".equals(c.getName())) {
                        value = c.getValue();
                    }
                }
            }
            if (value == null) return "No session_state cookie";
            byte[] bytes = Base64.getDecoder().decode(value);
            // VULNERABLE: session cookie is deserialized without validation.
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();
            return "Restored session: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Native Java deserialization of uploaded file contents.
    @PostMapping("/java/upload")
    public String deserUpload(@RequestParam("file") MultipartFile file) {
        try {
            // VULNERABLE: uploaded bytes deserialized directly.
            ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized upload: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Native Java deserialization from a server file path param.
    @GetMapping("/java/file")
    public String deserFile(@RequestParam("path") String path) {
        try {
            // VULNERABLE: reads and deserializes an arbitrary file path.
            FileInputStream fis = new FileInputStream(path);
            ObjectInputStream ois = new ObjectInputStream(fis);
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized file: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Native Java deserialization from a remote URL.
    @GetMapping("/java/url")
    public String deserUrl(@RequestParam("url") String url) {
        try {
            // VULNERABLE: fetches a remote serialized object and deserializes it.
            URL u = new URL(url);
            InputStream in = u.openStream();
            ObjectInputStream ois = new ObjectInputStream(in);
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized remote: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Jackson polymorphic typing via activateDefaultTyping (gadget surface).
    @PostMapping("/jackson/default-typing")
    public String jacksonDefaultTyping(@RequestBody String userJson) {
        try {
            ObjectMapper om = new ObjectMapper();
            // VULNERABLE: default typing on NON_FINAL enables polymorphic gadget deserialization.
            om.activateDefaultTyping(om.getPolymorphicTypeValidator(),
                    ObjectMapper.DefaultTyping.NON_FINAL);
            Object obj = om.readValue(userJson, Object.class);
            return "Jackson deserialized: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Jackson enableDefaultTyping (legacy) unsafe polymorphic typing.
    @PostMapping("/jackson/enable-default")
    @SuppressWarnings("deprecation")
    public String jacksonEnableDefault(@RequestBody String userJson) {
        try {
            ObjectMapper om = new ObjectMapper();
            // VULNERABLE: legacy enableDefaultTyping — no type validator at all.
            om.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            Object obj = om.readValue(userJson, Object.class);
            return "Jackson (legacy) deserialized: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Native Java deserialization from base64 param into whitelist-less readObject.
    @PostMapping("/java/state-restore")
    public String stateRestore(@RequestParam("state") String state) {
        try {
            byte[] bytes = Base64.getDecoder().decode(state);
            // VULNERABLE: no ObjectInputFilter / no class allow-list.
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();
            if (obj instanceof SavedState) {
                return "Restored state v" + ((SavedState) obj).version;
            }
            return "Restored: " + obj;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
