package com.dast.vulnapp.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Server-Side Request Forgery (SSRF) sink collection.
 */
@RestController
@RequestMapping("/api/ssrf")
public class SsrfController {

    private final RestTemplate restTemplate;

    public SsrfController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public static class WebhookRequest {
        public String url;
        public String payload;
    }

    // OWASP A10:2021 Server-Side Request Forgery - fetch arbitrary user-supplied URL
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam("url") String url) {
        try {
            return restTemplate.getForObject(url, String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP API7:2023 SSRF - POST a payload to any user-supplied webhook URL
    @PostMapping("/webhook")
    public String postWebhook(@RequestBody WebhookRequest req) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> entity = new HttpEntity<>(req.payload, headers);
            return restTemplate.postForObject(req.url, entity, String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - image proxy fetches raw bytes from any user-supplied URL
    @GetMapping("/image-proxy")
    public ResponseEntity<byte[]> imageProxy(@RequestParam("url") String url) {
        try {
            byte[] data = restTemplate.getForObject(url, byte[].class);
            return ResponseEntity.ok().contentType(MediaType.IMAGE_JPEG).body(data);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
        }
    }

    // OWASP A10:2021 SSRF - PDF proxy streams any user-supplied URL server-side
    @GetMapping("/pdf-proxy")
    public ResponseEntity<byte[]> pdfProxy(@RequestParam("url") String url) {
        try {
            byte[] data = restTemplate.getForObject(url, byte[].class);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF).body(data);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
        }
    }

    // OWASP A10:2021 SSRF - URL preview/metadata fetch of arbitrary target
    @GetMapping("/url-preview")
    public String urlPreview(@RequestParam("target") String target) {
        try {
            URL u = new URL(target);
            URLConnection conn = u.openConnection();
            Map<String, Object> meta = new HashMap<>();
            meta.put("contentType", conn.getContentType());
            meta.put("contentLength", conn.getContentLength());
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                int count = 0;
                while ((line = br.readLine()) != null && count++ < 20) {
                    sb.append(line).append("\n");
                }
            }
            return "META: " + meta + "\nBODY:\n" + sb;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - import data from a remote user-supplied URL
    @PostMapping("/import")
    public String importFromUrl(@RequestParam("source") String source) {
        try {
            String body = restTemplate.getForObject(source, String.class);
            return "Imported " + (body == null ? 0 : body.length()) + " bytes from " + source + "\n" + body;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - fetch avatar image from user-controlled URL
    @PostMapping("/avatar")
    public String avatarFromUrl(@RequestParam("avatarUrl") String avatarUrl) {
        try {
            byte[] data = restTemplate.getForObject(avatarUrl, byte[].class);
            return "Downloaded avatar (" + (data == null ? 0 : data.length) + " bytes) from " + avatarUrl;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - check status of an arbitrary user-supplied URL
    @GetMapping("/check-status")
    public String checkStatus(@RequestParam("url") String url) {
        try {
            URL u = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(5000);
            int code = conn.getResponseCode();
            return "Status for " + url + ": " + code + " " + conn.getResponseMessage();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - fetch internal resource assembled from host + path
    @GetMapping("/internal")
    public String fetchInternal(@RequestParam("host") String host, @RequestParam("path") String path) {
        try {
            String url = "http://" + host + path;
            return restTemplate.getForObject(url, String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - follows redirects (including to internal targets)
    @GetMapping("/follow-redirects")
    public String followRedirects(@RequestParam("url") String url) {
        try {
            URL u = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setInstanceFollowRedirects(true);
            conn.setConnectTimeout(5000);
            StringBuilder sb = new StringBuilder();
            try (InputStream is = conn.getInputStream();
                 BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            }
            return "Final URL: " + conn.getURL() + "\n" + sb;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - cloud instance metadata fetch (169.254.169.254)
    @GetMapping("/cloud-metadata")
    public String cloudMetadata(@RequestParam(value = "endpoint", defaultValue = "http://169.254.169.254/latest/meta-data/") String endpoint) {
        try {
            return restTemplate.getForObject(endpoint, String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - allows file:// and gopher:// and other schemes
    @GetMapping("/fetch-scheme")
    public String fetchAnyScheme(@RequestParam("uri") String uri) {
        try {
            URL u = new URL(uri);
            URLConnection conn = u.openConnection();
            StringBuilder sb = new StringBuilder();
            try (InputStream is = conn.getInputStream();
                 BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A10:2021 SSRF - port scan style probe of arbitrary host:port
    @GetMapping("/port-scan")
    public String portScan(@RequestParam("host") String host, @RequestParam("port") int port) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(addr, port), 3000);
                return "OPEN: " + host + ":" + port + " (resolved " + addr.getHostAddress() + ")";
            }
        } catch (Exception e) {
            return "CLOSED/ERROR: " + host + ":" + port + " - " + e.getMessage();
        }
    }
}
