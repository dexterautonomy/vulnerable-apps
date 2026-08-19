package com.dast.vulnapp.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * INTENTIONALLY VULNERABLE controller for DAST scanner testing.
 * Path Traversal / Local File Inclusion (LFI) sink collection.
 */
@RestController
@RequestMapping("/api/files")
public class PathTraversalController {

    private static final String BASE_DIR = "uploads/";

    private final JdbcTemplate jdbcTemplate;

    public PathTraversalController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public static class WriteRequest {
        public String filename;
        public String content;
    }

    // OWASP A01:2021 Path Traversal - read file by name concatenated onto base dir
    @GetMapping("/read")
    public String readFile(@RequestParam("name") String name) {
        try {
            Path p = Paths.get(BASE_DIR + name);
            return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 LFI - download by fully user-supplied path param
    @GetMapping("/download")
    public ResponseEntity<byte[]> download(@RequestParam("path") String path) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(path));
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", new File(path).getName());
            return ResponseEntity.ok().headers(headers).body(data);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
        }
    }

    // OWASP A01:2021 Path Traversal - view document: filepath from DB then read from disk
    @GetMapping("/view-document")
    public String viewDocument(@RequestParam("id") int id) {
        try {
            String filepath = jdbcTemplate.queryForObject(
                    "SELECT filepath FROM documents WHERE id = " + id, String.class);
            return new String(Files.readAllBytes(Paths.get(filepath)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - delete file by name with no normalization
    @DeleteMapping("/delete")
    public String deleteFile(@RequestParam("name") String name) {
        try {
            Path p = Paths.get(BASE_DIR + name);
            boolean deleted = Files.deleteIfExists(p);
            return "Deleted=" + deleted + " path=" + p.toAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - list directory contents by user path param
    @GetMapping("/list")
    public String listDirectory(@RequestParam("dir") String dir) {
        try (Stream<Path> stream = Files.list(Paths.get(dir))) {
            List<String> entries = stream.map(Path::toString).collect(Collectors.toList());
            return String.join("\n", entries);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - write file by name+content with no validation
    @PostMapping("/write")
    public String writeFile(@RequestBody WriteRequest req) {
        try {
            Path p = Paths.get(BASE_DIR + req.filename);
            if (p.getParent() != null) {
                Files.createDirectories(p.getParent());
            }
            Files.write(p, req.content.getBytes(StandardCharsets.UTF_8));
            return "Wrote " + req.content.length() + " bytes to " + p.toAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 LFI - include/render a file inline by path
    @GetMapping("/include")
    public String includeFile(@RequestParam("template") String template) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(BASE_DIR + template)), StandardCharsets.UTF_8);
            return "<html><body>" + content + "</body></html>";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - serve static asset by unvalidated path
    @GetMapping("/static")
    public ResponseEntity<byte[]> serveStatic(@RequestParam("resource") String resource) {
        try {
            byte[] data = Files.readAllBytes(Paths.get("static/" + resource));
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
        }
    }

    // OWASP A01:2021 Path Traversal - read log file by name
    @GetMapping("/logs")
    public String readLog(@RequestParam("logName") String logName) {
        try {
            Path p = Paths.get("logs/" + logName);
            return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - get file size by arbitrary path
    @GetMapping("/size")
    public String fileSize(@RequestParam("path") String path) {
        try {
            long size = Files.size(Paths.get(path));
            return "Size of " + path + " = " + size + " bytes";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - copy file from src to dst, both user-controlled
    @PostMapping("/copy")
    public String copyFile(@RequestParam("src") String src, @RequestParam("dst") String dst) {
        try {
            Path source = Paths.get(src);
            Path target = Paths.get(dst);
            Files.copy(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            return "Copied " + source.toAbsolutePath() + " -> " + target.toAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 Path Traversal - read using filename from documents table
    @GetMapping("/read-by-doc-filename")
    public String readByDocFilename(@RequestParam("id") int id) {
        try {
            String filename = jdbcTemplate.queryForObject(
                    "SELECT filename FROM documents WHERE id = " + id, String.class);
            Path p = Paths.get(BASE_DIR + filename);
            return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
