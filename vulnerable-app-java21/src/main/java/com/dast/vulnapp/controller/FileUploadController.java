package com.dast.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * INTENTIONALLY VULNERABLE controller — insecure file upload test target.
 * OWASP A01:2021 Broken Access Control / A05:2021 Security Misconfiguration /
 * A08:2021 Software and Data Integrity Failures.
 * No validation is performed: no path sanitisation, no content-type check,
 * no size limit, no extension allow-list.
 */
@RestController
@RequestMapping("/api/upload")
public class FileUploadController {

    // Directory that is also served statically by the web server (RCE/stored-XSS surface).
    private static final String UPLOAD_DIR = System.getProperty("java.io.tmpdir") + File.separator + "vulnapp_uploads";
    private static final String WEB_DIR = System.getProperty("java.io.tmpdir") + File.separator + "vulnapp_web";

    private final JdbcTemplate jdbc;

    public FileUploadController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        new File(UPLOAD_DIR).mkdirs();
        new File(WEB_DIR).mkdirs();
    }

    private void saveMeta(String filename, String filepath) {
        try {
            jdbc.update("INSERT INTO documents (owner_id, filename, filepath, content, is_public) VALUES (?,?,?,?,?)",
                    1, filename, filepath, "", true);
        } catch (Exception ignored) {
            // Table may not exist in some test runs; ignore for metadata persistence.
        }
    }

    // OWASP A01:2021 - Path traversal: saves using the client-supplied original filename.
    @PostMapping("/save")
    public String save(@RequestParam("file") MultipartFile file) {
        try {
            // VULNERABLE: original filename may contain ../ sequences — no sanitisation.
            String name = file.getOriginalFilename();
            File dest = new File(UPLOAD_DIR + File.separator + name);
            file.transferTo(dest.getAbsoluteFile());
            saveMeta(name, dest.getAbsolutePath());
            return "Saved to: " + dest.getAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - No content-type / MIME validation before storing the file.
    @PostMapping("/raw")
    public String raw(@RequestParam("file") MultipartFile file) {
        try {
            // VULNERABLE: content-type is ignored; any payload is written to disk.
            String name = file.getOriginalFilename();
            File dest = new File(UPLOAD_DIR + File.separator + name);
            try (FileOutputStream fos = new FileOutputStream(dest)) {
                fos.write(file.getBytes());
            }
            saveMeta(name, dest.getAbsolutePath());
            return "Stored (content-type ignored): " + name;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - No size limit and no extension allow-list (.jsp/.php/.svg/.html accepted).
    @PostMapping("/unrestricted")
    public String unrestricted(@RequestParam("file") MultipartFile file) {
        try {
            // VULNERABLE: executable/script extensions accepted, no max-size enforcement.
            String name = file.getOriginalFilename();
            File dest = new File(UPLOAD_DIR + File.separator + name);
            file.transferTo(dest.getAbsoluteFile());
            saveMeta(name, dest.getAbsolutePath());
            return "Accepted any extension/size: " + name + " (" + file.getSize() + " bytes)";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Stores upload into a web-served directory (direct RCE/stored-XSS surface).
    @PostMapping("/web")
    public String web(@RequestParam("file") MultipartFile file) {
        try {
            // VULNERABLE: file written into a publicly served web root, executable as-is.
            String name = file.getOriginalFilename();
            File dest = new File(WEB_DIR + File.separator + name);
            file.transferTo(dest.getAbsoluteFile());
            saveMeta(name, dest.getAbsolutePath());
            return "Available at /files/" + name;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 - Serves an uploaded file back by name (path traversal + stored XSS/RCE).
    @GetMapping("/serve")
    public String serve(@RequestParam("name") String name) {
        try {
            // VULNERABLE: no path canonicalisation — ../ escapes the upload dir.
            File f = new File(WEB_DIR + File.separator + name);
            byte[] data = Files.readAllBytes(f.toPath());
            return new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 - Zip extraction without zip-slip protection (arbitrary file write).
    @PostMapping("/unzip")
    public String unzip(@RequestParam("file") MultipartFile file) {
        StringBuilder extracted = new StringBuilder();
        try (ZipInputStream zis = new ZipInputStream(file.getInputStream())) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // VULNERABLE: entry name used directly — "../" escapes UPLOAD_DIR (zip slip).
                File out = new File(UPLOAD_DIR + File.separator + entry.getName());
                if (entry.isDirectory()) {
                    out.mkdirs();
                } else {
                    out.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        byte[] buf = new byte[4096];
                        int n;
                        while ((n = zis.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    extracted.append(out.getAbsolutePath()).append(";");
                }
                zis.closeEntry();
            }
            return "Extracted: " + extracted;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 - Avatar upload writing to an arbitrary path from a request param.
    @PostMapping("/avatar")
    public String avatar(@RequestParam("file") MultipartFile file, @RequestParam("path") String path) {
        try {
            // VULNERABLE: caller fully controls destination path — write anywhere.
            File dest = new File(path);
            if (dest.getParentFile() != null) dest.getParentFile().mkdirs();
            try (FileOutputStream fos = new FileOutputStream(dest)) {
                fos.write(file.getBytes());
            }
            saveMeta(file.getOriginalFilename(), dest.getAbsolutePath());
            return "Avatar written to: " + dest.getAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 - Replace a stored file by document id with no ownership/type checks.
    @PutMapping("/replace/{id}")
    public String replace(@PathVariable("id") int id, @RequestParam("file") MultipartFile file) {
        try {
            String path;
            try {
                path = jdbc.queryForObject("SELECT filepath FROM documents WHERE id = ?", String.class, id);
            } catch (Exception ex) {
                // Fall back to id-named file if metadata lookup fails.
                path = UPLOAD_DIR + File.separator + id + "_" + file.getOriginalFilename();
            }
            // VULNERABLE: no access control, no validation — overwrites target file.
            File dest = new File(path);
            try (FileOutputStream fos = new FileOutputStream(dest)) {
                fos.write(file.getBytes());
            }
            return "Replaced document " + id + " at " + dest.getAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - Bulk upload; every file stored with its client-supplied name, no checks.
    @PostMapping("/bulk")
    public String bulk(@RequestParam("files") MultipartFile[] files) {
        StringBuilder sb = new StringBuilder();
        try {
            for (MultipartFile f : files) {
                // VULNERABLE: each original filename trusted; no per-file validation.
                String name = f.getOriginalFilename();
                File dest = new File(UPLOAD_DIR + File.separator + name);
                f.transferTo(dest.getAbsoluteFile());
                saveMeta(name, dest.getAbsolutePath());
                sb.append(name).append(";");
            }
            return "Uploaded: " + sb;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A08:2021 - Upload from base64 payload with caller-controlled filename.
    @PostMapping("/base64")
    public String base64Upload(@RequestParam("filename") String filename, @RequestBody String base64) {
        try {
            byte[] data = Base64.getDecoder().decode(base64.trim());
            // VULNERABLE: filename unsanitised, bytes decoded and written verbatim.
            File dest = new File(UPLOAD_DIR + File.separator + filename);
            try (FileOutputStream fos = new FileOutputStream(dest)) {
                fos.write(data);
            }
            saveMeta(filename, dest.getAbsolutePath());
            return "Decoded and saved: " + dest.getAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - Overwrite an existing file by name with no confirmation/validation.
    @PostMapping("/overwrite")
    public String overwrite(@RequestParam("file") MultipartFile file, @RequestParam("target") String target) {
        try {
            // VULNERABLE: silently overwrites arbitrary named target within served dir.
            File dest = new File(WEB_DIR + File.separator + target);
            try (FileOutputStream fos = new FileOutputStream(dest, false)) {
                fos.write(file.getBytes());
            }
            saveMeta(target, dest.getAbsolutePath());
            return "Overwrote: " + dest.getAbsolutePath();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A03:2021 - Reflects the uploaded filename into an HTML response (reflected XSS).
    @PostMapping(value = "/reflect", produces = "text/html")
    public String reflect(@RequestParam("file") MultipartFile file) {
        try {
            String name = file.getOriginalFilename();
            File dest = new File(UPLOAD_DIR + File.separator + name);
            file.transferTo(dest.getAbsoluteFile());
            saveMeta(name, dest.getAbsolutePath());
            // VULNERABLE: filename echoed into HTML without encoding.
            return "<html><body>Uploaded file: " + name + "</body></html>";
        } catch (Exception e) {
            return "<html><body>Error: " + e.getMessage() + "</body></html>";
        }
    }

    // OWASP A01:2021 - Returns the absolute stored path of a file (server path info leak).
    @GetMapping("/stored-path")
    public String storedPath(@RequestParam("name") String name) {
        try {
            // VULNERABLE: leaks internal absolute filesystem paths to the client.
            File f = new File(UPLOAD_DIR + File.separator + name);
            InputStream in = new FileInputStream(f);
            long size = f.length();
            in.close();
            return "Stored at: " + f.getAbsolutePath() + " (" + size + " bytes)";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A01:2021 - Deletes an uploaded file by name with no auth or path checks.
    @DeleteMapping("/delete")
    public String delete(@RequestParam("name") String name) {
        try {
            // VULNERABLE: no path canonicalisation — ../ allows deleting arbitrary files.
            File f = new File(UPLOAD_DIR + File.separator + name);
            boolean deleted = f.delete();
            return "Deleted " + name + ": " + deleted;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
