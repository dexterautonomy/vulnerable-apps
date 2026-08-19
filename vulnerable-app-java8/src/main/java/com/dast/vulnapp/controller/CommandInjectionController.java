package com.dast.vulnapp.controller;

import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/cmd")
public class CommandInjectionController {

    private String readProcess(Process p) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (InputStream is = p.getInputStream(); InputStream es = p.getErrorStream()) {
            sb.append(IOUtils.toString(is, StandardCharsets.UTF_8));
            sb.append(IOUtils.toString(es, StandardCharsets.UTF_8));
        }
        p.waitFor();
        return sb.toString();
    }

    // OWASP A03:2021 Injection — OS command injection: ping host concatenated
    @GetMapping("/ping")
    public String ping(@RequestParam String host) {
        try {
            Process p = Runtime.getRuntime().exec("ping " + host);
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: nslookup domain via cmd /c
    @GetMapping("/nslookup")
    public String nslookup(@RequestParam String domain) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "nslookup " + domain});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: traceroute host
    @GetMapping("/traceroute")
    public String traceroute(@RequestParam String host) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "tracert " + host});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: whois domain
    @GetMapping("/whois")
    public String whois(@RequestParam String domain) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "whois " + domain});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: dns lookup with host tool
    @GetMapping("/dns")
    public String dns(@RequestParam String name) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "host " + name});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: zip/backup a path
    @PostMapping("/backup")
    public String backup(@RequestParam String path) {
        try {
            Process p = new ProcessBuilder("sh", "-c", "zip -r /tmp/backup.zip " + path).start();
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: convert a file
    @PostMapping("/convert")
    public String convert(@RequestParam String input, @RequestParam String output) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "convert " + input + " " + output});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: tail a log file
    @GetMapping("/tail-log")
    public String tailLog(@RequestParam String logfile) {
        try {
            Process p = new ProcessBuilder("sh", "-c", "tail -n 100 " + logfile).start();
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: disk usage of a path
    @GetMapping("/disk-usage")
    public String diskUsage(@RequestParam String path) {
        try {
            Process p = new ProcessBuilder("sh", "-c", "du -sh " + path).start();
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: curl a url
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "curl " + url});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: run a maintenance script by name
    @PostMapping("/maintenance")
    public String maintenance(@RequestParam String script) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "scripts\\" + script});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: ffmpeg-style transcode
    @PostMapping("/transcode")
    public String transcode(@RequestParam String input, @RequestParam String format) {
        try {
            Process p = new ProcessBuilder("sh", "-c", "ffmpeg -i " + input + " out." + format).start();
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: echo text to a file
    @PostMapping("/echo-to-file")
    public String echoToFile(@RequestParam String text, @RequestParam String file) {
        try {
            Process p = new ProcessBuilder("sh", "-c", "echo " + text + " > " + file).start();
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // OWASP A03:2021 Injection — OS command injection: generic exec param
    @PostMapping("/exec")
    public String exec(@RequestParam String command) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", command});
            return readProcess(p);
        } catch (Exception e) {
            return e.getMessage();
        }
    }

}
