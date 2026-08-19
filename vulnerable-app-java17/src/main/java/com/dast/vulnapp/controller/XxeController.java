package com.dast.vulnapp.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

/**
 * INTENTIONALLY VULNERABLE controller — XML External Entity (XXE) test target.
 * OWASP A05:2021 Security Misconfiguration / A03:2021 Injection.
 * The DocumentBuilderFactory / SAXParserFactory are deliberately NOT hardened:
 * DOCTYPE declarations and external general entities are left enabled.
 */
@RestController
@RequestMapping("/api/xxe")
public class XxeController {

    // Helper: build a DOM parser with NO XXE protections (external entities enabled).
    private Document parseUnsafe(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // VULNERABLE: no disallow-doctype-decl, no disabling of external-general-entities.
        dbf.setExpandEntityReferences(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new InputSource(new StringReader(xml)));
    }

    private String textOf(Document doc) {
        doc.getDocumentElement().normalize();
        return doc.getDocumentElement().getTextContent();
    }

    // OWASP A05:2021 - XXE via raw XML request body parsed with an unhardened parser.
    @PostMapping("/parse")
    public String parseBody(@RequestBody String xml) {
        try {
            Document doc = parseUnsafe(xml);
            // Return text so external-entity expansion is observable.
            return "Parsed: " + textOf(doc);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - XXE via uploaded XML file (MultipartFile), parser unhardened.
    @PostMapping("/upload")
    public String parseUpload(@RequestParam("file") MultipartFile file) {
        try {
            String xml = new String(file.getBytes(), StandardCharsets.UTF_8);
            Document doc = parseUnsafe(xml);
            return "Parsed upload: " + textOf(doc);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - SOAP-style endpoint parsing untrusted XML with external entities enabled.
    @PostMapping(value = "/soap", consumes = "text/xml")
    public String soap(@RequestBody String soapXml) {
        try {
            Document doc = parseUnsafe(soapXml);
            NodeList bodies = doc.getElementsByTagName("Body");
            String content = bodies.getLength() > 0 ? bodies.item(0).getTextContent() : textOf(doc);
            return "<response>" + content + "</response>";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A03:2021 - XML-to-JSON conversion; external entities resolved during parse.
    @PostMapping("/to-json")
    public String toJson(@RequestBody String xml) {
        try {
            Document doc = parseUnsafe(xml);
            String root = doc.getDocumentElement().getNodeName();
            String value = textOf(doc);
            // Naive JSON build echoing expanded entity content.
            return "{\"root\":\"" + root + "\",\"value\":\"" + value.replace("\"", "\\\"") + "\"}";
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    // OWASP A05:2021 - RSS/feed import; SAX parser without any XXE hardening.
    @PostMapping("/feed")
    public String importFeed(@RequestBody String rssXml) {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            // VULNERABLE: no feature toggles to disable DOCTYPE / external entities.
            SAXParser parser = spf.newSAXParser();
            final StringBuilder sb = new StringBuilder();
            parser.parse(new ByteArrayInputStream(rssXml.getBytes(StandardCharsets.UTF_8)),
                    new org.xml.sax.helpers.DefaultHandler() {
                        @Override
                        public void characters(char[] ch, int start, int length) {
                            sb.append(ch, start, length);
                        }
                    });
            return "Imported feed content: " + sb;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - SVG upload parsed as XML (SVG may embed DOCTYPE/entities).
    @PostMapping("/svg")
    public String parseSvg(@RequestParam("file") MultipartFile file) {
        try {
            String svg = new String(file.getBytes(), StandardCharsets.UTF_8);
            Document doc = parseUnsafe(svg);
            return "Parsed SVG title/text: " + textOf(doc);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A05:2021 - XML config import parsed with an unhardened DOM parser.
    @PutMapping("/config")
    public String importConfig(@RequestBody String configXml) {
        try {
            Document doc = parseUnsafe(configXml);
            NodeList settings = doc.getElementsByTagName("setting");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < settings.getLength(); i++) {
                sb.append(settings.item(i).getTextContent()).append(";");
            }
            if (sb.length() == 0) sb.append(textOf(doc));
            return "Applied config: " + sb;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // OWASP A03:2021 - XML search query parsed unsafely; entity-expanded value echoed back.
    @PostMapping("/search")
    public String search(@RequestBody String queryXml) {
        try {
            Document doc = parseUnsafe(queryXml);
            NodeList terms = doc.getElementsByTagName("term");
            String term = terms.getLength() > 0 ? terms.item(0).getTextContent() : textOf(doc);
            return "Search results for: " + term;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
