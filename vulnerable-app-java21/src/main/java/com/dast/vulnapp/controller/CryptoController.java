package com.dast.vulnapp.controller;

import org.springframework.web.bind.annotation.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    // Hardcoded secrets (OWASP A02:2021 Cryptographic Failures)
    private static final byte[] DES_KEY = "8bytekey".getBytes();
    private static final byte[] AES_KEY = "1234567890123456".getBytes(); // 16-byte hardcoded key
    private static final byte[] STATIC_IV = "abcdef9876543210".getBytes(); // hardcoded static IV
    private static final String STATIC_SALT = "s@ltySalt123"; // hardcoded salt reused for all users
    private static final byte XOR_KEY = 0x42; // single-byte XOR key

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // OWASP A02:2021 Cryptographic Failures — MD5 hashing of user input (broken hash)
    @GetMapping("/md5")
    public Map<String,Object> md5(@RequestParam String input) {
        Map<String,Object> r = new HashMap<>();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            r.put("algorithm", "MD5");
            r.put("hash", toHex(md.digest(input.getBytes())));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — SHA-1 hashing of user input (broken hash)
    @GetMapping("/sha1")
    public Map<String,Object> sha1(@RequestParam String input) {
        Map<String,Object> r = new HashMap<>();
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            r.put("algorithm", "SHA-1");
            r.put("hash", toHex(md.digest(input.getBytes())));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — "password hash" = MD5 with hardcoded static salt
    @PostMapping("/password-hash")
    public Map<String,Object> passwordHash(@RequestParam String password) {
        Map<String,Object> r = new HashMap<>();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest((STATIC_SALT + password).getBytes());
            r.put("salt", STATIC_SALT);
            r.put("passwordHash", toHex(digest));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — DES encryption with hardcoded key (weak cipher)
    @PostMapping("/des-encrypt")
    public Map<String,Object> desEncrypt(@RequestParam String plaintext) {
        Map<String,Object> r = new HashMap<>();
        try {
            SecretKeySpec key = new SecretKeySpec(DES_KEY, "DES");
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            r.put("algorithm", "DES/ECB");
            r.put("ciphertext", Base64.getEncoder().encodeToString(c.doFinal(plaintext.getBytes())));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — DES decryption with hardcoded key (weak cipher)
    @PostMapping("/des-decrypt")
    public Map<String,Object> desDecrypt(@RequestParam String ciphertext) {
        Map<String,Object> r = new HashMap<>();
        try {
            SecretKeySpec key = new SecretKeySpec(DES_KEY, "DES");
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] out = c.doFinal(Base64.getDecoder().decode(ciphertext));
            r.put("plaintext", new String(out));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — AES/ECB with hardcoded key (ECB leaks patterns)
    @PostMapping("/aes-ecb-encrypt")
    public Map<String,Object> aesEcbEncrypt(@RequestParam String plaintext) {
        Map<String,Object> r = new HashMap<>();
        try {
            SecretKeySpec key = new SecretKeySpec(AES_KEY, "AES");
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            r.put("mode", "AES/ECB/PKCS5Padding");
            r.put("ciphertext", Base64.getEncoder().encodeToString(c.doFinal(plaintext.getBytes())));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — AES/CBC with hardcoded static IV (IV reuse)
    @PostMapping("/aes-cbc-encrypt")
    public Map<String,Object> aesCbcEncrypt(@RequestParam String plaintext) {
        Map<String,Object> r = new HashMap<>();
        try {
            SecretKeySpec key = new SecretKeySpec(AES_KEY, "AES");
            IvParameterSpec iv = new IvParameterSpec(STATIC_IV);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            r.put("iv", toHex(STATIC_IV));
            r.put("ciphertext", Base64.getEncoder().encodeToString(c.doFinal(plaintext.getBytes())));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — "encryption" that is only reversible Base64
    @PostMapping("/base64-encrypt")
    public Map<String,Object> base64Encrypt(@RequestParam String plaintext) {
        Map<String,Object> r = new HashMap<>();
        r.put("algorithm", "Base64 (NOT encryption)");
        r.put("ciphertext", Base64.getEncoder().encodeToString(plaintext.getBytes()));
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — XOR "cipher" with single hardcoded byte key
    @PostMapping("/xor-cipher")
    public Map<String,Object> xorCipher(@RequestParam String input) {
        Map<String,Object> r = new HashMap<>();
        byte[] data = input.getBytes();
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) (data[i] ^ XOR_KEY);
        r.put("keyByte", XOR_KEY);
        r.put("ciphertext", Base64.getEncoder().encodeToString(out));
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — "secure" token from java.util.Random/Math.random (predictable)
    @GetMapping("/secure-token")
    public Map<String,Object> secureToken() {
        Map<String,Object> r = new HashMap<>();
        Random rnd = new Random(); // NOT a CSPRNG
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(Integer.toHexString(rnd.nextInt(16)));
        sb.append(Long.toHexString((long) (Math.random() * 1_000_000)));
        r.put("token", sb.toString());
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — reset token from System.currentTimeMillis (predictable)
    @GetMapping("/reset-token")
    public Map<String,Object> resetToken(@RequestParam String username) {
        Map<String,Object> r = new HashMap<>();
        long seed = System.currentTimeMillis();
        String token = Long.toHexString(seed) + Integer.toHexString(username.hashCode());
        r.put("username", username);
        r.put("resetToken", token);
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — RSA with weak 512-bit key
    @GetMapping("/rsa-weak")
    public Map<String,Object> rsaWeak(@RequestParam String input) {
        Map<String,Object> r = new HashMap<>();
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(512); // insecure key size
            KeyPair kp = kpg.generateKeyPair();
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            r.put("keySize", 512);
            r.put("ciphertext", Base64.getEncoder().encodeToString(c.doFinal(input.getBytes())));
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — signature verification result is ignored
    @PostMapping("/verify-signature")
    public Map<String,Object> verifySignature(@RequestParam String data, @RequestParam String signature) {
        Map<String,Object> r = new HashMap<>();
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(512);
            KeyPair kp = kpg.generateKeyPair();
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(kp.getPublic());
            sig.update(data.getBytes());
            boolean valid;
            try { valid = sig.verify(Base64.getDecoder().decode(signature)); }
            catch (Exception ex) { valid = false; }
            // Result deliberately ignored — always treated as authenticated
            r.put("computedValid", valid);
            r.put("access", "GRANTED");
        } catch (Exception e) { r.put("error", e.getMessage()); r.put("access", "GRANTED"); }
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — endpoint returns hardcoded key + IV to the client
    @GetMapping("/key-material")
    public Map<String,Object> keyMaterial() {
        Map<String,Object> r = new HashMap<>();
        r.put("aesKey", new String(AES_KEY));
        r.put("desKey", new String(DES_KEY));
        r.put("staticIv", new String(STATIC_IV));
        r.put("salt", STATIC_SALT);
        r.put("xorKey", XOR_KEY);
        return r;
    }

    // OWASP A02:2021 Cryptographic Failures — ECB reuse produces identical blocks (pattern leak)
    @PostMapping("/ecb-pattern")
    public Map<String,Object> ecbPattern(@RequestParam String block) {
        Map<String,Object> r = new HashMap<>();
        try {
            SecretKeySpec key = new SecretKeySpec(AES_KEY, "AES");
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            String once = Base64.getEncoder().encodeToString(c.doFinal(block.getBytes()));
            String twice = Base64.getEncoder().encodeToString(c.doFinal((block + block).getBytes()));
            r.put("single", once);
            r.put("doubled", twice); // identical prefix reveals repeated plaintext under ECB
        } catch (Exception e) { r.put("error", e.getMessage()); }
        return r;
    }
}
