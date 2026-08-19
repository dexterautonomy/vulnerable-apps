package com.dast.vulnapp.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * INTENTIONALLY VULNERABLE controller (DAST test target).
 * Demonstrates Broken Object Level Authorization / IDOR (OWASP API1:2023).
 * Every endpoint operates on a resource id supplied by the caller and NEVER
 * verifies that the "current user" (spoofable X-User-Id header) owns the
 * resource. All access-control checks are deliberately absent.
 */
@RestController
@RequestMapping("/api/bola")
public class BrokenObjectLevelAuthController {

    private final JdbcTemplate jdbc;

    public BrokenObjectLevelAuthController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ---- Inner DTOs -------------------------------------------------------

    public static class AccountUpdate {
        public String type;
        public Double balance;
        public String accountNumber;
    }

    public static class DocumentUpdate {
        public String filename;
        public String content;
        public Boolean isPublic;
    }

    public static class TransferRequest {
        public Long fromAccountId;
        public Long toAccountId;
        public Double amount;
    }

    public static class BalancePatch {
        public Double balance;
    }

    // ---- Endpoints --------------------------------------------------------

    // OWASP API1:2023 Broken Object Level Authorization.
    // Returns ANY account by id; ignores the caller identity entirely.
    @GetMapping("/accounts/{id}")
    public Object getAccountById(@PathVariable("id") Long id, HttpServletRequest req) {
        String caller = req.getHeader("X-User-Id"); // captured but never checked
        try {
            return jdbc.queryForMap("SELECT * FROM accounts WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("caller", String.valueOf(caller), "error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Leaks balance for any account_number with no ownership check.
    @GetMapping("/accounts/by-number/{accountNumber}")
    public Object getBalanceByAccountNumber(@PathVariable("accountNumber") String accountNumber,
                                            HttpServletRequest req) {
        try {
            return jdbc.queryForMap(
                "SELECT account_number, balance FROM accounts WHERE account_number = '"
                + accountNumber + "'");
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Returns any order by id regardless of who placed it.
    @GetMapping("/orders/{id}")
    public Object getOrderById(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap("SELECT * FROM orders WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Lists another user's orders simply by supplying their user_id.
    @GetMapping("/users/{userId}/orders")
    public Object getOrdersByUserId(@PathVariable("userId") Long userId, HttpServletRequest req) {
        try {
            return jdbc.queryForList("SELECT * FROM orders WHERE user_id = " + userId);
        } catch (Exception e) {
            return List.of(Map.of("error", e.getMessage()));
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Returns any document by id, including private ones (is_public ignored).
    @GetMapping("/documents/{id}")
    public Object getDocumentById(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap("SELECT * FROM documents WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Reads any private message by id with no participant check.
    @GetMapping("/messages/{id}")
    public Object getMessageById(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap("SELECT * FROM messages WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Deletes any message by id; caller need not own or receive it.
    @DeleteMapping("/messages/{id}")
    public Object deleteMessageById(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            int rows = jdbc.update("DELETE FROM messages WHERE id = " + id);
            return Map.of("deleted", rows, "id", id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Exposes another user's full profile including email and ssn.
    @GetMapping("/users/{id}/profile")
    public Object getUserProfile(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap(
                "SELECT id, username, email, role, ssn FROM users WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Returns any user's API key by id.
    @GetMapping("/users/{id}/api-key")
    public Object getUserApiKey(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap("SELECT id, username, api_key FROM users WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Updates any account by id with no ownership verification.
    @PutMapping("/accounts/{id}")
    public Object updateAccount(@PathVariable("id") Long id,
                                @RequestBody AccountUpdate body,
                                HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE accounts SET type = ?, balance = ?, account_number = ? WHERE id = ?",
                body.type, body.balance, body.accountNumber, id);
            return Map.of("updated", rows, "id", id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Deletes any order by id belonging to any user.
    @DeleteMapping("/orders/{id}")
    public Object deleteOrder(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            int rows = jdbc.update("DELETE FROM orders WHERE id = " + id);
            return Map.of("deleted", rows, "id", id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Transfers funds between arbitrary account ids owned by anyone.
    @PostMapping("/transfer")
    public Object transfer(@RequestBody TransferRequest body, HttpServletRequest req) {
        try {
            int debit = jdbc.update(
                "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                body.amount, body.fromAccountId);
            int credit = jdbc.update(
                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                body.amount, body.toAccountId);
            return Map.of("debited", debit, "credited", credit, "amount", body.amount);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Reveals any api_client secret by id regardless of ownership.
    @GetMapping("/api-clients/{id}/secret")
    public Object getApiClientSecret(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap(
                "SELECT id, client_id, client_secret, owner_id FROM api_clients WHERE id = " + id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Lists all documents for any owner_id supplied as a query param.
    @GetMapping("/documents")
    public Object listDocumentsByOwner(@RequestParam("ownerId") Long ownerId,
                                       HttpServletRequest req) {
        try {
            return jdbc.queryForList("SELECT * FROM documents WHERE owner_id = " + ownerId);
        } catch (Exception e) {
            return List.of(Map.of("error", e.getMessage()));
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Updates any document by id; caller need not be the owner.
    @PutMapping("/documents/{id}")
    public Object updateDocument(@PathVariable("id") Long id,
                                 @RequestBody DocumentUpdate body,
                                 HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE documents SET filename = ?, content = ?, is_public = ? WHERE id = ?",
                body.filename, body.content,
                body.isPublic != null && body.isPublic, id);
            return Map.of("updated", rows, "id", id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Reads all messages addressed to any recipient_id.
    @GetMapping("/messages")
    public Object getMessagesByRecipient(@RequestParam("recipientId") Long recipientId,
                                         HttpServletRequest req) {
        try {
            return jdbc.queryForList(
                "SELECT * FROM messages WHERE recipient_id = " + recipientId);
        } catch (Exception e) {
            return List.of(Map.of("error", e.getMessage()));
        }
    }

    // OWASP API1:2023 Broken Object Level Authorization.
    // Cancels any order by id with no ownership check.
    @PatchMapping("/orders/{id}/cancel")
    public Object cancelOrder(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE orders SET status = 'CANCELLED' WHERE id = ?", id);
            return Map.of("cancelled", rows, "id", id);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

}
