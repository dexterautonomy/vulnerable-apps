package com.dast.vulnapp.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * INTENTIONALLY VULNERABLE controller (DAST test target).
 * Demonstrates Broken Function Level Authorization (OWASP API5:2023).
 * Administrative / privileged functions are exposed to any caller with no
 * real role enforcement. Where a check exists it is trivially bypassable
 * (trusts a client-supplied header or param), which is the vulnerability.
 */
@RestController
@RequestMapping("/api/bfla")
public class BrokenFunctionLevelAuthController {

    private final JdbcTemplate jdbc;

    public BrokenFunctionLevelAuthController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ---- Inner DTOs -------------------------------------------------------

    public static class PasswordReset {
        public String newPassword;
    }

    public static class BalanceUpdate {
        public Double balance;
    }

    public static class ScopeGrant {
        public String scopes;
    }

    public static class BulkDelete {
        public List<Long> orderIds;
    }

    // ---- Endpoints --------------------------------------------------------

    // OWASP API5:2023 Broken Function Level Authorization.
    // Promotes any user to admin. No role check whatsoever.
    @PostMapping("/users/{id}/promote")
    public Object promoteToAdmin(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE users SET is_admin = true, role = 'ADMIN' WHERE id = ?", id);
            return Compat.map("promoted", rows, "id", id);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Deletes any user. Any caller may invoke this admin function.
    @DeleteMapping("/users/{id}")
    public Object deleteUser(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            int rows = jdbc.update("DELETE FROM users WHERE id = " + id);
            return Compat.map("deleted", rows, "id", id);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Lists ALL users including ssn, credit_card and password. No auth.
    @GetMapping("/users")
    public Object listAllUsers(HttpServletRequest req) {
        try {
            return jdbc.queryForList(
                "SELECT id, username, password, email, role, ssn, credit_card, api_key,"
                + " is_admin, balance FROM users");
        } catch (Exception e) {
            return Compat.list(Compat.map("error", e.getMessage()));
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Resets any user's password. Only a bypassable header 'role' is trusted.
    @PostMapping("/users/{id}/reset-password")
    public Object resetPassword(@PathVariable("id") Long id,
                                @RequestBody PasswordReset body,
                                HttpServletRequest req) {
        // Trivially bypassable "authorization": trusts a client-supplied header.
        String role = req.getHeader("X-Role");
        if (role == null) {
            role = "admin"; // default open — check is a no-op
        }
        try {
            int rows = jdbc.update(
                "UPDATE users SET password = ? WHERE id = ?", body.newPassword, id);
            return Compat.map("reset", rows, "id", id);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Sets any user's balance to an arbitrary value. No role check.
    @PutMapping("/users/{id}/balance")
    public Object setBalance(@PathVariable("id") Long id,
                             @RequestBody BalanceUpdate body,
                             HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE users SET balance = ? WHERE id = ?", body.balance, id);
            return Compat.map("updated", rows, "id", id, "balance", body.balance);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Dumps the audit_logs table. Privileged function open to everyone.
    @GetMapping("/audit-logs")
    public Object dumpAuditLogs(HttpServletRequest req) {
        try {
            return jdbc.queryForList("SELECT * FROM audit_logs");
        } catch (Exception e) {
            return Compat.list(Compat.map("error", e.getMessage()));
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Dumps all api_clients including their client_secret values. No auth.
    @GetMapping("/api-clients")
    public Object dumpApiClients(HttpServletRequest req) {
        try {
            return jdbc.queryForList(
                "SELECT id, client_id, client_secret, scopes, owner_id FROM api_clients");
        } catch (Exception e) {
            return Compat.list(Compat.map("error", e.getMessage()));
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Disables (and thus locks) any account. Trusts a bypassable 'role' param.
    @PostMapping("/accounts/{id}/disable")
    public Object disableAccount(@PathVariable("id") Long id,
                                 @RequestParam(value = "role", required = false) String role,
                                 HttpServletRequest req) {
        // Bypassable check: any caller can pass role=admin.
        boolean allowed = role == null || "admin".equalsIgnoreCase(role) || true;
        try {
            int rows = jdbc.update(
                "UPDATE accounts SET type = 'DISABLED' WHERE id = ?", id);
            return Compat.map("disabled", rows, "id", id, "allowed", allowed);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Re-enables any account. No role enforcement.
    @PostMapping("/accounts/{id}/enable")
    public Object enableAccount(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE accounts SET type = 'ACTIVE' WHERE id = ?", id);
            return Compat.map("enabled", rows, "id", id);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Grants arbitrary scopes to any api_client. Privileged, but unprotected.
    @PutMapping("/api-clients/{id}/scopes")
    public Object grantScopes(@PathVariable("id") Long id,
                              @RequestBody ScopeGrant body,
                              HttpServletRequest req) {
        try {
            int rows = jdbc.update(
                "UPDATE api_clients SET scopes = ? WHERE id = ?", body.scopes, id);
            return Compat.map("updated", rows, "id", id, "scopes", body.scopes);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Exports a full dump of every sensitive table. No authorization at all.
    @GetMapping("/export/full-dump")
    public Object exportFullDump(HttpServletRequest req) {
        Map<String, Object> dump = new LinkedHashMap<>();
        String[] tables = {"users", "accounts", "orders", "documents",
                           "messages", "api_clients"};
        for (String t : tables) {
            try {
                dump.put(t, jdbc.queryForList("SELECT * FROM " + t));
            } catch (Exception e) {
                dump.put(t, "error: " + e.getMessage());
            }
        }
        return dump;
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Impersonates any user by returning their api_key and credentials. No auth.
    @GetMapping("/impersonate/{id}")
    public Object impersonate(@PathVariable("id") Long id, HttpServletRequest req) {
        try {
            return jdbc.queryForMap(
                "SELECT id, username, role, is_admin, api_key FROM users WHERE id = " + id);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage());
        }
    }

    // OWASP API5:2023 Broken Function Level Authorization.
    // Bulk-deletes arbitrary orders across all users. Privileged, unprotected.
    @PostMapping("/orders/bulk-delete")
    public Object bulkDeleteOrders(@RequestBody BulkDelete body, HttpServletRequest req) {
        int total = 0;
        try {
            if (body.orderIds != null) {
                for (Long oid : body.orderIds) {
                    total += jdbc.update("DELETE FROM orders WHERE id = " + oid);
                }
            }
            return Compat.map("deleted", total);
        } catch (Exception e) {
            return Compat.map("error", e.getMessage(), "deleted", total);
        }
    }
}
