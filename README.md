# DAST Test Targets — Intentionally Vulnerable Spring Boot Apps

> ## ⚠️ DANGER — READ FIRST
> These three applications are **deliberately insecure**. Every endpoint is designed to
> **fail** a security assessment (OWASP Top 10 2021 + OWASP API Security Top 10 2023 and
> more). They exist only as **target apps to validate a DAST scanner** — the same purpose
> as OWASP WebGoat, DVWA, or Juice Shop.
>
> - **DO NOT** deploy on the public internet or any shared/production network.
> - **DO NOT** point them at a real database or reuse any of this code.
> - Run **only** inside an isolated lab, VM, or container network.
> - They ship with hardcoded fake secrets and seed PII — all fake, for testing only.

---

## The three targets

Identical vulnerability surface, three Java runtimes:

| App                     | Java | Spring Boot | App port | Postgres port | API docs |
|-------------------------|:----:|:-----------:|:--------:|:-------------:|----------|
| `vulnerable-app-java8`  |  8   |   2.7.18    |  `8080`  |    `5432`     | **Swagger UI** (`springdoc-openapi-ui` 1.6.15) |
| `vulnerable-app-java17` |  17  |    3.2.5    |  `8082`  |    `5433`     | **OpenAPI docs** (`springdoc-openapi` 2.3.0) |
| `vulnerable-app-java21` |  21  |    3.2.5    |  `8081`  |    `5434`     | **OpenAPI docs** (`springdoc-openapi` 2.3.0) |

Each app exposes **exactly 250 endpoints** across 20 vulnerability controllers plus a
landing/inventory controller. The Java 8 build uses the `javax.*` namespace and a small
`Compat` shim (for the Java 9 `Map.of`/`List.of`/`Set.of` factory methods); the Java 17
and Java 21 builds use `jakarta.*`. The vulnerable logic is otherwise identical.

## Dependencies (per the request)

- **PostgreSQL** (`org.postgresql:postgresql`) — the primary datasource.
- Spring Boot **web, data-jpa, jdbc, thymeleaf, validation, actuator**.
- **springdoc / Swagger** — left open and unauthenticated (see API9 below).
- `jjwt` 0.11.5, `commons-io`, `commons-lang3` — used insecurely on purpose.
- **H2** is bundled only as a convenience so the app can boot with **no Postgres** via the
  `h2` profile. It does not change the vulnerabilities.

---

## Quick start

### Option A — zero dependencies (in-memory H2)

No database to install. From any app folder:

```bash
cd vulnerable-app-java21
mvn spring-boot:run -Dspring-boot.run.profiles=h2
```

Then open the landing page, e.g. <http://localhost:8081/>.

### Option B — PostgreSQL (as required), via Docker

From this top-level folder:

```bash
docker compose up -d          # starts one Postgres per app (5432/5433/5434)
cd vulnerable-app-java21
mvn spring-boot:run           # default profile -> Postgres on 5434
```

Schema and seed data are created automatically on startup from
`src/main/resources/schema.sql` and `data.sql`.

> The Java 8 app requires a **JDK 8** on the `mvn` path; Java 17 needs JDK 17; Java 21 needs
> JDK 21. To build against a specific JDK, set `JAVA_HOME` before running Maven.

### API documentation URLs (open on purpose)

| App    | Swagger UI                                   | OpenAPI JSON                          |
|--------|----------------------------------------------|---------------------------------------|
| Java 8 | <http://localhost:8080/swagger-ui.html>      | <http://localhost:8080/v3/api-docs>   |
| Java 17| <http://localhost:8082/swagger-ui.html>      | <http://localhost:8082/v3/api-docs>   |
| Java 21| <http://localhost:8081/swagger-ui.html>      | <http://localhost:8081/v3/api-docs>   |

Each app also serves `GET /api/inventory` (full route dump) and an open Actuator at
`/actuator` (all endpoints exposed, `env`/`configprops` unmasked).

---

## OWASP Top 10 (2021) coverage

| ID  | Category | Where |
|-----|----------|-------|
| A01 | Broken Access Control | `/api/bola` (IDOR), `/api/bfla` (admin funcs), `/api/files` (traversal), `/api/redirect` |
| A02 | Cryptographic Failures | `/api/crypto` (MD5/SHA1, DES, AES-ECB, static IV, weak PRNG), `/api/data` (plaintext secrets) |
| A03 | Injection | `/api/sqli` (SQLi), `/api/cmd` (OS command), `/api/xss` (XSS), `/api/headers` (CRLF) |
| A04 | Insecure Design | `/api/auth` (no lockout, backdoors), `/api/limits` (no rate limiting) |
| A05 | Security Misconfiguration | `/api/config`, open Actuator, verbose stack traces, permissive CORS, `/api/xxe` |
| A06 | Vulnerable & Outdated Components | pinned old `commons-io` / `jjwt` / Boot 2.7 (Java 8 build) |
| A07 | Identification & Authentication Failures | `/api/auth`, `/api/jwt` |
| A08 | Software & Data Integrity Failures | `/api/deser` (Java + Jackson deserialization), `/api/upload` |
| A09 | Security Logging & Monitoring Failures | credentials logged to `audit_logs`, secrets in logs, `/api/inventory` |
| A10 | Server-Side Request Forgery | `/api/ssrf` |

## OWASP API Security Top 10 (2023) coverage

| ID    | Category | Where |
|-------|----------|-------|
| API1  | Broken Object Level Authorization | `/api/bola` |
| API2  | Broken Authentication | `/api/auth`, `/api/jwt` |
| API3  | Broken Object Property Level Auth (mass assignment / excessive data) | `/api/mass`, `/api/data` |
| API4  | Unrestricted Resource Consumption | `/api/limits` |
| API5  | Broken Function Level Authorization | `/api/bfla` |
| API6  | Unrestricted Access to Sensitive Business Flows | `/api/bfla` bulk ops, `/api/mass` |
| API7  | Server-Side Request Forgery | `/api/ssrf` |
| API8  | Security Misconfiguration | `/api/config`, open CORS, open Actuator |
| API9  | Improper Inventory Management | open Swagger/OpenAPI, `/api/inventory`, `/api/config` beta/shadow routes |
| API10 | Unsafe Consumption of APIs | `/api/ssrf` (proxies/imports untrusted upstreams) |

---

## Endpoint inventory (250 total)

| Controller | Base path | Endpoints | Primary class |
|------------|-----------|:---------:|---------------|
| SQL Injection | `/api/sqli` | 22 | A03 / Injection |
| XSS (reflected + stored) | `/api/xss` | 18 | A03 |
| Broken Object Level Auth (IDOR) | `/api/bola` | 17 | API1 |
| Authentication failures | `/api/auth` | 16 | A07 / API2 |
| Cryptographic failures | `/api/crypto` | 15 | A02 |
| Command Injection | `/api/cmd` | 14 | A03 |
| File Upload | `/api/upload` | 14 | A08 |
| Sensitive Data Exposure | `/api/data` | 14 | A02 / API3 |
| Broken Function Level Auth | `/api/bfla` | 13 | API5 |
| JWT flaws | `/api/jwt` | 13 | A07 / API2 |
| SSRF | `/api/ssrf` | 13 | A10 / API7 |
| Path Traversal / LFI | `/api/files` | 12 | A01 |
| Header / CRLF Injection | `/api/headers` | 10 | A03 |
| Mass Assignment / BOPLA | `/api/mass` | 10 | API3 |
| Unrestricted Resource Consumption | `/api/limits` | 10 | API4 |
| Insecure Deserialization | `/api/deser` | 10 | A08 |
| Open Redirect | `/api/redirect` | 8 | A01 |
| Security Misconfiguration / Inventory | `/api/config` | 8 | A05 / API8 / API9 |
| XXE | `/api/xxe` | 8 | A05 / A03 |
| Landing + route inventory | `/` | 5 | API9 / A05 |
| **Total** | | **250** | |

## Validation status

- **Java 21**: compiles (bytecode 65) and boots; SQLi, reflected+stored XSS, BOLA, BFLA,
  SSRF, path traversal, JWT, mass assignment, sensitive-data exposure, open Swagger/OpenAPI
  and open Actuator were all exercised live and confirmed exploitable.
- **Java 17**: compiles (bytecode 61); identical Spring Boot 3 source as Java 21.
- **Java 8**: compiles (bytecode 52); `javax.*` namespace, Spring Boot 2.7, `Compat` shim.
