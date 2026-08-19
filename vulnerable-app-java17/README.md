# vulnerable-app-java17

Intentionally vulnerable Spring Boot **3.2.5** app on **Java 17** — a DAST scanner test
target with **250 endpoints** failing OWASP Top 10 (2021) and API Security Top 10 (2023).
See the [top-level README](../README.md) for the full vulnerability matrix and warnings.

> ⚠️ Deliberately insecure. Run only in an isolated lab. Never expose publicly.

- **App port:** `8082`  ·  **Postgres port:** `5433`  ·  **DB:** `vulndb` / `vulnuser` / `vulnpass`
- **Namespace:** `jakarta.*` (Spring Boot 3).
- **API docs (open OpenAPI):**
  - OpenAPI JSON — <http://localhost:8082/v3/api-docs>
  - Swagger UI — <http://localhost:8082/swagger-ui.html>

## Run

Requires a **JDK 17** on Maven's path (`JAVA_HOME` → your JDK 17).

```bash
# Option A: no database (in-memory H2)
mvn spring-boot:run -Dspring-boot.run.profiles=h2

# Option B: PostgreSQL (start it from the top-level folder first)
#   docker compose up -d
mvn spring-boot:run
```

Landing page + links: <http://localhost:8082/>  ·  full route dump: `/api/inventory`.
