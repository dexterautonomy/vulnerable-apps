# vulnerable-app-java8

Intentionally vulnerable Spring Boot **2.7.18** app on **Java 8** — a DAST scanner test
target with **250 endpoints** failing OWASP Top 10 (2021) and API Security Top 10 (2023).
See the [top-level README](../README.md) for the full vulnerability matrix and warnings.

> ⚠️ Deliberately insecure. Run only in an isolated lab. Never expose publicly.

- **App port:** `8080`  ·  **Postgres port:** `5432`  ·  **DB:** `vulndb` / `vulnuser` / `vulnpass`
- **Namespace:** `javax.*` (Spring Boot 2.7). A small `Compat` helper backfills the Java 9
  `Map.of` / `List.of` / `Set.of` factory methods so the shared controllers compile on Java 8.
- **API docs (open Swagger):**
  - Swagger UI — <http://localhost:8080/swagger-ui.html>
  - OpenAPI JSON — <http://localhost:8080/v3/api-docs>

## Run

Requires a **JDK 8** on Maven's path (`JAVA_HOME` → your JDK 8).

```bash
# Option A: no database (in-memory H2)
mvn spring-boot:run -Dspring-boot.run.profiles=h2

# Option B: PostgreSQL (start it from the top-level folder first)
#   docker compose up -d
mvn spring-boot:run
```

Landing page + links: <http://localhost:8080/>  ·  full route dump: `/api/inventory`.
