# Logical sign-in controls (DLV-920)

Identity owns a PostgreSQL registry of logical sign-ins. A browser's Identity session, BFF session and OAuth authorizations share one registry entry; this is not hardware/device identification. At most two entries are active per account. Fresh credentials reuse the same valid browser binding; the binding cookie alone never authenticates.

A third valid login returns flat HTTP 409 `SIGN_IN_LIMIT` with `expiresAt` and a restricted HttpOnly challenge cookie. It does not create an authenticated session. Fetch the challenge inventory, then explicitly replace one entry or cancel. Replacement is transactional and retrying the same proof/choice is idempotent for five minutes. After success, refresh Identity CSRF and continue the normal BFF authorization-code/PKCE flow. Cancel preserves the existing entries.

The [OpenAPI source](sign-in-openapi.json) defines the seven new endpoints. All success bodies use `{data,timestamp}`; all responses are no-store. Every POST requires Identity's `X-CSRF-TOKEN`, obtained from `/api/v1/auth/csrf`; BFF CSRF is separate. Requests reject extra fields. Revocation requires recent credential authentication: handle 403 `RECENT_AUTHENTICATION_REQUIRED` by signing in again, then explicitly retrying. Labels affect only the current entry and permit at most 80 Unicode code points of plain text.

Revoking an entry invalidates its Identity session, OAuth code, refresh and access-token verification. Gateway checks private requests through Domain, which calls Identity's internal verifier; no positive validity cache is used. Already-running requests are not transactional with a simultaneous revoke. Password rotation revokes all entries through the global credential epoch. OIDC logout and ordinary logout release the current entry. Database/verifier outages fail closed. Old sessions and OAuth artifacts without a logical-sign-in binding require fresh authentication after migration.

## Configuration and migration

Run the existing migration entry point with the migration database role before starting this candidate; V3 adds `logical_sign_ins`, `sign_in_challenges` and the authorization-to-sign-in reference. The application role does not own schema creation. Preserve the database for restart tests; never reset shared data.

| Variable | Default | Supported range / meaning |
| --- | --- | --- |
| `LOOKAHEAD_SIGNIN_IDLE_LIFETIME` | `30m` | 1 minute–24 hours; activity renews idle time |
| `LOOKAHEAD_SIGNIN_ABSOLUTE_LIFETIME` | `7d` | 5 minutes–30 days; idle must not exceed absolute |
| `LOOKAHEAD_SIGNIN_RECENT_AUTH_LIFETIME` | `5m` | 30 seconds–15 minutes |
| `LOOKAHEAD_SIGNIN_BINDING_COOKIE_NAME` | `LOOKAHEAD_SIGNIN_BINDING` | Must match Gateway; distinct per deployment |
| `LOOKAHEAD_SIGNIN_CHALLENGE_COOKIE_NAME` | `LOOKAHEAD_SIGNIN_CHALLENGE` | Must match Gateway; distinct from session/binding |

Cookies are HttpOnly, SameSite=Lax, path `/`; secure follows the Identity session-cookie setting. Disable Secure only for isolated loopback HTTP development. Challenge lifetime is five minutes; at most five challenges per account per rolling fifteen minutes. Capacity is fixed at two. Retained revoked-record history currently has no automated retention job. Servlet sessions remain instance-local; durable binding allows fresh credential authentication after restart without consuming another slot. This does not establish seamless session failover.

## Local verification and deployment boundary

`./gradlew test bootJar --offline` runs unit/HTTP tests. For real database tests set `DLV919_DATABASE_URL` and `DLV920_DATABASE_URL` to the dedicated disposable PostgreSQL JDBC URL and inject `DLV920_DATABASE_PASSWORD` privately. These tests create/drop unique schemas and must never target a production database. Without these variables database tests are skipped; report the distinction.

Build the standard Dockerfile with `docker build -t lookahead-identity:dlv-920-candidate .`; resolve its immutable ID with `docker image inspect`. Standard image builds do not supply database-test credentials and do not replace the separate database suite. No Google provider is activated. Cross-service restart, recovery and complete Gateway/Domain HTTP proof belong to the isolated Infra gate before release.
