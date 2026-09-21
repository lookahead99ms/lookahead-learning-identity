# Look Ahead Learning Identity

This executable owns password authentication, registration identity/profile data,
OAuth clients, authorizations, consents and signing keys. It contains no product
grants, plans, support delivery or curriculum loader. The legacy root application
remains a separate compatibility baseline; this candidate does not migrate or
replace its running database automatically.

## Independent build

Install a Java 21 JDK, then run from this repository:

```sh
./gradlew --no-daemon clean test bootJar
```

The committed wrapper downloads Gradle 9.6.1 and verifies its official SHA-256.
Spring Boot 4.1.1 provides dependency versions, and `gradle.lockfile` pins the
resolved dependencies. Only public Gradle plugin and Maven Central repositories
are used. No sibling checkout, Toolkit JAR, private artifact registry or
pre-populated Maven cache is required. Windows users can run `gradlew.bat`.

The executable is `build/libs/lookahead-identity.jar`, with main class
`com.lookahead.identity.IdentityApplication`. Test results are under
`build/reports/tests/test/`. To deliberately refresh dependency locks after a
reviewed dependency change, run `./gradlew clean test bootJar --write-locks` and
review the lock diff.

The five transport records in `com.lookahead.learning.content.dto` are owned by
this application. The historical package is preserved for compatibility; it does
not imply a shared library dependency. `IdentityJsonContractTest` verifies the
public JSON shapes with Spring Boot's configured mapper, including nulls,
timestamps, IDs, grants and credential exclusion. Cross-service verification is
orchestrated separately; passing these tests is not proof of a complete OAuth
journey.

## Run and container build

Identity is independently buildable, but real authentication requires its
PostgreSQL database, application-owned schema migration, restricted database
roles, externally supplied signing keys and OAuth/verifier configuration. It does
not start an in-memory database or silently create demo users. Supply the
configuration below, then run:

```sh
java -jar build/libs/lookahead-identity.jar --spring.profiles.active=local
```

Build an image using only this application's checkout:

```sh
docker build --tag lookahead-identity:local .
```

The build runs the tests and packages the executable. The runtime image uses Java
21, UID/GID 10001, `/opt/lookahead/app.jar` and port 8080. It includes a Java-only
readiness probe at `/opt/lookahead/health` and checks
`/actuator/health/readiness`. Credentials and keys must be supplied at runtime,
never through image build arguments. Bind any development host ports to loopback.
The private Infra repository owns the integrated local environment and database
lifecycle; it is not required to compile or test this application.

GitHub Actions runs the wrapper checksum check, tests, packaging and standalone
Docker build with read-only repository permissions. It does not publish an image
or deploy resources.

Every launch includes `accounts` and
`oauth-server`; Gateway/Learning Domain API profiles are rejected. Choose `local`, `dev`, or
`prod` explicitly, with the matching canonical `app.deployment-environment` value.
Long-form aliases and contradictory environment profiles are rejected. Local fixtures additionally require `local-test`,
`app.local-test.seed-enabled=true`, and a guarded seed password. The optional
local author identity retains its existing stable subject but receives no grants
in this application.

## Configuration contract

| Property / environment | Meaning |
| --- | --- |
| `LOOKAHEAD_ENVIRONMENT` | Required `local`, `dev`, or `prod`, matching the selected environment profile |
| `LOOKAHEAD_BIND_ADDRESS` / `PORT` | Bind address (defaults to loopback) and port (defaults to 8080); forwarding headers are ignored |
| `spring.datasource.url` / `LOOKAHEAD_IDENTITY_JDBC_URL` | Identity database JDBC URL |
| `spring.datasource.username` | Must be `lookahead_identity_app` |
| `spring.datasource.password` / `LOOKAHEAD_IDENTITY_DB_PASSWORD` | Dedicated Identity runtime credential |
| `LOOKAHEAD_SECRETS_DIRECTORY` | Optional config-tree directory; required secret values still fail closed if absent |
| `app.oauth.issuer` / `LOOKAHEAD_OAUTH_ISSUER` | Existing externally visible issuer origin |
| `app.oauth.frontend` / `LOOKAHEAD_FRONTEND_ORIGIN` | Existing frontend origin; must equal issuer in this compatibility stage |
| `app.oauth.client-id` / `APP_OAUTH_CLIENT_ID` | Registered Gateway client ID |
| `app.oauth.client-secret` / `LOOKAHEAD_GATEWAY_CLIENT_SECRET` | Gateway client credential, distinct from verifier credential |
| `app.oauth.signing-private-key` / `LOOKAHEAD_SIGNING_PRIVATE_KEY` | RSA private PEM, at least 3072 bits |
| `app.oauth.signing-public-key` / `LOOKAHEAD_SIGNING_PUBLIC_KEY` | Matching public PEM |
| `app.identity.verifier-secret` / `LOOKAHEAD_IDENTITY_VERIFIER_SECRET` | Separate Learning Domain API verification credential, at least 32 characters |
| `LOOKAHEAD_REGISTRATION_ENABLED` | Explicitly enable registration/password account login |
| `server.servlet.session.cookie.name` / `LOOKAHEAD_IDENTITY_COOKIE_NAME` | Defaults to `LOOKAHEAD_SESSION`; configure a unique candidate cookie and the same name in Gateway |
| `LOOKAHEAD_MAX_ACTIVE_SIGN_INS` | Local requires `0` (unlimited); DEV and PROD require `2` |

Database URLs must be explicit single-host PostgreSQL URLs. Only `sslmode` and
an absolute `sslrootcert` path are accepted as URL parameters; credentials,
`options`, schema and timeout overrides are rejected. Both runtime and migration
entrypoints check the actual database role. Each runtime pool connection checks
its restricted privileges before use and fixes its search path; readiness checks
every required DML privilege on every owned table.

Secrets must remain out of source, command output, logs and images. Local cookie
relaxation is limited to local configuration. `dev` and `prod` use secure
cookies and do not enable synthetic identities. Infra can explicitly set
`LOOKAHEAD_BIND_ADDRESS=0.0.0.0` inside an isolated container network; host development
using the `local` profile binds to loopback.

The private verification endpoint is `POST /internal/v1/tokens/verify`, accepting
form field `token`. It requires HTTP Basic username `lookahead-domain-verifier`
with `app.identity.verifier-secret`. It is stateless and does not use browser
cookies or CSRF. Keep it off public edge routing and protect its transport in
production. Browser-facing login, registration, continuation, OAuth and logout
routes keep their existing names and cookie behavior.

Verification checks signature, issuer, expiry, audience, configured Gateway
client, matching active persisted authorization, and the current enabled
identity. Invalid/revoked/disabled tokens return `200 {"active":false}`;
valid tokens return `active`, `subject`, `username`, `displayName`, and `clientId`.
Verifier credential failures return 401 without redirects. Storage failures
return a safe 503. Responses use `Cache-Control: no-store` and contain no token
or password material.

Login/registration and Identity `/api/v1/auth/me` return identity facts with empty
product grants and `authorPreview=false`. **This is not an authoritative product
access response.** In the existing frontend OAuth mode the login/registration
body is ignored and navigation continues through OAuth. After establishing the
BFF session, Learning Domain API `/api/v1/auth/me` supplies current grants and author access.
Do not wire a legacy non-OAuth client to this response and infer revoked access.
Identity never calls Learning Domain API to compose its login response.

## Fresh database migration

The one-shot class `com.lookahead.identity.IdentityMigration` reads
`SPRING_FLYWAY_URL`, `SPRING_FLYWAY_USER=lookahead_identity_migrator`, and exactly
one of `SPRING_FLYWAY_PASSWORD` or `LOOKAHEAD_MIGRATION_PASSWORD_FILE` (the latter
defaults to `/run/secrets/spring.flyway.password`). Invoke through Boot's
`org.springframework.boot.loader.launch.PropertiesLauncher` with
`-Dloader.main=com.lookahead.identity.IdentityMigration` and the executable JAR
on the classpath.

Infra provisions the database and roles first. This entry point runs only
`classpath:db/identity`, disables Flyway clean, and grants DML to the dedicated
runtime role. Identity readiness checks that role, migration version, and all
five owned tables. Runtime Flyway execution is disabled.

The fresh schema is not a live migration procedure. Existing accounts, stable
subjects, password hashes, OAuth registrations, active/revoked tokens and
consents require a separately verified transfer and rollback procedure. No
cross-database foreign keys, account copies with product privileges, or changes
to root V1–V5 migrations are included.

## Validation boundary

Module checks exercise credential rejection, token/identity freshness, safe
storage errors, identity-only schema ownership, local fixture guards, OAuth
principal persistence, and registration/session/CSRF behavior. They do not prove
an isolated PostgreSQL migration, a three-application OAuth journey, live-state
transfer, production deployment, session replication or disaster recovery.
Those remain required before cutover. Google federation, paid subscriptions,
roles/admin tooling, password recovery and MFA are separate capabilities; this
extraction does not claim to implement them.

## Logical sign-in controls

See [the sign-in API and configuration guide](docs/sign-in-api.md) and [OpenAPI source](docs/sign-in-openapi.json) for unlimited Local development, the DEV/PROD two-sign-in limit, restricted replacement, revocation, migration and verification.
