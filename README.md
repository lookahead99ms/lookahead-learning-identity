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

## Required release coverage

`./gradlew clean check` runs JaCoCo 0.8.15 and requires at least **85% production-code line coverage**, with no main-source exclusions. XML/HTML/CSV reports are under `build/reports/jacoco/test/`. Branch coverage is reported separately. The ordinary standalone `test bootJar` command remains useful for unit development; it does not certify the release coverage gate.

The coverage run needs the disposable PostgreSQL fixtures: set `DLV919_DATABASE_URL` and `DLV920_DATABASE_URL` to the test database JDBC URL, and `DLV920_DATABASE_PASSWORD` to its synthetic password. Infra owns `scripts/session_registry_test_database.py` for local fixture lifecycle. Tests create and remove isolated schemas; never point them at application data. CI supplies a digest-pinned disposable PostgreSQL service and runs `clean check bootJar`. Without database fixtures the optional integration tests skip and the full coverage gate remains below the floor.

Infra `tools/security/coverage_gate.py` additionally checks complete source inventory, current inputs and fresh reports for the four required applications (Web, Gateway, Domain and Identity) before DEV or PROD deployment. Infra tooling coverage is an optional measurement. A successful unit-only run or an old report cannot satisfy that release gate. Coverage evidence stays local/CI-private.

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

See [the Local sign-in API and configuration guide](docs/sign-in-api.md) and
[OpenAPI source](docs/sign-in-openapi.json) for this service's retained Local
behavior. Historical DEV/PROD policy options remain in the implementation and
its tests, but this service is no longer selected by the cloud deployment target.

## Local Identity and the cloud provider split

Local continues to run this Spring Identity service with its own database.
DEV/PROD now select Cognito explicitly in Gateway and Domain. Gateway keeps
browser sessions, tokens and CSRF; Domain owns durable two-sign-in enforcement,
revocation, stable issuer/subject-to-account mapping, admission and authorization.
There is one Domain RDS instance per cloud environment and no cloud Identity
service or Identity database in the maintained infrastructure candidate.

The old `deployment/service.yaml` is preserved as a historical, inactive contract;
Infra no longer loads it into cloud service plans. It is not an instruction to
provision this service or its former secrets. The two shared ECS roles are reused
by the three current cloud applications, with separate role resources for DEV and
PROD. Local Docker configuration and stored data are preserved.

The cloud implementation has controlled-provider and isolated PostgreSQL evidence;
live Cognito/RDS/ECS verification, private service TLS and release-security gates
remain open. See the active Gateway and Domain READMEs and Infra deployment
runbooks for current contracts. No AWS resource, image or repository publication
is authorized by these documents.

The container readiness probe is production Java source at `src/main/java/com/lookahead/identity/health/ContainerHealthcheck.java`, so the ordinary JaCoCo report includes it. Tests use loopback HTTP fixtures to cover healthy and failed responses, malformed bodies, redirects, unavailable endpoints, timeouts and interruption. The container still probes only `127.0.0.1:8080/actuator/health/readiness`, with a two-second connection limit and three-second request limit. The process-exit wrapper remains in the measured source inventory.

Docker resolves the checksum-pinned Gradle wrapper in a source-independent layer before copying build declarations and application sources. This reuses the wrapper download when source files change; dependency versions and the `clean test bootJar` build remain unchanged.

## SAST gate diagnostics

`python3 tools/security/check.py sarif` requires completed CodeQL invocations,
valid rule/result inventories and exercised, source-bound exceptions. A failure
prints a reviewed constant reason (for example, missing invocation inventory or
unexercised exception) while leaving untrusted error text and SARIF messages out
of public logs. Warning/error notifications still block; this diagnostic change
does not waive findings or weaken the security gate. Raw SARIF and source
databases remain unpublished. Run the tooling regressions with
`python3 -m unittest discover -s tools/security -p 'test_*.py'`.

SAST exception hashes are also checked in the first tooling-test step; review
the security boundary before updating a hash after a source change. Expiry and
mandatory exception usage stay enforced. SARIF trace notifications (`none`)
are informational alongside `note`; warnings, errors and unknown levels block.
A rejected notification logs only its level and a bounded Java diagnostic ID,
never its message, source snippet, locations or properties.


The Docker builder and runtime use explicit, digest-pinned Eclipse Temurin
Java 21 Ubuntu 24.04 (`21-jdk-noble` / `21-jre-noble`) images. This avoids the
reported OpenSSL and bundled Go-tooling findings in the prior Ubuntu 26.04
pins. The scanner still blocks High, Critical and Unknown severities, including
unfixed findings, and requires complete OS/Java package coverage for built images.
A passing base scan does not certify the built application; CI scans both bases
and the exact final image. User 10001 and the existing health probe remain unchanged.
