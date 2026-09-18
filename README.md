# Identity application candidate

This executable owns password authentication, registration identity/profile data,
OAuth clients, authorizations, consents and signing keys. It contains no product
grants, plans, support delivery or curriculum loader. The legacy root application
remains a separate compatibility baseline; this candidate does not migrate or
replace its running database automatically.

Build from the sibling `lookahead-learning-toolkit` directory with `./mvnw -pl :identity-app -am verify`.
The executable is `../lookahead-learning-identity/target/lookahead-identity.jar`, with main class
`com.lookahead.identity.IdentityApplication`. Every launch includes `accounts` and
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
