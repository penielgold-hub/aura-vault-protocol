# API keys

API keys are intended for trusted machine-to-machine clients. Apply migration
`backend/migrations/005_create_api_keys.sql` to the configured PostgreSQL
database before using the feature. Set `DATABASE_URL`; optional pool settings
are `PG_POOL_MAX`, `PG_IDLE_TIMEOUT_MS`, `PG_CONNECTION_TIMEOUT_MS`, and
`PG_SSL=true` for TLS.

## Administrator authorization

Creating or revoking keys requires an administrator JWT. Normal wallet login
does not issue one and its client-supplied `tier` is not used to grant admin
access. An operator must provision `ADMIN_JWT_SECRET` out of band; it must be
at least 32 characters and different from `JWT_SECRET`. An administrator JWT
must be signed with HS256 and this secret, include `iss` and `aud` set to
`aura-vault-admin`, `scope: "admin"`, a non-empty `sub`, and a short-lived
`exp`. Keep the signing secret with the trusted issuer/operator and never
distribute it to API clients. Missing or invalid server configuration disables
the admin endpoints with a service-unavailable response.

## Create and use a key

An authorized administrator sends:

```http
POST /api/admin/api-keys
Authorization: Bearer <administrator-jwt>
Content-Type: application/json

{"scope":"read","expiresAt":"2027-01-01T00:00:00.000Z"}
```

`expiresAt` is optional; when supplied it must be a future ISO date. Scope is
required and must be `read`, `write`, or `admin`. The create response contains
the raw secret once. Copy it into a secret manager immediately; the server
stores only a bcrypt hash, and the secret cannot be retrieved later.

Send a key on supported protected endpoints using:

```http
X-API-Key: avk_<key-id>.<secret>
```

The portfolio endpoint and authenticated email endpoints support API keys.
Portfolio and email reads require `read`; email sending requires `write`.
`write` also permits reads, and `admin` satisfies lower scopes. Routes without
an explicit API-key scope mapping continue to use JWT authentication only.

Revoke a key with:

```http
DELETE /api/admin/api-keys/<key-id>
Authorization: Bearer <administrator-jwt>
```

Access, rejection, creation, and revocation events are written to `audit_logs`
without recording the raw key. The existing global IP limiter remains active;
API-key requests also use an independent Redis bucket keyed by key ID.
