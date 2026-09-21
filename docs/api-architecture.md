# API Architecture

Status: DESIGN DECISION (for Phase 1 + future phases)
Not yet implemented.

## Principles
- REST-based (JSON) with module-scoped paths
- Versioned: /v1/ prefix; future major versions via path
- Every endpoint: auth → tenant context → RBAC → ABAC → execution → audit
- No infrastructure commands through public API (Control Plane uses separate internal endpoint set, still through gateway/auth)
- Rate limiting per tenant / user / endpoint

## API Surface (Phase 1 — verified design)
Module: auth / identity (DESIGN DECISION — Keycloak owns authentication flows; app does not duplicate identity provider functions)
- GET /v1/auth/oidc/authorize — redirect to Keycloak (OIDC Authorization Code + PKCE) [FACT: Keycloak performs authorization]
- GET /v1/auth/saml/acs — SAML ACS endpoint (Keycloak handles assertion; app validates session) [FACT: Keycloak performs SAML auth]
- POST /v1/auth/logout — application-initiated logout (calls Keycloak end-session endpoint; revokes session) [DESIGN DECISION: session revocation authority is application-backed, Keycloak-backed]
- DELETE /v1/auth/session/{id} — revoke session (session store; Keycloak token revoked if applicable)
NOTE: POST /auth/login and POST /auth/mfa/verify are NOT application endpoints — Keycloak owns username/password and MFA challenge flows. Application receives validated JWT token from Keycloak.

Module: identity / tenant (multi-tenant isolation enforced)
- GET /v1/tenants — list (filtered by MSP parent if applicable)
- POST /v1/tenants — create (high-risk; audit + approval for MSP admins)
- GET /v1/tenants/{id} — read (must match user's tenant or MSP scope)
- PATCH /v1/tenants/{id} — update (tenant-specific settings)
- DELETE /v1/tenants/{id} — deactivate/suspend (not hard delete; retention policy applies)

Module: users / access
- GET /v1/users — list (tenant-scoped)
- POST /v1/users — create
- PATCH /v1/users/{id} — update
- DELETE /v1/users/{id} — deactivate
- GET /v1/roles — list roles
- POST /v1/roles — create role
- PATCH /v1/permissions — ABAC permission rules

Module: api-keys / service-accounts
- POST /v1/api-keys — create (scope-defined; hashed storage)
- DELETE /v1/api-keys/{id} — revoke
- GET /v1/service-accounts — list
- POST /v1/service-accounts — create

Module: session
- GET /v1/sessions — list current sessions
- DELETE /v1/sessions/{id} — revoke

Module: settings
- GET /v1/settings/{category} — read (modular categories: General, Identity, Security, Agents, Notifications, Storage, Query, AI, Audit, Health)
- PATCH /v1/settings/{category} — update (audit event generated)

Module: audit
- GET /v1/audit/events — read with filters: user, tenant, action, resource, time_range
- POST /v1/audit/export — export (restricted to admin roles; approval for high-volume export)

Module: health / platform (self-managing skeleton in Phase 2, framework in Phase 1)
- GET /v1/health/status — basic platform health (auth service, gateway, DB connection)

## Internal Control Plane APIs (not public UI-facing; still auth/tenant/policy protected)
Internal APIs use same gateway/auth but are restricted to service accounts / control-plane role:
- POST /internal/control/job — submit desired state (start/restart/scale/deploy/rollback)
- GET /internal/control/job/{id} — job status (pending, approved, executing, verified, rolled_back, failed)
- PATCH /internal/control/job/{id}/approve — approval action
- GET /internal/control/dependency/{resource} — change impact analysis
- POST /internal/control/rollback/{resource} — trigger rollback

## Authentication Flow
1. Client sends token / session cookie / API key in Authorization header
2. Gateway validates token/session (Keycloak JWT or session store check)
3. Gateway extracts tenant_id + user_id + role + session_id
4. Middleware attaches tenant context; queries DB with tenant filter
5. RBAC checks role.permission for endpoint module
6. ABAC checks attribute rules (resource, action, time, tenant)
7. Endpoint executes; audit event written

## Error Model (Standardized)
Every response: { success: bool, data?, error?: { code, message, details?, audit_event_id?, request_id? } }
Error codes: AUTH_MISSING, AUTH_INVALID, MFA_REQUIRED, TENANT_MISMATCH, RBAC_DENIED, ABAC_DENIED, RATE_LIMITED, NOT_FOUND, INTERNAL_ERROR, CONTROL_HIGH_RISK_APPROVAL_REQUIRED, CONTROL_ROLLBACK_FAILED

## Rate Limits (Per Tenant / Per User)
- Auth endpoints: 5/min per IP; 30/min per user
- Read endpoints: 100/min per user; 300/min per tenant
- Write endpoints (settings, users, roles): 20/min per user; 100/min per tenant
- Audit export: 1/hour per user; approval required for bulk
- Internal control endpoints: restricted; audit every call

## Keycloak / Auth Boundary (DESIGN DECISION)
FACT: Keycloak is an identity provider; our application is a relying party.
DESIGN DECISION: Keycloak performs authentication (login, MFA verification, token issuance, token refresh, SSO). Our application validates tokens, manages sessions (with Keycloak token reference), and enforces authorization (RBAC/ABAC).
- /auth/login and /auth/mfa/verify removed from application API — Keycloak owns these.
- Our application endpoints: session management, token refresh (via Keycloak), logout (application + Keycloak), authorization checks.
- Token validation: Keycloak JWT public key verification (local or JWKS endpoint); no custom token format.
- Refresh token: stored in application session store (reference); Keycloak manages token lifecycle.
