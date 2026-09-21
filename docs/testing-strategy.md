# Testing Strategy

Status: DESIGN (for Phase 1 verification and continuous)

## Layers
- Unit: module functions (auth, tenant, RBAC, settings, audit)
- Integration: Keycloak + API Gateway + PostgreSQL + module services
- E2E: login → MFA → tenant → settings change → audit read → logout
- Security: cross-tenant access attempts (must fail), session hijacking tests, brute-force, API key scope, RBAC bypass
- Load: API rate limits, DB concurrent queries, audit event volume

## CI / Pipeline
- Dependency scanning (SCA): verify all open-source licenses compliant (docs/open-source-stack.md criteria)
- Static analysis (SAST): security vulnerabilities
- Test run: automated on PR; must pass before merge
- Migration test: schema changes verified backward-compatible
- Security regression: cross-tenant query tests must always pass

## Phase 1 Specific Tests
- Auth: valid/invalid login, MFA required after N attempts, SSO redirect, token refresh, session revocation
- Tenant: create/read/update/deactivate; cross-tenant access blocked; MSP parent visibility correct; quota enforcement
- RBAC: role creation; permission assignment; role change affects access immediately; denied actions blocked
- ABAC: attribute rules (user + tenant + resource + time); deny when attributes mismatch
- Settings: read/update per category; audit event generated; unauthorized settings blocked
- Audit: event recorded for every action; filter by tenant; export restricted; audit event IDs present in errors
- Security: API keys scoped; service accounts restricted; no secrets in repos/config; TLS required

## Phase 1 Security Tests — Required (DESIGN DECISION — from second planning pass)
- Cross-tenant API access: tenant A token → tenant B endpoint (must fail; audit event)
- Cross-tenant DB query: session set to A; query B table row (must fail; RLS denies)
- RLS bypass attempt: manipulate session variable to wrong tenant (must fail)
- MSP parent → authorized child tenant (must succeed; audit event)
- MSP parent → unauthorized child tenant (must fail; audit event)
- Platform admin access to tenant data without authorization (must fail)
- Role escalation: user gets new role; old-access resources must be re-validated
- ABAC bypass: attribute rules not enforced (must fail)
- Token replay: same JWT reused after revocation (must fail)
- Revoked session: session revoked; subsequent request fails; audit
- Revoked API key: key revoked; request fails
- Expired token: access token past lifetime (must fail; refresh required)
- MFA bypass: attempt without completed MFA claim (must fail)
- SSO state/nonce validation: replay attack on SAML/ OIDC (must fail)
- CSRF: state validation required where applicable
- Rate limiting: exceed limits; must be blocked; audit
- Secret leakage: audit/event/log must not contain secret values; verify scanning
- Audit tampering: audit table protected (RLS + no direct delete for non-admin)
- Authorization failure auditing: every denied access must create audit event (no silent denial)
