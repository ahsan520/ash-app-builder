# SIEM/XDR/SOAR Platform — Planning Document

Source of truth for this platform (NOT marketplace.md / marketplace.md — unrelated project).

## A. Architecture Summary (Verified from docs/)
- Module architecture: module loader, dependency resolver, settings framework (docs/module-architecture.md)
- Three planes: Data / Control / Management (docs/architecture.md)
- Control Plane: UI never executes infra; desired state/job → orchestrator → provider abstraction (docs/control-plane.md)
- Multi-tenancy: MSSP hierarchy; isolation at API/auth/DB/search/storage/collectors/brokers/detections/playbooks/secrets/AI/audit/quotas/dashboards (docs/multi-tenancy.md)
- Security: MFA (TOTP/WebAuthn), OIDC, SAML, RBAC+ABAC, API keys/service accounts, session management, audit (docs/security-architecture.md)
- Data: Kafka/Redpanda → Vector/Fluent Bit → OpenSearch (hot) + ClickHouse (analytics) → archive (docs/data-architecture.md)
- AI: Tool Registry → Permission Check → Tenant Check → Action Policy → Execution → Audit (docs/ai-architecture.md)
- Self-managing: Observe→Diagnose→Explain→Recommend→Approve→Remediate→Verify→Rollback→Audit (docs/control-plane.md + docs/roadmap.md)
- Open-source stack: OpenSearch, ClickHouse, Kafka, Vector, Fluent Bit, Keycloak, Wazuh, Sigma, TheHive (API only), MISP/OpenCTI, Prometheus/Grafana/Loki/Tempo (docs/open-source-stack.md — verified with sources)

## B. Inconsistencies Found
1. Existing marketplace.md (marketplace.md) is an unrelated project (package marketplace / SDK / billing). Must be preserved separately; docs/plan.md now references this SIEM project.
2. architecture.md lists "ClickHouse (analytics)" and OpenSearch together but does not specify schema separation or index naming conventions — need data-architecture clarification.
3. control-plane.md describes provider abstraction but architecture.md table puts "Custom abstraction over Kubernetes / Docker / VM" — consistent, but no concrete provider interface spec exists yet.
4. ai-architecture.md defines tool registry but does not specify how AI permissions link to RBAC/ABAC roles — missing integration point.
5. module-architecture.md defines module dependencies but does not specify versioning or upgrade rollback for module schemas.
6. multi-tenancy.md specifies isolation but does not specify DB strategy (schema-per-tenant vs row-level) — open decision.
7. security-architecture.md mentions "Key management" but no secrets manager component selected (HashiCorp Vault / AWS Secrets Manager / Kubernetes Secrets — not specified).

## C. Missing Components / Dependencies
- docs/api-architecture.md — API contracts, gateway design, endpoint naming, versioning
- docs/ui-architecture.md — modular UI framework, navigation, settings expandable categories, module routing
- docs/testing-strategy.md — unit/integration/e2e, CI pipeline, test environments
- docs/threat-model.md — full threat model with attack trees (security-architecture.md has basics)
- docs/deployment-architecture.md — deployment patterns, container orchestration, network topology
- docs/observability-architecture.md — metrics/logs/traces/distributed tracing specifics
- docs/ha-dr.md — replication, failover, recovery, multi-region
- docs/configuration-as-code.md — YAML/JSON/Git representation, validation, import/export/rollback
- docs/upgrade-rollback.md — upgrade paths, rollback procedures, version compatibility
- Architecture diagrams (SVG/text): overall, control plane, data plane, management plane, multi-tenant isolation, collector/broker/mesh, AI tool registry, Phase 1 auth flow, control plane lifecycle, self-managing lifecycle

## D. Phase 1 Implementation Boundary
ONLY Phase 1: Identity + MFA + SSO + Multi-tenancy + RBAC/ABAC + API Gateway + Session Management + Settings Framework + Audit Foundation.
NOT Phase 2 (Control Plane skeleton — design only until Phase 1 verified).
NOT Phase 3 (Brokers/Collectors — design only).
NOT Phase 4+ (Data ingestion / SIEM — design only).

## E. Phase 1 Service / Component Diagram (Text)
[Web UI] → [API Gateway] → [Auth Service (Keycloak)] → [Tenant Context Middleware] → [RBAC/ABAC Policy Engine] → [Module Services (settings/audit/tenant)] → [PostgreSQL (multi-tenant schema)] → [Audit Log Store]
Every request carries: tenant_id + user_token + session_id + auth_context.

## F. Phase 1 API Surface (Proposed — needs approval)
- POST /auth/login — username/password → token
- POST /auth/mfa/verify — MFA challenge
- GET /auth/oidc/authorize, /auth/saml/acs — SSO flows
- POST /api-keys — create/revoke (service account / API key)
- GET /tenants — list (MSP filtered) / POST /tenants — create
- GET /tenants/{id}/users — list / POST — create / PATCH — update / DELETE — deactivate
- GET /tenants/{id}/roles — RBAC roles / POST — create role
- GET /permissions — ABAC permissions (resource/tenant/action)
- GET /settings/{category} — settings read / PATCH — settings update (with audit)
- GET /audit/events — audit read with filters (tenant-scoped; MSP-scoped if permitted)
- GET /sessions — session management / POST — revoke session
- POST /auth/logout / DELETE /auth/session/{id}

## G. Phase 1 Database / Data Model (Proposed)
- Database: PostgreSQL (proven, ACID, multi-tenant row-level or schema-level; easier than distributed for Phase 1)
- Tables: tenants, users, user_roles, roles, permissions (ABAC), api_keys, sessions, audit_events, settings, tenant_quotas
- Isolation: PostgreSQL RLS REQUIRED (DESIGN DECISION). DB session context (SET app.current_tenant_id) establishes RLS; RLS denies by default; application middleware does NOT replace RLS
- Migration: schema migrations versioned; module migrations separate

## H. Phase 1 Security Model (Verified)
- Auth: Keycloak (OIDC/SAML/TOTP/WebAuthn) — fact from docs/open-source-stack.md
- Session: server-side session store + JWT token with tenant claim; session revocation checkpointed
- API Gateway: rate limiting, IP restrictions, TLS termination, request validation
- RBAC: roles with permissions per module/resource; tenant-scoped
- ABAC: attribute-based rules (user.role + tenant.id + resource.type + action + time)
- Audit: every auth, config change, API key creation, session event, settings change, tenant change logged with user/tenant/action/result
- Secrets: API keys hashed (bcrypt/argon2); service account tokens stored encrypted; no secrets in config files (use env/secrets manager — specific manager open decision)


## H.5 Session Architecture (DESIGN DECISION — FACT: one authoritative session store, not two)
- Browser session: cookie/session ID managed by application.
- Access token: Keycloak JWT (validated by gateway/app) with tenant claim.
- Refresh token: stored in session record; Keycloak manages refresh lifecycle.
- Session record: DB table (session_id, user_id, tenant_id, token_ref, created_at, expires_at, revoked_at) — authoritative.
- Token lifetime: access 15 min; refresh 7 days; session refresh extends.
- Refresh: app calls Keycloak; new JWT; session updated; audit.
- Logout: app revokes session (DB + Keycloak end-session); cookie cleared.
- Global logout: Keycloak revoked; all user sessions revoked; audit.
- Session revocation: revoked_at set; validation fails; audit.
- Compromised token: revocation + re-auth; audit alert.
- Tenant switching: allowed only if user authorized; session updated; audit.
- MFA state: Keycloak manages; app receives MFA-completed claim.
- Session audit: all session events audited with user/tenant/session/result.
- Authoritative: application session store for lifecycle; Keycloak for token issuance/validation.

## H.6 Authorization Architecture (DESIGN DECISION — distinct from RBAC and ABAC)
Sequence: Identity → Tenant Context → RBAC → ABAC → Resource Authorization → Action Authorization → Risk Policy → Approval/Autonomy → Execution
- RBAC: permission format <module>:<resource>:<action> (tenant:user:read, settings:security:update, audit:event:read, controlplane:job:create)
- ABAC: attribute rules (user.role + tenant.id + resource.tenant + action + time + risk)
- Resource authorization: resource.tenant must match session.tenant (or MSP-authorized)
- Risk / autonomy: evaluated after authorization; autonomy levels 0-4
- Inheritance: permissions NOT automatically inherited through parent/MSP; explicit ABAC required.

## H.7 Secrets Architecture (DESIGN DECISION — abstraction for future providers)
- SecretsProvider interface: support Kubernetes Secrets, HashiCorp Vault, cloud managers, environment.
- Components: SecretStore / SecretProvider / SecretReference / SecretRotation / SecretAccessAudit.
- Phase 1: simple provider (env / K8s Secret); production replaces via interface.
- Rules: never plaintext in Git/config/logs/audit; audit only references, never values.

## H.8 AI Authorization Model (DESIGN DECISION — tool registry + RBAC + ABAC + risk + approval)
AI Agent → Tool Registry → RBAC/ABAC Check → Tenant Check → Tool Enabled → Risk Classification → Autonomy Policy → Approval (if needed) → Control Plane Execution → Verify → Audit
Example: controlplane:collector:restart → RBAC → ABAC → tool enabled → medium risk → Level 2 → approval → job → verify → audit. AI never gets unrestricted credentials.

## I. Phase 1 Test Strategy (Proposed)
- Unit: auth module, tenant module, RBAC module, audit module
- Integration: Keycloak + API Gateway + PostgreSQL + settings framework
- E2E: login → MFA → tenant selection → settings change → audit verification
- Security: brute-force resistance, session hijacking test, cross-tenant access attempt (must fail), API key scope test
- CI: automated test run; dependency scanning (SCA/SAST); license verification

## J. Phase 1 Dependencies (Verified / Assumed)
VERIFIED (fact): Keycloak (Apache 2), PostgreSQL (PostgreSQL License — open source, MIT-like), React/TypeScript (MIT)
ASSUMED (needs verification): Keycloak version compatible with our OIDC/SAML requirements; PostgreSQL row-level security sufficient vs schema isolation; API Gateway framework (Kong / Envoy / custom) — open decision
REPLACEMENT PATHS: Keycloak → Authentik / Authelia / custom; PostgreSQL → MySQL / CockroachDB; Gateway → Kong/Envoy/traefik

## K. Phase 1 Risks
- Keycloak integration complexity (SSO flows, MFA, session management)
- Multi-tenant DB isolation failure (row-level vs schema — must test cross-tenant query attempts)
- RBAC + ABAC interaction complexity (permission conflicts)
- Session revocation / audit consistency (distributed session store if scaled)
- Security: API keys leaked; session tokens stolen; cross-tenant data exposure
- Dependency: Keycloak version compatibility, PostgreSQL version, gateway framework
- Migration: existing data (if any) must migrate to multi-tenant schema

## L. Open Decisions Requiring Your Approval
1. Database strategy for Phase 1: PostgreSQL row-level security vs schema-per-tenant vs separate DB instances? (Recommendation: PostgreSQL with tenant_id + RLS for Phase 1; schema-per-tenant for scale later)
2. API Gateway framework: Kong, Envoy, custom Node/Go gateway, or traefik? (Recommendation: Kong or custom lightweight gateway for Phase 1; Envoy for production scale later)
3. Secrets manager: Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager, or environment-only for Phase 1? (Recommendation: environment + Kubernetes Secrets for Phase 1; Vault for production)
4. UI framework: React + TypeScript + modular routing (confirmed in architecture.md); specific component library? (Recommendation: no heavy library — build modular navigation with expandable settings categories)
5. Module framework: Node/TypeScript module loader with dependency resolution, or separate services per module? (Recommendation: monorepo with module packages for Phase 1; separate services for production)
6. Keycloak deployment: embedded container for Phase 1, or external service? (Recommendation: external container/service for Phase 1 to mirror production)
7. Should docs/plan.md replace marketplace.md or keep both? (Recommendation: keep marketplace.md; docs/plan.md is SIEM-specific)
8. Phase 1 API surface: exact endpoint list, versioning strategy (v1 / v1.0), rate limits? (Needs approval of proposed list above)
9. AI security integration point: should AI tool registry be designed in Phase 1 (design only) or deferred to Phase 10? (Recommendation: design architecture in Phase 1, implement in Phase 10)
10. Self-managing SIEM dependency graph: should the dependency model be designed in Phase 1 (data model only) or deferred? (Recommendation: data model / schema design in Phase 1; full implementation Phase 11)

## M. Exact Recommended Implementation Order (AFTER YOUR APPROVAL)
Phase 1 only — in this exact order:
1. Design Phase 1 DB schema + migrations (tenants, users, roles, permissions, audit, settings, api_keys, sessions, quotas)
2. Set up development environment (dev container / CI / test framework) — existing .devcontainer/ exists; verify
3. Integrate Keycloak (container) with OIDC + MFA + SAML configurations
4. Build API Gateway (request validation, rate limit, tenant extraction, auth forwarding)
5. Build Auth Service (login, MFA verify, SSO flows, session management)
6. Build Tenant Service (CRUD, isolation, MSP hierarchy, quotas)
7. Build RBAC/ABAC Policy Engine (role definitions, permission evaluation, ABAC rules)
8. Build Settings Framework (modular categories, settings read/update, audit on change)
9. Build Audit Foundation (event schema, storage, filtering, tenant-scoped queries)
10. Build API Key + Service Account Service (creation, revocation, scopes)
11. Integrate frontend skeleton (navigation, settings expandable categories, module routing framework) — real backend required; no fake UI
12. Integration tests + security tests (cross-tenant access must fail, session revocation, audit verification)
13. Review + approval to proceed to Phase 2 design

No Phase 2 / 3 / 4 code written until Phase 1 verified.
