# Threat Model

Status: DESIGN (expanded from docs/security-architecture.md)

## Assets
- Tenant data (events, alerts, cases, audit)
- Authentication tokens / sessions
- API keys / service accounts
- Configuration (settings, roles, permissions, policies)
- Control Plane jobs (desired state, execution records)
- AI tool access / audit
- Secrets (credentials, certificates, keys)
- Platform health / metrics

## Threat Actors
- External attacker (unauthenticated / stolen credentials)
- Malicious insider (tenant admin / MSP admin / platform admin)
- Compromised service account / API key
- Supply chain attacker (malicious dependency / container image)
- AI misuse (uncontrolled AI tool access)

## Threat Scenarios
- Cross-tenant data access: attacker with tenant A creds tries to access tenant B (must fail at DB, API, audit)
- Session hijacking: stolen token used; revocation must block immediately
- RBAC escalation: user gets new role; must not access resources outside role
- ABAC bypass: attribute rules not enforced; must check every endpoint
- API key leak: external attacker uses key; must be revocable; scope must restrict
- Control plane misuse: high-risk action executed without approval; approval required; audit must show attempt
- AI unrestricted access: AI executes arbitrary backend command; tool registry + permission check must block
- Secret exposure: secrets in config / logs / audit; secrets must be hashed/encrypted; audit must not expose raw secrets
- Database isolation failure: query missing tenant filter; RLS / middleware must enforce
- Supply chain: malicious dependency; scanning + lock files + license check
- Configuration drift: unexpected config change; self-managing SIEM must detect

## Mitigations (Mapped)
- Authentication (Keycloak + MFA + SSO) → external attacker / stolen creds
- Authorization (RBAC + ABAC + Policy Engine) → insider / escalation
- Audit (every action) → detection / forensics / accountability
- Multi-tenancy (isolation at all layers) → cross-tenant access
- Control Plane (approval + rollback + audit) → unauthorized infra changes
- AI (tool registry + permission + audit) → AI misuse
- Secrets management → secret exposure
- Supply chain scanning → supply chain
- Self-managing (observe/diagnose/remediate) → drift / failure
