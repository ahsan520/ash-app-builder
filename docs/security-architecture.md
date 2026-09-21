# Security Architecture

## Threat Model (Platform Itself)
- Tenant isolation failure: attacker accesses another tenant's data
- Authentication bypass: weak MFA / session management / API key exposure
- Authorization escalation: RBAC / ABAC bypass; privilege escalation
- Data exposure: unencrypted storage; TLS misconfiguration; key management failure
- Supply chain: malicious dependency; unverified open-source component
- Container / Kubernetes security: container escape; insufficient network segmentation; insecure defaults
- AI tool misuse: unrestricted AI access to backend; missing audit; no permission checks
- Control plane misuse: unapproved high-risk actions; rollback failure; audit missing
- Insider threat: admin can access all tenants improperly; audit missing

## Mitigations by Layer

### Identity / Auth
- Keycloak: MFA (TOTP, WebAuthn/passkeys), SSO (OIDC, SAML), session management, password/auth policies
- IP restrictions available
- API keys scoped per tenant; service accounts with role assignment
- Audit: all auth events, session events, password changes, MFA changes

### Authorization
- RBAC (roles, permissions) + ABAC (attributes: tenant, resource, time, action)
- Policy engine enforces approval rules before control actions
- Least privilege: default deny; minimum permissions assigned

### Data Protection
- Encryption at rest (storage layer, database, message bus)
- Encryption in transit (TLS for all APIs, internal service communication, UI to API)
- Key management (KMS / secrets manager integration; secrets not in config files)
- Secret rotation / expiration monitoring (part of self-managing SIEM)

### Network / Segmentation
- Internal service mesh or network policies separate modules
- API Gateway is single entry point; backend services not exposed externally
- Control Plane communicates through secure channels; not exposed to UI directly

### Container / Kubernetes
- Secure defaults: non-root containers, read-only file systems, resource limits
- Container scanning / dependency scanning (SCA / SAST / DAST)
- Network policies restrict inter-module traffic; only allowed through event bus / API

### AI / Agent Security
- Tool Registry defines allowed actions
- Every AI action: Permission Check → Tenant Check → Action Policy → Audit
- Never allow unrestricted backend access
- AI actions logged with full audit
- Model routing controlled; cost/usage limits enforced

### Control Plane Security
- High-risk actions require approval
- Low-risk/reversible actions allowed only with configured autonomy level per resource/action
- Every control action audits: user, role, resource, action, result, rollback state
- Change Impact Analysis shows risk before approval
- Rollback plans recorded before execution

### Supply Chain
- Every dependency verified: license, activity, security track record
- Dependency scanning integrated into CI
- Lock files maintained; updates reviewed before deployment
