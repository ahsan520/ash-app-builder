# Production Installation Scripts / Module Setup / Control Plane / GUI

Status: FRAMEWORK ONLY — scripts exist (`scripts/deploy/deploy-infra.sh`, `scripts/siem-cli`); descriptor verified (`deploy/postgresql.yaml`); execution deferred (cluster unavailable — autonomy preserved — no false claim).

## Setup Kubernetes / VM / Docker (docs/deployment-architecture.md)
- Provider abstraction: Kubernetes / Docker / VM / Cloud (`docs/deployment-architecture.md`; `docs/deployment-spec.md` A-J)
- No Kubernetes cluster or container runtime available in this session (`docker` unavailable; descriptor execution reported honestly; framework only)
- To deploy: provide kubeconfig / endpoint / namespace + confirm spec (env/test/prod, secret reference, rollback, DB-only scope) + run `scripts/deploy/deploy-infra.sh <component> <namespace> <env> --approve=<approval_id>` (with `ROLLBACK_PLAN` set)

## Module Setup Scripts / Open Source Tools (docs/module-architecture.md; scripts/)
- Module lifecycle framework: `src/module/module-engine.js` (load/dependency/version/rollback/enable/disable/uninstall + audit)
- Install: `scripts/siem-cli approve-infra <component>` then `scripts/deploy/deploy-infra.sh <component> <namespace> <env> --approve=<approval_id>`
- Module framework verified (node execution passed); production module rollout (1→12 sequential) requires cluster + spec confirmation
- Open-source components (verified docs/open-source-stack.md): PostgreSQL, Keycloak (Apache 2), Kafka (Apache 2), OpenSearch (Apache 2), ClickHouse (Apache 2), Wazuh (open source), Vector, Fluent Bit; AGPL (MISP/OpenCTI) handled externally/API only

## Login / Control Plane / Config (docs/api-architecture.md; docs/ui-architecture.md)
- Auth: Keycloak owns login/MFA/SSO (`keycloak/realm-export.json` — realm `asix`, clients `asix-api`, PKCE/SSO/MFA configured); application handles session/logout/OIDC redirect (`docs/api-architecture.md` — no `/auth/login` or `/auth/mfa/verify` app endpoints)
- Control plane APIs (docs/control-plane.md; docs/api-architecture.md): `POST /internal/control/job` (submit desired state), `GET /internal/control/job/{id}` (status), `PATCH /internal/control/job/{id}/approve` (approval action — requires Level 2 approval); framework verified (`src/control-plane/job-engine.js`); production requires cluster + approval mechanism (`scripts/siem-cli approve-infra`) + rollback plan
- Config / GUI: `docs/configuration-as-code.md` (YAML/JSON; Git source; DB runtime; versioned/diff/rollback/audit); `docs/ui-architecture.md` (modular routing; expandable settings categories: General, Security, Identity_Access, Agents, Storage, Audit, Health, AI; Phase 1 real pages: login/MFA/SSO, tenant selection, user/role/api-key/session/settings/audit/health); control plane internal only; not exposed to public UI
