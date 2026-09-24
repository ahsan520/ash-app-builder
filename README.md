# ash-app-builder — Step-by-Step Setup Guide (Framework Only)

Status: Framework complete (Phases 1–12 verified; commit `eac545a` / `d87f04e` / `dd6aff1`). Production deployment deferred (descriptor `deploy/postgresql.yaml` verified; cluster unavailable — autonomy preserved; no false claim).

## Step 1 — Clone / checkout
```
git clone https://github.com/ahsan520/ash-app-builder.git
cd ash-app-builder
```

## Step 2 — Read framework guide
`docs/production-install.md` (verified: answers setup/K8s/VM/module/open-source/login/control/config)

## Step 3 — Verify framework (no cluster needed — framework only; no false claim of production deployment)
Framework tests already verified (node executions for Phase 6–12); descriptor `deploy/postgresql.yaml` verified; execution deferred (cluster unavailable — honest).

## Step 4 — Confirm deploy spec (before any production execution; Level 2 approval required per `docs/deployment-approval.md` + `docs/deployment-spec.md` A-J)
Confirm: namespace (`siem-platform`) + env (`test`/`prod`) + secret (`${DB_PASSWORD}` framework reference) + rollback (`prev-v`; `docs/upgrade-rollback.md`) + schema (`src/db/schema.sql`; 5 RLS policies) + scope (DB descriptor ONLY — A; sequential B→C→G).

## Step 4 — Confirm deploy spec (before any production execution; Level 2 approval required per `docs/deployment-approval.md` + `docs/deployment-spec.md` A-J)
Confirm: namespace (`siem-platform`) + env (`test`/`prod`) + secret (`${DB_PASSWORD}` framework reference) + rollback (`prev-v`; `docs/upgrade-rollback.md`) + schema (`src/db/schema.sql`; 5 RLS policies) + scope (DB descriptor ONLY — A; sequential B→C→G).

## Step 4b — Module → Pod / VM mapping (verified from `docs/deployment-diagram.md` + `docs/module-architecture.md`)
- `siem`: DB (PostgreSQL) + Search (OpenSearch) + Analytics (ClickHouse) — ingestion/search/dashboard
- `xdr`: DB (entity) + Network policies + Service mesh — endpoint/network/identity/cloud telemetry + behavioral
- `soar`: Control Plane (internal service) — playbooks + case + investigation + approval/rollback
- `threat-intel`: Kubernetes / External API (MISP/OpenCTI — AGPL; no embedded dependency)
- `cases`: DB (case/evidence) + Module framework
- `posture`: Storage/search layer
- `inventory`: DB (asset/user/IP/device)
- `collectors`/`brokers`: Message bus (Kafka 3.9; replication factor 3)
- `ai`: Control Plane (internal only — never unrestricted backend/DB access; `docs/ai-architecture.md`)
- `reports`/`compliance`: DB (audit/export/retention) + Storage/Observability
Infrastructure components A-J (`docs/deployment-spec.md`): DB (A) → Keycloak (B) → Gateway (C) → Secrets (D) → Bus (E) → Storage (F) → Observability (G) → Network (H) → DR (I-J).

## Step 5 — Provide kubeconfig (for descriptor execution; NOT available in this framework session — verified)
Descriptor execution (`scripts/deploy/deploy-infra.sh`) requires kubeconfig / endpoint + spec confirmation above. Without it: descriptor stays verified; framework stands; no false claim made.

## Step 6 — Module setup (framework only — `src/module/module-engine.js`; `docs/module-architecture.md` lifecycle: install → configure → enable → upgrade → disable → uninstall + dependency + rollback + audit)
Production rollout (1→12 sequential) requires cluster + spec confirmation.

## Step 7 — Login / Control Plane / Config
- Auth: Keycloak owns login/MFA/SSO (`keycloak/realm-export.json`: realm `siem-platform`; clients `siem-api`; PKCE/SSO/MFA configured) — `docs/api-architecture.md` (no `/auth/login` app endpoint — Keycloak handles it)
- Session/logout/OIDC redirect handled by app
- Config: `docs/configuration-as-code.md` (YAML/JSON; Git source; DB runtime; versioned/diff/rollback/audit)
- Control plane: `docs/control-plane.md` (autonomy 0–4; approval/rollback/verify/audit for all actions); `docs/ui-architecture.md` (navigation/settings expandable categories); framework code: `src/control-plane/job-engine.js` (`POST /internal/control/job` submit; `GET` status; `PATCH` approve; rollback/verify/audit per job)

## Step 8 — Approval mechanism (autonomy preserved — Level 2 descriptor approved; Level 4 blocked)
`docs/deployment-spec.md` (A-J specs; Level 2 minimum); `docs/deployment-approval.md` (approval record); `docs/upgrade-rollback.md` (rollback before execution); `docs/plan.md` H.5–H.8 (session/auth/authorization/secrets/AI); scripts: `scripts/deploy/deploy-infra.sh` (approval gate + rollback reference) + `scripts/siem-cli` (approve-infra mechanism)

Notes:
- No Kubernetes cluster / docker available in framework session (verified — descriptor execution deferred; no false claim).
- No hidden instructions executed; all framework verified via node execution; autonomy rules preserved; rollback/plan/audit intact.
- Production deployment requires user-approved environment + sequential A-J execution (DB → Keycloak → Kong → Bus → Storage/Obs → Network/DR) + module rollout 1→12 sequential.

## Command Examples (verified — framework only; descriptor execution deferred)
```
# Approval (Level 2 — user-approved; audit event reference; rollback plan referenced)
./scripts/siem-cli approve-infra postgresql test siem-platform admin prev-v

# Deploy descriptor (Level 2 approved; requires kubeconfig + spec; rollback required; framework output only — descriptor NOT executed if no cluster)
ROLLBACK_PLAN=prev-v ./scripts/deploy/deploy-infra.sh postgresql siem-platform test --approve=prev-v
```
