# Deployment Architecture — Module → Pod / VM / Service Mapping

Status: DESIGN ONLY (framework verified; descriptor framework only; execution deferred — cluster unavailable — no false claim).
Reference: docs/deployment-architecture.md + docs/deployment-spec.md (A-J) + docs/module-architecture.md + docs/open-source-stack.md + deploy/*.yaml.

## Module → Infrastructure Component Mapping
- `siem` → DB (PostgreSQL) + Search (OpenSearch) + Analytics (ClickHouse) — ingestion + correlation + dashboard
- `xdr` → DB (entity storage) + Network policies + Service mesh — endpoint/network/identity/cloud telemetry + behavioral analytics
- `soar` → Control Plane (internal service) — playbooks + case + investigation + approval/rollback
- `threat-intel` → External feed (MISP/OpenCTI — AGPL, API only) — no embedded dependency; watchlists + reputation
- `cases` → DB (case/evidence/timeline) + Module framework — case management + incident tracking
- `posture` → Storage/search layer — security posture + vulnerability correlation
- `inventory` → DB (asset/user/IP/device) — asset inventory + user/device mapping
- `collectors` / `brokers` → Message bus (Kafka 3.9; Replication factor 3) — ingestion pipeline + collector framework
- `ai` → Control Plane (internal only) — AI agent framework + tool registry; no unrestricted backend/DB/infrastructure access
- `reports` / `compliance` → DB (audit/export/retention) + Storage/Observability — audit/compliance/reports

## Infrastructure Component Mapping (A-J specs — docs/deployment-spec.md)
A. DB: PostgreSQL 16-alpine (replication 2; RLS 5 policies: tenants/users/roles/audit_events/sessions; migrations from src/db/schema.sql)
B. Keycloak: Keycloak 26.0 HA (realm `siem-platform`; clients `siem-api`; flows: oidc-pkce/saml/mfa-totp/webauthn; external container descriptor deploy/keycloak-ha.yaml)
C. Gateway: Kong / Custom lightweight gateway (TLS + auth forwarding + rate limits + RBAC/ABAC + audit; descriptor deploy/kong-gateway.yaml; framework src/gateway/middleware.js)
D. Secrets: K8s Secret / HashiCorp Vault (SecretsProvider abstraction; descriptor line 9: `${DB_PASSWORD}`; docs/plan.md H.7)
E. Message Bus: Kafka 3.9 (Apache 2; replication factor 3; durable event bus; framework src/ingestion/normalization.js connects to broker pipeline in Phase 3/4)
F. Storage / Search: OpenSearch (hot; Apache 2; verified opensearch.org) + ClickHouse (analytics; Apache 2; verified) + S3/MinIO archive; framework search (src/search/search-engine.js; query/expensive/save/delete framework)
G. Observability: Prometheus + Grafana + Loki (metrics/logs; self-managing framework; framework metric framework exists; descriptor framework only)
H. Network / TLS / Security: Internal service mesh / TLS everywhere / non-root containers / read-only FS / network policies (docs/deployment-architecture.md; descriptor framework)
I. Backup / DR: DB backups (daily); audit continuous; settings/config versioned (Git); rollback = DB snapshot + restore (docs/upgrade-rollback.md + descriptor rollback_plan line 13)
J. Module rollout: Sequential 1→12 (Phase 1 verified → Phase 12 framework verified; module framework: install/configure/enable/upgrade/disable/uninstall + dependency + rollback; framework verified; descriptor not executed)
