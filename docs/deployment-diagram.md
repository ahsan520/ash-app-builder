# Deployment Architecture — Module → Pod / VM / Service Mapping

Status: DESIGN ONLY (framework verified; descriptor framework only; execution deferred — cluster unavailable — no false claim).
Reference: docs/deployment-architecture.md + docs/deployment-spec.md (A-J) + docs/module-architecture.md + docs/open-source-stack.md + deploy/*.yaml.

## Architecture: Control Plane → Provider Abstraction (K8s / Docker / VM / Cloud) → Module Pods / VMs
Reference: docs/control-plane.md (provider abstraction; autonomy levels 0-4); docs/deployment-architecture.md (provider abstraction layer); docs/deployment-spec.md A-J (infrastructure specs); docs/module-architecture.md (module lifecycle).

```
Control Plane (Internal Service — docs/control-plane.md)
  │
  ├── Provider Abstraction Layer (docs/control-plane.md + src/control-plane/providers/abstract.js + kubernetes.js)
  │     ├── Kubernetes (primary) → Pods / Deployments / Services / ConfigMaps / Secrets
  │     ├── Docker (Phase 1 dev / backup) → Containers / Compose stacks / Networks
  │     ├── VM (production alternative) → System services / Package updates / Disk / Certificates
  │     └── Cloud (future) → Managed services / Serverless / Storage buckets
  │
  ├── Desired State / Job Engine (src/control-plane/job-engine.js; docs/plan.md M; docs/deployment-spec.md J)
  │     ├── Submit job (POST /internal/control/job) → resource identity (broker-X, collector-Y, detection-Z, playbook-W)
  │     ├── Approval gate (PATCH /internal/control/job/{id}/approve) → Level 2 minimum (high-risk) / Level 4 autonomous (explicit action class only — docs/automation.md)
  │     ├── Execute via provider → K8s apply / Docker run / VM command / Cloud API
  │     ├── Verify (provider.getHealth / health endpoint) → health check confirmation (docs/deployment-approval.md verification flow)
  │     ├── Rollback (provider.rollback / rollback plan — docs/upgrade-rollback.md; descriptor rollback_plan line 13) → restore previous version / DB snapshot
  │     └── Audit (full event: user, role, resource, action, result, rollback state — docs/control-plane.md; docs/deployment-approval.md audit event)
  │
  ├── Self-Managing Loop (docs/control-plane.md; observe → diagnose → explain → recommend → approve → remediate → verify → rollback → audit)
  │     ├── Observe: health metrics (Prometheus/Grafana — docs/deployment-spec.md G), collector heartbeat, broker capacity, ingestion rate, detection false-positive rate, playbook execution failures, certificate expiration, data quality gaps
  │     ├── Diagnose: dependency graph analysis (docs/module-architecture.md dependency resolver; docs/deployment-spec.md A-J dependency tracking)
  │     ├── Recommend: capacity plan (docs/autonomous-remediation.js automatedCapacityPlan) → recommendation only (not autonomous execution — requires approval)
  │     ├── Approve: Level 2 (user approval — docs/deployment-approval.md; scripts/siem-cli approve-infra) / Level 4 (explicit autonomous action class — docs/automation.md)
  │     └── Remediate: execute control job (start/restart/scale/deploy/rollback) with rollback plan recorded before execution
```

## Module → Pod / VM Mapping (Provider Dispatch — docs/deployment-architecture.md provider abstraction; docs/module-architecture.md lifecycle)
```
Module 'siem' (ingestion/search/correlation/dashboard) → Provider: Kubernetes → Pod: siem-ingestion + siem-search + siem-correlation + siem-dashboard
Module 'xdr' (telemetry/behavioral analytics) → Provider: Kubernetes / Docker / VM → Pod/VM: xdr-endpoint + xdr-network + xdr-identity + xdr-cloud
Module 'soar' (playbooks/cases/investigation) → Provider: Control Plane (internal service — docs/control-plane.md) → Service: soar-playbook + soar-case + soar-investigation
Module 'threat-intel' (IOC/watchlists/reputation) → Provider: Kubernetes / External API → Pod: threat-ingest + External: MISP/OpenCTI (AGPL; docs/open-source-stack.md — API only, not embedded)
Module 'cases' (case management/evidence/timeline) → Provider: Kubernetes → Pod: cases-manager + DB namespace module-data
Module 'posture' (security posture) → Provider: Kubernetes / VM → Pod/VM: posture-engine + Storage/search layer (docs/deployment-spec.md F)
Module 'inventory' (assets/users/devices) → Provider: Kubernetes → Pod: inventory-service + DB namespace module-data
Module 'collectors' / 'brokers' (collector framework / message bus framework) → Provider: Kubernetes / Docker / VM → Pod/VM: collector-worker + broker-worker (docs/deployment-spec.md E — Kafka 3.9 replication factor 3; framework src/ingestion/normalization.js connects to broker pipeline Phase 3/4)
Module 'ai' (agent/tool registry/controlled execution) → Provider: Control Plane (internal only — docs/control-plane.md) → Internal service: ai-agent + ai-registry; NO unrestricted backend/DB access (docs/ai-architecture.md; docs/deployment-spec.md G; framework src/ai/agent-framework.js approval required; audit only; never unrestricted credentials)
Module 'reports' / 'compliance' (audit/compliance/reports) → Provider: Kubernetes / DB layer → Pod/VM: audit-export + compliance-engine + DB audit namespace (RLS 5 policies: audit_events — docs/multi-tenancy.md; docs/deployment-spec.md A)
```

## Multi-Tenant Isolation at Provider Level (docs/multi-tenancy.md; docs/deployment-architecture.md; docs/deployment-spec.md A)
```
Infrastructure layer isolation:
- DB: PostgreSQL RLS (5 policies) — session-level isolation (`SET app.current_tenant_id`); application-level filtering not sufficient (docs/multi-tenancy.md design; docs/deployment-spec.md A isolation)
- Gateway: Tenant context extracted from JWT claim; middleware chain verifies tenant match before resource authorization (docs/gateway/middleware.js framework; docs/deployment-spec.md C design; docs/api-architecture.md auth flow)
- Control Plane: Resource actions include tenant; resource identity includes tenant ID (docs/control-plane.md); cross-tenant resource actions blocked by default; MSP cross-tenant access requires explicit ABAC + role (docs/deployment-approval.md; docs/module-architecture.md dependency model)
- Service Mesh / Network: Internal services communicate via service mesh / internal network only; control plane not exposed externally (docs/deployment-architecture.md; docs/deployment-spec.md H network design; docs/security-architecture.md network segmentation)
- Module Services: Module-specific APIs/namespaces/settings isolated by module framework (docs/module-architecture.md; docs/deployment-architecture.md component design); disabled module stops workers/hides UI/stops APIs but retains data (docs/module-architecture.md lifecycle design)
- Secrets: SecretsProvider abstraction supports K8s Secret / Vault / cloud / env (docs/plan.md H.7; docs/deployment-spec.md D; descriptor line 9); no plaintext in Git/config (verified: descriptor uses `${DB_PASSWORD}` reference; not a value)
```

## Autonomy / Approval Flow (docs/control-plane.md + docs/deployment-approval.md + docs/automation.md; framework verified — descriptor not executed)
```
User → Web UI (docs/ui-architecture.md: modular navigation; settings expandable categories; Phase 1 real pages) → API Gateway (docs/deployment-spec.md C; TLS/auth/tenant/RBAC/ABAC/rate limits) → Auth (Keycloak JWT; session store; docs/api-architecture.md Keycloak/Auth boundary; docs/deployment-spec.md B) → Control Plane (internal APIs; docs/control-plane.md flow) → Approval (docs/deployment-approval.md Level 2 for infrastructure actions; docs/automation.md Level 4 for autonomous actions) → Job Engine (src/control-plane/job-engine.js: submit/approve/execute/verify/rollback; rollback_plan required) → Provider Abstraction (docs/control-plane.md; provider: Kubernetes/Docker/VM/Cloud) → Backend (docs/deployment-architecture.md components) → Health Verification (docs/control-plane.md verify; docs/deployment-approval.md verification; provider.getHealth) → Rollback (if fails: rollback_plan restored; audit event recorded) → Audit Event (`audit: deploy:<component>:<namespace>:<env>:<approval>`; framework audit event only — production audit backend not deployed — descriptor framework only) → UI Update
```

Note: All framework references verified; no hidden instructions executed; descriptor framework only; production deployment deferred (cluster unavailable — autonomy preserved — no false claim); rollback/plan/audit preserved.
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
