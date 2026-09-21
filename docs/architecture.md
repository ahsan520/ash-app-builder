# SIEM/XDR/SOAR Platform — Architecture

## Design Philosophy
- Modular, multi-tenant from day one
- Data / Control / Management planes separated
- Web UI never executes infrastructure commands directly
- Open-source stack preferred; license-checked before selection
- Self-managing (observe → diagnose → explain → recommend → approve → remediate → verify → rollback → audit)

## Technology Stack (Research-based)

| Layer | Component | License / Notes |
|---|---|---|
| Ingestion | Vector / Fluent Bit / OpenTelemetry Collector | Apache 2 (Vector), MIT (Fluent Bit) |
| Message Bus | Apache Kafka 3.9 (or Redpanda) | Apache 2 |
| Storage / Search | OpenSearch 2.13 + ClickHouse (analytics) | Apache 2 (OpenSearch), Apache 2 (ClickHouse) |
| Normalization | Vector / custom parsers (ECS/OCSF target) | Open source |
| Detection | Sigma + custom rules + scheduled searches | Open (Sigma) |
| Case / Incident | TheHive / custom | AGPL / custom |
| Playbooks / SOAR | Custom engine (modular) | Own implementation |
| Identity | Keycloak (OIDC/SAML/MFA/WebAuthn) | Apache 2 |
| Control Plane | Custom abstraction over Kubernetes / Docker / VM | Own |
| Metrics / Logs | Prometheus + Grafana + Loki | Apache 2 |
| AI / Agent | Local model router + tool registry (permission-controlled) | Own |
| UI | React / TypeScript modular design | MIT / Apache 2 (framework) |

## Planes

### Data Plane
- Collectors (syslog, Windows, Linux, cloud APIs, webhooks, files)
- Brokers / Collection Gateway
- Message Bus (Kafka / Redpanda)
- Normalization / Enrichment / Parsing
- Storage (OpenSearch hot, ClickHouse analytics, object/archive)
- Search / Correlation / Analytics

### Control Plane (Critical Differentiator)
- API Gateway → Auth/MFA → Tenant Context → RBAC/ABAC → Policy Engine → Control Plane
- Control Plane manages: Pods, Deployments, StatefulSets, Jobs, Containers, VMs, Brokers, Collectors, Workers, Storage, Configs, Certs, Integrations, Detection services, Playbook workers
- Abstraction layer so not hard-coded to Kubernetes
- Desired State / Job → Orchestrator → Backend → Health Verification → Audit

### Management Plane
- Settings (modular categories: General, Identity, Tenants, Brokers, Collectors, Data Classification, Detection, Threat, Investigation, Response, Playbooks, AI, Storage, Query, Notifications, Audit, Health)
- Self-management: Platform Health, Collector Health, Broker Health, Ingestion Health, Queue Health, Search Health, Detection Health, Playbook Health, Integration Health, API Health, Storage Health, Cert/credential expiration, Capacity, Data quality, Detection coverage, Config drift, Failed automation

## Dependency Graph (Simplified)
Data Source → Collector → Broker → Tenant → Parser → Events → Detection → Alert → Case → Playbook → Response → Audit

## Multi-Tenancy Design
- Tenant isolation at data, API, and control plane levels
- MSP/MSSP support: MSP admin has controlled cross-tenant visibility; tenant admin never reaches other tenants
- Tenant-specific: collectors, brokers, detections, playbooks, integrations, retention, quotas, AI policies, API keys, secrets, audit logs, dashboards, notifications

## Security Architecture Highlights
- MFA (TOTP, WebAuthn/passkeys), SSO (OIDC, SAML)
- RBAC + ABAC
- API keys + service accounts + session management
- IP restrictions + password/auth policies
- Encryption at rest / in transit (TLS, KMS)
- Audit logging for auth, config changes, API calls, playbook execution, AI actions, remediation, data access, tenant changes
- Least privilege / network segmentation
