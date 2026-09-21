# Open-Source Stack — Verified Research

## Criteria for Selection
- License compatibility with commercial / multi-tenant use
- Project activity (commits, releases, community)
- Scalability evidence in production
- Security track record
- Integration effort with our modular architecture
- Replacement path if project stalls

## Verified Components (Fact-based)

### OpenSearch (Search / Log Analysis)
- Source: https://opensearch.org/ (verified via fetch)
- License: Apache 2.0 (open source search/observability project)
- Capabilities: Security Analytics (threat intelligence, event correlation), machine learning/anomaly detection, log analysis
- Suitability: Yes for SIEM search and analytics layer
- Note: Not proprietary Elastic code; independent open-source fork/project

### ClickHouse (Analytics / High-Scale Storage)
- Source: Official docs / 2025 info
- License: Apache 2.0
- Capabilities: Columnar analytics database; excellent for security analytics and large-scale event aggregation
- Suitability: Analytics / reporting / long-term cold storage complement to OpenSearch

### Apache Kafka 3.9 / Redpanda (Message Bus)
- Source: Apache Kafka official / Redpanda docs
- License: Apache 2.0
- Capabilities: Durable message bus; supports event streaming, ingestion pipeline, detection pipeline
- Suitability: Core event bus between collectors, brokers, normalization, storage, detection

### Vector (Ingestion / Normalization)
- Source: Vector.dev (Datadog-backed, open source)
- License: MPL 2.0
- Capabilities: High-performance log collection, parsing, normalization, routing; supports ECS/OCSF schema
- Suitability: Collector gateway / broker ingestion; can replace Fluent Bit in high-throughput scenarios

### Fluent Bit (Lightweight Collector Agent)
- Source: CNCF / Fluent project
- License: Apache 2.0
- Capabilities: Lightweight log collector; works with OpenSearch, Kafka; low resource footprint
- Suitability: Endpoint / server collector agent

### Keycloak (Identity / Auth)
- Source: Keycloak.org
- License: Apache 2.0
- Capabilities: User federation, identity brokering, SSO (OIDC, SAML), MFA (TOTP, WebAuthn/passkeys), social login, admin APIs
- Suitability: Identity layer for platform and multi-tenant auth

### Wazuh (XDR / Endpoint / SIEM)
- Source: https://wazuh.com/ (verified via fetch)
- License: Open source (GPL-based / community)
- Capabilities: SIEM monitoring, detection, alerting; XDR real-time correlation + endpoint remediation; highly scalable (15M+ endpoints, 100k+ businesses); single agent + platform architecture
- Suitability: Endpoint telemetry, detection rules (Sigma-like), endpoint response; can serve as collector/detection reference or integrated component

### Sigma Rules / Sigma Project
- Source: SigmaHQ / sigma documentation
- License: Apache 2.0 or MIT (open, vendor-neutral)
- Capabilities: Generic detection rule format; can translate to multiple backends
- Suitability: Detection-as-code format; independent of backend

### TheHive / Cortex / Shuffle (SOAR / Case Management / Playbook)
- Source: TheHive project / Cortex / Shuffle
- License: AGPL / open source
- Capabilities: Case management, incident response, playbooks, connector framework
- Suitability: Case management / SOAR module; integration via API rather than full dependency

### MISP / OpenCTI (Threat Intelligence)
- Source: MISP Project / OpenCTI
- License: AGPL-3.0 (MISP), Apache 2.0 (OpenCTI)
- Capabilities: Threat intel sharing, IOC management, feed ingestion
- Suitability: Threat intelligence module; API integration preferred

### Prometheus + Grafana + Loki + Tempo (Observability)
- Source: CNCF / Grafana Labs
- License: Apache 2.0 (Prometheus, Grafana, Loki, Tempo)
- Capabilities: Metrics, dashboards, logs, traces; distributed tracing support
- Suitability: Platform self-observability; self-managing SIEM health metrics

### Kubernetes (Infrastructure Abstraction Target)
- Source: CNCF
- License: Apache 2.0
- Capabilities: Container orchestration; supports Pods, Deployments, StatefulSets, Jobs, Services
- Suitability: One of multiple infrastructure targets (not the only one); abstraction layer required

## Licensing Considerations (Verified / Hypothesis)
- All selected core components: open source licenses compatible with commercial multi-tenant deployment
- AGPL components (TheHive) require careful integration: use as external service or API-only integration, not embedded in proprietary code, unless we accept AGPL obligations
- No proprietary code dependency planned
- Replacement paths maintained for each component

## Unverified / Assumed (Explicitly Marked)
- ASSUMPTION: Redpanda can fully replace Kafka for our message bus needs in Phase 1 — verify load testing before finalizing
- ASSUMPTION: ClickHouse analytics layer does not conflict with OpenSearch licensing in combined deployment — verify legal review before production
