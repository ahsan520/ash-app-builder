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

### SOAR / playbooks / case management (researched 2026-11-08; engine NOT chosen yet; spike kit built 2026-11-12)
**2026-11-13 result:** Tracecat ran the scenario and passed; details and the open items in `docs/soar-spike.md`. **2026-11-12 update:** provisional first try is **Tracecat**, fallback Shuffle; the comparison table, the scenario, the decision rule and the empty results are in `docs/soar-spike.md`. New facts from the sources that day: Tracecat's Helm chart is PolyForm Shield (internal use) and its documentation calls it a private OCI artifact, so the spike uses Docker Compose; its human-in-the-loop, RBAC/ABAC, Git sync and MCP servers are listed as paid (not needed, ASIX keeps approval); Tracecat needs PostgreSQL, Redis, an S3-compatible store and Temporal; Shuffle's own `.env` points at OpenSearch and its Orborus starts app containers through Docker (Kubernetes is mentioned as a scaling option); a community discussion questions limits in the self-hosted Shuffle edition (unverified).
Sources: the projects' own repositories and one July 2026 comparison article (aimultiple.com, "open source SOAR"); licences must be re-checked at the time of use.
- **Shuffle** (security automation, workflow editor, OpenAPI-based apps). Licence as its repository states: the backend is AGPLv3; workflows, documentation, the app specification, the app SDK and the apps are MIT. The article counts 200+ pre-built app integrations and over 11,000 endpoints. Built with MSSPs in mind (its README). *Unverified for us:* footprint on a one-VM Home install, tenant isolation, running under k3s as it is.
- **Tracecat** (automation with YAML templates, cases, tables). AGPL-3.0, except a paid enterprise directory (`tracecat-ee`) and a Helm chart under PolyForm Shield. Depends on Temporal, PostgreSQL and an S3-compatible store. *Sources disagree* on which features are enterprise-only (one lists RBAC, MCP servers and version control; the article says SSO and audit logs are free): check before choosing. Smaller integration catalogue than Shuffle.
- **TheHive** (case management): version 5 moved to a commercial model (new installs need a vendor licence after a 14-day trial, or fall to read-only; a free community licence on request, per the article). **Not a core component.** **Cortex** (analyzers for IPs, domains, hashes) remains AGPL and can be used as an optional enrichment service over its API.
- **n8n**: source-available (Sustainable Use License), not an OSI open-source licence, and it had serious 2026 vulnerabilities (one listed by CISA as exploited). **Avoid.**
- **StackStorm** (event-driven automation, packs): Apache 2.0 as far as we know; *not re-checked in this session*. Candidate if a permissive licence matters more than a ready SOAR UI.
- **Own engine**: `src/playbooks/playbook-engine.js` is a Level 0 skeleton (143 lines, returns objects, no triggers, approval or rollback). `docs/architecture.md` previously said "custom engine"; that is now **superseded by the spike below**.
- **Decision rule:** whichever engine is chosen runs as a **separate service**; ASIX talks to it over HTTP and keeps the approval, autonomy-level, tenant and audit gate in front of every action (`docs/automation.md`). AGPL is acceptable on that basis (the "API-only" rule in "Licensing Considerations"). The choice is made by the spike task SR0 in `docs/product-plan.md`.

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

## Adopt before build (policy, agreed 2026-11-08)
Most modules should run the best open-source tool for the job **under** the ASIX portal, not a new implementation.
1. **Order of choice:** (a) a mature open-source tool with a licence we can live with, run as its own service; (b) a thin ASIX layer over it; (c) our own code only for what no tool gives us (approval gate, tenant isolation, audit, undo, the pack format).
2. **What ASIX always owns:** sign-in and tenants, the permission checks, approval and autonomy levels (`docs/automation.md`), the audit trail, secrets (`docs/plan.md` H.7), and what an action is allowed to do. A tool never receives broad credentials from ASIX; it gets only what the enabled action needs.
3. **How it shows in the portal:** as an `embedded` module page (`docs/portal-shell.md`) or through ASIX pages that call the tool's API. The index page is not edited for it.
4. **Before adopting:** check the licence (AGPL means separate service, API-only), the maintenance state (last release, open security problems), footprint on the Home profile (4 vCPU / 8 GB / 100 GB assumed), tenant isolation, and a way out (a replacement path, as in the criteria above).
5. **Record every choice here** with its source and date, and mark what is unverified.

## Marketplace delivery (candidates, 2026-11-08)
We do not build a marketplace web store first. Candidates for the parts:
- **Package format and delivery:** each pack as a signed archive listed in a catalog index; stored in an OCI registry (CNCF Distribution or Harbor, Apache 2.0) and signed with Sigstore cosign, or simply GitHub Releases plus a signed `index.json` to start. *From our own knowledge, not checked this session.* Decision task: MK3.
- **Discovery UI:** Artifact Hub (CNCF, Apache 2.0, can be self-hosted from its Helm chart) lists a fixed set of artifact kinds (Helm charts, OPA policies, Falco rules and similar); adding an "ASIX pack" kind means changing its code and running its own database. **Not adopted for the first release**; we use it as a design reference and build a small Marketplace page that reads the catalog (`docs/xsiam-reference.md`).
- **Content to import instead of write:** Shuffle's MIT apps (connector definitions), SigmaHQ rules (check the rule licence before bundling), Wazuh rules and decoders (GPL, kept behind ASIX Endpoint Security as in `docs/branding.md`), MISP and OpenCTI feeds.
- **Packs carry data only, never portal code** (`docs/portal-shell.md`).

## Unverified / Assumed (Explicitly Marked)
- ASSUMPTION: Redpanda can fully replace Kafka for our message bus needs in Phase 1 — verify load testing before finalizing
- ASSUMPTION: ClickHouse analytics layer does not conflict with OpenSearch licensing in combined deployment — verify legal review before production
- RUN (2026-11-13, Tracecat 1.4.0, one lab VM): the scenario passed; idle memory 5025 MiB over 16 containers. STILL UNVERIFIED: busy and one-hour footprint, tenant isolation, k3s fit of Tracecat, and everything about Shuffle; Tracecat's free vs enterprise feature split; StackStorm's current licence; Sigstore/OCI as the pack delivery path; the licence terms of SigmaHQ rules for bundling.
