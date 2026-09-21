# Phased Roadmap (Realistic)

Note: Do NOT attempt everything simultaneously. Only Phase 0 + Phase 1 will have real implementations; others may be mocked for UI development.

## Phase 0: Foundation & Architecture (Months 1-2)
- Core architecture docs (completed in planning mode)
- Module framework skeleton (module loader, dependency resolver, settings framework)
- Development environment (dev container / CI / testing framework)
- Technology selection validated (open-source stack verified)
- Security baseline (TLS, secrets management, audit framework skeleton)
- Deliverable: Platform skeleton with module loading, identity skeleton, settings framework

## Phase 1: Identity + MFA + Multi-Tenancy + RBAC (Months 2-3)
- Keycloak integration (OIDC / SAML / MFA / TOTP / WebAuthn)
- Tenant model (creation, configuration, quotas, isolation, audit)
- RBAC / ABAC framework (roles, permissions, policies, session management)
- API Gateway (auth, MFA, tenant context, rate limits)
- Basic UI framework (navigation, settings expandable categories, modular pages)
- Deliverable: Login with MFA, tenant isolation, role-based access, settings framework working

## Phase 2: Control Plane + API + Orchestration (Months 3-4)
- Control Plane abstraction layer (provider interface for K8s / Docker / VM)
- Desired State / Job model (request, approve, execute, verify, audit)
- Orchestrator (execute jobs across backends)
- Policy Engine (approval rules, risk classification, autonomy levels)
- Health verification framework (health checks for services, brokers, collectors)
- Audit event framework (every action logged)
- Change Impact Analysis (dependency graph for infrastructure changes)
- Deliverable: Admin can request broker restart / collector deploy with approval flow; platform observes itself

## Phase 3: Broker + Collector Framework (Months 4-5)
- Collector configuration framework (profiles, policies, groups, assignment, installers)
- Broker framework (registration, health, capacity, failover, upgrades)
- Message bus setup (Kafka / Redpanda integration)
- Collector group management
- Health monitoring for collectors / brokers
- Deliverable: Collectors and brokers configured, health visible, dependency mapping working

## Phase 4: Data Ingestion + Normalization + Storage (Months 5-7)
- Ingestion pipeline (Vector / Fluent Bit → Kafka → normalization → OpenSearch / ClickHouse)
- Normalization engine (ECS/OCSF-compatible schema, parsers, enrichment)
- Storage layer (OpenSearch hot, ClickHouse analytics, archive / object storage)
- Data classification (PII detection, sensitivity labeling, data tagging)
- Data quality monitoring
- Deliverable: Events ingested, normalized, searchable; data quality monitored

## Phase 5: Search + SIEM (Months 7-9)
- Search interface (query builder, saved searches, history, permissions)
- Correlation / scheduled searches / streaming detection skeleton
- Dashboards / reports skeleton
- Query management (limits, concurrency, timeouts, expensive query detection)
- Deliverable: Search working with real events; basic dashboards visible

## Phase 6: Detection Engine (Months 9-10)
- Sigma detection rules framework
- Detection lifecycle (version, test, deploy, rollback)
- MITRE ATT&CK mapping
- False-positive tracking
- Detection health monitoring
- Deliverable: Custom rules executable; version and rollback working

## Phase 7: Cases / Investigation (Months 10-11)
- Case / Incident management (create, assign, severity, SLA, timeline)
- Evidence / comments / tasks
- Search integration (correlate events to cases)
- Investigation policies
- Deliverable: Cases created from alerts; investigation timeline working

## Phase 8: SOAR / Playbooks (Months 11-12)
- Playbook framework (trigger → conditions → actions → approval → execution → verification → rollback)
- Action registry (endpoint, network, identity, notification, external API)
- Connector framework
- Approval policies (autonomy levels configurable)
- Execution history and audit
- Deliverable: Playbook execution with approval; rollback available

## Phase 9: Threat Intelligence / XDR (Months 12-14)
- Threat feeds / IOC ingestion (MISP / OpenCTI integration)
- Watchlists / reputation providers
- Entity model (user, device, IP, domain, process, file, cloud resource, application, alert, case)
- Behavioral analytics skeleton
- Endpoint / network / identity telemetry integration
- Deliverable: Threat intel visible; entity relationships modeled

## Phase 10: AI Assistant (Months 14-16)
- AI agent framework (tool registry, permission check, tenant check, action policy, audit)
- Search / investigate / explain / recommend / generate queries / generate rules
- Model routing (local / hosted / provider selection)
- AI permissions / audit / cost controls
- Deliverable: AI can search SIEM, explain detections, recommend response with controlled tool access

## Phase 11: Self-Managing SIEM (Months 16-18)
- Full observe / diagnose / explain / recommend / approve / remediate / verify / rollback / audit automation
- Automatic ingestion diagnosis (collector → broker → network → auth → source → queue → parser)
- Configuration drift detection
- Detection coverage monitoring (source-to-detection dependency mapping)
- Automated capacity planning
- Deliverable: Platform can diagnose and propose remediation for its own failures

## Phase 12: Advanced Automation / Autonomous Remediation (Months 18-20)
- Autonomous remediation for explicitly approved action classes (Level 4)
- Cross-tenant operational management for MSSPs
- Security + infrastructure unified control plane fully realized
- Advanced reporting / compliance / regulatory reporting
- Deliverable: Fully autonomous approved actions; MSP cross-tenant operations working
