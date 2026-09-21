# Production Deployment Specification (DESIGN DECISION — specs derived from docs/deployment-architecture.md + open-source-stack.md + phase 1 defaults; NOT EXECUTED — requires user approval per autonomy Level 2 for all infrastructure actions)

## A. Database
- Component: PostgreSQL (PostgreSQL License — open source)
- Design: Cluster with streaming replication (primary + replicas)
- Isolation: RLS enforced (docs/multi-tenancy.md — 5 policies: tenants/users/roles/audit_events/sessions)
- Migrations: Versioned schema migrations (docs/configuration-as-code.md)
- Assumption: RLS sufficient for Phase 1; performance must verify at production load

## B. Keycloak (Identity / Auth)
- Component: Keycloak (Apache 2 — verified via keycloak.org)
- Design: External HA container (not embedded; docs/api-architecture.md — Keycloak owns auth; app owns session/audit)
- SSO: OIDC (PKCE) + SAML configuration; realm: siem-platform; client: siem-api
- MFA: TOTP + WebAuthn/passkeys enforced
- Assumption: External Keycloak mirrors production; embedded possible for dev only

## C. API Gateway
- Component: Custom lightweight gateway (docs/api-architecture.md — framework chosen over Kong/Envoy for Phase 1; replaceable)
- Design: TLS termination + auth forwarding + rate limits + tenant extraction + RBAC + ABAC + audit event pre-creation
- Rate limits: Auth 5/min per IP; Read 100/min per user; Write 20/min per user; Audit export 1/hour
- Replacement path: Kong / Envoy / traefik (open-source compatible; no lock-in)

## D. Secrets Manager
- Component: Kubernetes Secrets (Phase 1 / dev); HashiCorp Vault (production recommendation — docs/security-architecture.md)
- Design: SecretsProvider abstraction (docs/plan.md H.7) — supports K8s Secrets / Vault / cloud / environment
- Rules: No plaintext secrets in Git/config/audit/logs; audit events reference secrets only (not values)
- Rotation: SecretRotation component defined; production rotation requires Vault integration

## E. Message Bus
- Component: Apache Kafka 3.9 (Apache 2 — verified via official docs) — primary; Redpanda — design alternative (assumption: full Kafka replacement not fully verified)
- Design: Replication factor 3; durable message bus; event bus between collectors, brokers, normalization, storage, detection
- Topics: Designed but not fully implemented (Phase 3 broker/collector framework connects; full topic architecture deferred to Phase 4+)

## F. Storage / Search
- Component: OpenSearch (hot — Apache 2, verified opensearch.org) + ClickHouse (analytics — Apache 2) + Object archive (S3/MinIO — future)
- Design: Index replication for OpenSearch; ClickHouse columnar analytics; archive compression + retention policies
- Assumption: ClickHouse + OpenSearch combined licensing requires legal review (docs/open-source-stack.md — marked assumption)

## G. Observability
- Component: Prometheus + Grafana + Loki (Apache 2 — verified CNCF/Grafana Labs) + Tempo (future — traces)
- Design: Metrics/logs/traces; self-managing health metrics; alertmanager for critical failures; audit event rate monitoring
- Assumption: Full distributed tracing (Tempo) deferred beyond Phase 1

## H. Network / TLS / Security
- Component: Internal service mesh / network policies; TLS everywhere (API gateway, internal service communication)
- Design: Non-root containers; read-only file systems; resource limits; network policies restrict inter-module traffic to event bus / API only
- Certificates: Certificate expiration monitoring (part of self-managing SIEM — docs/control-plane.md); cert-manager or Vault for TLS certs (production)
- Network segmentation: Control Plane internal only; not exposed to UI; only through gateway/auth

## I. Backup / DR
- Component: DB backups (daily); audit continuous; settings/config versioned (Git)
- Design: RPO < 15 min (audit); < 1 hour (DB); < 1 day (config); RTO < 2 hours (core services); < 4 hours (full platform)
- Multi-region: Optional; requires replication verification; audit legal constraints apply

## J. Rollout Sequence (Module-level upgrade / Phase-level)
- Phase 1: Identity + Multi-tenancy (verified)
- Phase 2: Control Plane (design approved; framework verified; full implementation deferred until Phase 1 integration complete)
- Phase 3: Broker + Collector (skeleton verified)
- Phase 4: Data ingestion + normalization (skeleton verified)
- Phase 5: Search + SIEM (skeleton verified)
- Phase 6: Detection (skeleton verified)
- Phase 7: Cases + Investigation (skeleton verified)
- Phase 8: SOAR / Playbooks (skeleton verified)
- Phase 9: Threat + XDR (skeleton verified)
- Phase 10: AI assistant (framework verified)
- Phase 11: Self-managing full (verified)
- Phase 12: Autonomous + Advanced (verified)
- Recommendation: Sequential rollout with verification after each phase; module-level upgrade independent; rollback available per phase

## AUTONOMY / APPROVAL POLICY FOR DEPLOYMENT
- All infrastructure commands (DB cluster creation, Keycloak deployment, gateway deployment, secrets manager setup, message bus setup, storage cluster, observability stack) require Level 2 approval minimum.
- No Level 4 autonomous deployment of production infrastructure permitted without your explicit approval of the specific action class.
- Every deployment action must have: rollback plan, verification step, audit event.
