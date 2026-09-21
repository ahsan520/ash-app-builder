# Deployment Architecture

Status: DESIGN (not implemented in Phase 1; framework only)

## Principles
- Not hard-coded to Kubernetes
- Provider abstraction: Kubernetes / Docker / VM / Cloud
- Multi-tenant deployment: same infrastructure, isolated services per tenant (not separate clusters per tenant for Phase 1)
- Modular services: auth, gateway, module services, DB, message bus, control plane, observability

## Components
- API Gateway (Kong / Envoy / custom) — TLS termination, auth forwarding, rate limits
- Auth Service / Keycloak — external or embedded; SSO + MFA
- Module Services (modular): auth, tenant, user, RBAC, settings, audit (Phase 1); future: siem, xdr, soar, cases, threat, ai
- PostgreSQL — multi-tenant DB; schema migrations versioned; module migrations isolated
- Kafka / Redpanda — message bus; future ingestion / event pipeline
- Control Plane Service — internal; manages infrastructure through provider abstraction
- Observability — Prometheus + Grafana + Loki (metrics/logs); Tempo future (traces)
- Container Runtime — Kubernetes (primary design target) / Docker (Phase 1 dev/test / backup)

## Network Design
Public: API Gateway only; TLS; rate limits
Internal: services communicate via service mesh / internal network; no external access
DB: internal only; encrypted connections; no public endpoint
Message Bus: internal; encrypted; auth required
Control Plane: internal; service account auth; audit all actions
Observability: internal / admin access only; audit access

## Multi-Tenancy Isolation at Infrastructure Level
Phase 1: same DB, same services, isolation enforced at application layer (tenant filter in every query). Not separate DB instances or clusters per tenant (scalability; cost).
Future: option for dedicated DB instances / dedicated clusters for high-trust / large tenants.

## HA / DR Design (docs/ha-dr.md covers detail; this is deployment view)
- Replication: PostgreSQL replication (primary/replica); message bus replication (Kafka replicas / Redpanda)
- Failover: gateway health check; service restart; no automatic failover for DB in Phase 1 (manual promotion or automated with tool)
- Backup: DB backups scheduled; audit logs backed up; settings/config exported (configuration-as-code)
