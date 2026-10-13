# ASIX product plan — one SIEM, two profiles

Agreed direction (see chat history for the full discussion): **one codebase, one product**.
Residential and Enterprise are configurations of the same platform — different module sets,
deployment profiles, and entitlements — never a fork.

## The three dials

| Dial | Controls | Home | Enterprise |
|---|---|---|---|
| Modules | which capabilities are on | core SIEM, search, dashboards, detections, alerts/notifications, threat intel, content packs, retention, capacity | + SOAR playbooks, XDR, posture, AI assistant, compliance, MSSP multi-tenant |
| Deployment profile | storage/queue/archive | one VM, k3s, Postgres, direct ingest | broker VMs, Kafka, ClickHouse cluster, S3 archive, HA |
| Entitlements | limits/unlocks from a signed license file | 1 tenant, retention cap | multi-tenant, SSO/SAML, no caps |

## Phases

1. **Home edition, solid** — data safety (this build), module/profile skeleton, broker VM on
   Vector, content packs (residential), alert triage, regex-safety fix, CI.
2. **Foundation for scale** — event envelope, event-store interface (Postgres adapter + ClickHouse
   adapter, one conformance suite), search/detections/IOC/retention moved behind it, parsers as
   separate workers.
3. **Enterprise data plane** — Kafka between broker and parser, ClickHouse cluster, S3 archive, HA
   control-plane DB, multi-node capacity dashboard.
4. **Enterprise features** — multi-tenant hardening, sandboxed playbooks/integrations, marketplace
   catalog + signing, SSO/SAML, compliance, AI.

Rules that keep it one product: Postgres stays first-class (not legacy); all content (rules,
parsers, dashboards) is written in XQL, never raw SQL; one event envelope used end-to-end; modules
register themselves via a manifest instead of being hard-coded into the gateway or portal menu.

## Open decisions (ask before committing)
- Smallest Home machine to design against (assumed: 4 vCPU / 8 GB / 100 GB until told otherwise).
- Licensing model: open core vs. fully commercial with locked modules (business decision; the
  signed-license mechanism is the same either way).
- Enterprise search engine: ClickHouse alone vs. ClickHouse + OpenSearch (can wait until Phase 3).
