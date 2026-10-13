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

## Status of Phase 1 (updated this build)

| Item | State |
|---|---|
| Data safety | Done |
| Module / profile skeleton | Done as a skeleton, see below |
| Broker VM on Vector | Not started |
| Content packs (residential) | Not started; the `content-packs` module is listed as planned |
| Alert triage | Done (assign, notes, bulk acknowledge/close); dedupe split out as its own item |
| Regex-safety fix | Next |
| CI | Not started |

### Alert triage (what exists)
- Each alert can be assigned to a user of the same tenant (or unassigned), and carries analyst notes
  (stored with the author's name at the time, so notes survive a user being deleted; deleting a user
  just unassigns their alerts).
- The Alerts list has an assignee column and filter (anyone / me / unassigned), and tick-boxes to
  acknowledge or close up to 200 alerts at once. The alert detail shows the assignee picker and notes.
- Uses the existing `alerts:read` / `alerts:write` permissions, so no role changes are needed.
- Needs the new schema (`alerts.assignee_id`, `alert_notes`); it is applied by the normal schema-init
  job on deploy and is safe to re-run.
- Not built: dedupe/merge of repeat alerts, a "my open alerts" dashboard tile, notes on status changes,
  note editing or deletion.

### How the three dials are implemented now
- **Modules:** one manifest file per module in `src/modules/manifests/`. A module is on only if its
  tier is part of the profile, its license feature (if any) is granted, and everything it requires is
  on. Modules with no backend yet are shown as `planned` and are never on. Today all ten Home modules
  are available; the six Enterprise modules (SOAR, XDR, posture, AI assistant, compliance, MSSP) are
  planned, so they cannot be switched on yet even with a license.
- **Deployment profile:** `ASIX_PROFILE` = `home` (default) or `enterprise`. In this step it only
  describes the target shape (storage, queue, archive, HA); it does not yet change how data is stored.
- **Entitlements:** a license is a signed token (Ed25519) read from `ASIX_LICENSE_FILE` (default
  `/etc/asix/license.jwt`) and verified with the public key at `/etc/asix/license.pub`. Missing,
  expired or invalid licenses fall back to Home limits and never block the platform or touch data.
  `scripts/license-tool.js` makes keys and signs licenses; the private key stays off the platform.
- **Not enforced yet:** the `tenants` and `retention_days_max` limits are reported on the Modules
  page but not yet applied by tenant creation or the retention job. The Home retention cap of 90 days
  is a placeholder until the licensing decision below is made.
- **Not yet done:** the portal menu does not hide or grey out entries based on module state, and there
  is no per-tenant module toggle (that would need a schema change).

## Open decisions (ask before committing)
- Smallest Home machine to design against (assumed: 4 vCPU / 8 GB / 100 GB until told otherwise).
- Licensing model: open core vs. fully commercial with locked modules (business decision; the
  signed-license mechanism is the same either way).
- Enterprise search engine: ClickHouse alone vs. ClickHouse + OpenSearch (can wait until Phase 3).
