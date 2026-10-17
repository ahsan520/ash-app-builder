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
   adapter, one conformance suite), search/detections/IOC moved behind it (done), retention (done), parsers as
   separate workers (done: worker threads, off by default; see below).
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
| Broker VM on Vector | Done for syslog (see below) |
| Content packs (residential) | Done for detection rules (see below); parsers and dashboards not yet |
| Collector heartbeat | Done (see below) |
| Alert triage | Done (assign, notes, bulk acknowledge/close) |
| Alert dedupe | Done (see below): find and merge repeat alerts, by hand or all at once |
| Regex-safety fix | Done (see below) |
| CI | Done: lint (`no-undef`) and unit tests on every push; database tests in `postgres` and `clickhouse` jobs (every step run locally; first GitHub run pending) |

Every Phase 1 item is now done. Phase 2 (foundation for scale) is now done too: see "Status of Phase 2" below. Phase 3 (enterprise data plane) has started: see "Status of Phase 3" below.

## Status of Phase 2 (updated this build)

| Item | State |
|---|---|
| Event envelope | Done (see below) |
| Event-store interface, Postgres adapter, conformance suite | Done (see below); ingest writes go through it |
| XQL search moved behind the store (query plan + `store.search()`) | Done (see below) |
| Page counts moved behind the store (collectors, storage, capacity, search fields) | Done (see `docs/event-store.md`, "Page counts behind the store") |
| Detections, IOC matcher and alert sample events moved behind the store | Done (see below and `docs/event-store.md`, "Detection rules") |
| Events list, data sources and Command Center reads in `routes/core.js` moved behind the store | Done (see `docs/event-store.md`) |
| Retention job moved behind the store | Done (see below and `docs/event-store.md`, "The retention job behind the store") |
| ClickHouse retention by partition drop and ClickHouse storage page | Done (see below and `docs/event-store.md`) |
| `xql.compile` wrappers removed; ClickHouse table created on deploy | Done (see below and `docs/event-store.md`) |
| ClickHouse adapter (same conformance suite) | Done — `src/events/clickhouse-store.js`; passes the conformance suites (store, search, rule match) against a real ClickHouse 24.8 and runs in its own CI job. XQL `search()` and detection rules run on it |
| Parsers as separate workers | Done as worker threads in the API, off by default (see below and `docs/parser-workers.md`) |

### Event envelope and event store (what exists)
- **One shape:** every event is an envelope (`id`, `tenant_id`, `source_type`, `collector_id`, `received_at`,
  `event_time`, `raw`, `parsed`) that maps one to one onto the existing `events` table, so there is no schema change.
  `makeEnvelope()` validates and cleans it (UTC times, NUL characters removed, size limits). Details and limits:
  `docs/event-store.md`.
- **One interface:** `src/events/event-store.js` defines `insertBatch`, `getByIds`, `scan` (cursor paging, stable order),
  `count`, `sourceTypes` and `deleteBefore`. Every call is scoped to one tenant. Inserts are idempotent on
  `(id, received_at)`, which is what a queue that delivers at least once (Phase 3) needs.
- **Adapters:** Postgres (plain or daily-partitioned `events`, row-level security kept), ClickHouse (`ReplacingMergeTree`, daily partitions, exact idempotency without waiting for merges; see `docs/event-store.md`) and an in-memory one for tests.
  `ASIX_EVENT_STORE` picks the adapter (default `postgres`).
- **Conformance suite:** `tests/event-store-conformance.js` is the contract as a test. The in-memory adapter runs it in CI;
  the Postgres adapter runs it with `ASIX_TEST_DB=1` (checked against both table layouts), and the ClickHouse adapter runs it
  against a real server in the `clickhouse` CI job.
- **Ingest switched over:** the HTTP key lane and the broker lane write through the store. The broker lane is now one
  statement per batch instead of one per event. A malformed event is now a `400` (`INGEST_INVALID_EVENT`) instead of a
  `500`, and a NUL character no longer fails the batch. Routes, auth, rate limits, parsing rules and audit rows are unchanged.
- **XQL search runs on any engine.** XQL is parsed once into a *query plan* (`src/search/xql-plan.js`: stages, a small
  expression tree, no SQL). `getEventStore().search(tenantId, plan)` runs it: Postgres and ClickHouse each translate the
  plan to their own SQL (`xql-postgres.js`, `xql-clickhouse.js`), the in-memory adapter evaluates it directly
  (`xql-eval.js`). `POST /v1/search/xql` now goes through the store; its request and response are unchanged. The plan is
  validated before any engine sees it (field names, sizes, limits), values are always bound parameters, and a hand-built
  plan cannot inject SQL. One conformance suite (`tests/event-search-conformance.js`) holds all engines to the same results:
  a frozen set of 116 query/window cases checked against real PostgreSQL, plus hand-written checks of each rule of the
  language. The old compiler's SQL is reproduced exactly (`tests/xql-golden.test.js`, 170 query cases), so BIOC rules are unchanged.
  The old `xql.compile` / `compileCondition` wrappers are removed; the golden test calls the parser and the Postgres emitter directly.
- Known differences between engines (listed in `docs/event-store.md`): regex dialect (PostgreSQL ARE vs RE2 on ClickHouse),
  text of a whole object or array value, numbers as exact decimals vs Float64, text sort order.
- Counts on the collectors, storage and capacity pages and `/v1/search/fields` now read through the store (`groupCounts`,
  `timeRange`, `fieldStats`), checked on in-memory, PostgreSQL and ClickHouse 24.8 and against the SQL they replaced.
- **Detection rules, the IOC matcher and the alert sample events now read through the store.** A rule becomes a match spec
  (filter as a plan expression, a group, a threshold; no SQL) and `getEventStore().matchGroups()` runs it on PostgreSQL,
  ClickHouse or in memory. The IOC matcher keeps its place as a store cursor and reads in pages. Plan fields can now be written
  `@path` (always a path into `parsed`), which keeps rule fields called `dataset` or `_time`, or with hyphens, exactly as they were.
  Checked by running the old SQL builder and the new path side by side on real PostgreSQL over 1,914 rule definitions (identical
  results), by a rule-match conformance suite on all three engines, and end to end (`tests/detection-store-db.test.js`). A rule is
  now validated as a whole when it is saved. `querySQL` and `queryAggregated` are removed.
- The events list (`/v1/search/events`), data sources and Command Center now read through `listEvents`, `dataSources` and
  `ingestionStats`, checked on in-memory, PostgreSQL and ClickHouse 24.8 and against the SQL they replaced.
- **The retention preview and row purge now go through the store** (`expiredCounts`, `deleteExpired`), with the same policy (default days, per-source overrides, keep forever), API and run log. Checked on in-memory, PostgreSQL 16 and ClickHouse 24.8 by one conformance block, and on the partitioned Postgres table against the old preview SQL (`tests/retention-db.test.js`); the job also runs with events in ClickHouse (`tests/retention-clickhouse.test.js`). Partition creation and whole-partition drops stay PostgreSQL housekeeping and are skipped on other engines.
- **ClickHouse partition retention and storage sizes are done** (`dropPartitionsBefore`, `storageStats`): when every tenant has automatic purge on and no keep-forever rule, whole UTC days older than the longest retention are dropped (`ALTER TABLE ... DROP PARTITION ID` on ClickHouse, `DROP TABLE` of the daily partition on PostgreSQL), and the storage page's events numbers come from the store on any engine. A ClickHouse table TTL is deliberately not used (retention is per tenant and per source). ClickHouse refuses to drop a partition above its `max_partition_size_to_drop` (50 GB default); that day is reported as failed and the others still go.
- **The ClickHouse table is created on deploy**: `store.init()` runs when the API starts (retrying while ClickHouse comes up) and the API exits if it cannot, instead of serving without a table. The database itself must exist.
- Not built: a ClickHouse server in `k8s/` (Phase 3), and any per-tenant choice of adapter (one adapter per process).

### Parser workers (what exists)
- The parse step of the HTTP ingest lane (parsing rules, then the data model pass) can run on `worker_threads` inside each API replica
  instead of in the request handler: `ASIX_PARSER_WORKERS=N` (default `0` = inline, as before), `ASIX_PARSER_TIMEOUT_MS` (5000),
  `ASIX_PARSER_QUEUE` (100). Inline and workers call one function (`src/ingestion/parse-batch.js`), so results are identical.
- **Hard time limit and isolation:** a batch that runs too long or crashes (or exhausts a worker's 192 MB heap cap) costs one worker,
  which is replaced; the API keeps serving. Its events are stored **unparsed** with `parsed._parse_error` (`PARSE_TIMEOUT`,
  `PARSE_WORKER_CRASH`, `PARSE_FAILED`), never lost. A tenant whose rules fail 3 batches in a row is skipped for 60 s
  (`PARSE_QUARANTINED`). This is the "worker with a hard timeout" that the regex-safety item listed as not built, for the HTTP lane.
- **Back-pressure:** every worker busy and the queue full is `503 INGEST_BUSY` with `Retry-After: 2`; nothing is stored, the sender retries.
- Workers are sent the tenant's rule text (a hash key identifies it) and compile it once; the first batch after saving new rules carries the new text.
- Needs no schema change and no role change. Shipped **off**: `k8s/30-asix-api.yaml` has `ASIX_PARSER_WORKERS` at `"0"`; turn it on with
  `"2"` and a higher memory limit (see `docs/parser-workers.md`).
- Checked with real worker threads and a fake worker that hangs, crashes and runs out of memory (`tests/parser-pool.test.js`), and on real
  PostgreSQL 16 through the real HTTP lane, inline and on 2 workers (`tests/parse-ingest-db.test.js`), plus the real `src/server.js` with 2
  workers (parsed an sshd line, exited 0 on SIGTERM).
- Not built: a portal view of the pool, re-parsing events stored unparsed, parser processes outside the API and Kafka between broker and
  parser (Phase 3), a per-tenant share of the workers.

### Broker VM and collector heartbeat (what exists)
- A broker VM runs Vector: syslog in on UDP and TCP, forwarded over HTTPS to the existing HTTP ingest lane with a
  per-broker ingestion key (revocable, named on the Collectors page), through a 1 GiB on-disk buffer that survives
  ASIX outages. `scripts/deploy/bootstrap-broker.sh` installs and starts it; `docs/broker-vm.md` has the steps.
- Vector rewrites events to the `ISO-time host app[pid]: message` shape the HTTP lane already parses, so parsing
  rules and the data model need no change and there is no schema change.
- Heartbeat: brokers (and the in-cluster syslog collector) ping `POST /v1/ingest/heartbeat` (or `/broker` for the
  shared token) every 60 s, refreshing `collectors.last_seen`, so an idle source stays Connected. The Collectors
  page merges the key-less (built-in) heartbeat rows with their event-derived counts.
- Not built: managing brokers from the portal (config push, upgrades, capacity), syslog over TLS, non-syslog
  sources on the broker, Kafka between broker and parser (Phase 3), a per-collector connected threshold (still 15 min).

### Alert triage (what exists)
- Each alert can be assigned to a user of the same tenant (or unassigned), and carries analyst notes
  (stored with the author's name at the time, so notes survive a user being deleted; deleting a user
  just unassigns their alerts).
- The Alerts list has an assignee column and filter (anyone / me / unassigned), and tick-boxes to
  acknowledge or close up to 200 alerts at once. The alert detail shows the assignee picker and notes.
- Uses the existing `alerts:read` / `alerts:write` permissions, so no role changes are needed.
- Needs the new schema (`alerts.assignee_id`, `alert_notes`); it is applied by the normal schema-init
  job on deploy and is safe to re-run.
- Not built: a "my open alerts" dashboard tile, notes on status changes, note editing or deletion.

### Alert dedupe (what exists)
- **What counts as a repeat:** two active (open or acknowledged) alerts from the same rule with the same group key. The rule
  runner already folds new hits into an alert that saw events within twice the rule window; repeats appear when a noisy
  source goes quiet for longer and then returns. Alert raising itself is unchanged.
- **What a merge does:** the oldest alert is kept. It takes the summed event count, the earliest first-seen and latest
  last-seen time, and the worst severity. Status becomes open if any merged alert was open (an unhandled repeat is not hidden
  behind an acknowledged one). It keeps its owner, or takes the owner of the most recently active repeat that had one.
  The other alerts are closed and linked to it (`merged_into_id`); nothing is deleted. Their notes move to the kept alert,
  and an "ASIX" note records who merged how many. Closed alerts are never updated by the rule runner or the IOC matcher, so
  the kept alert simply carries on absorbing new events.
- **Portal:** Alerts page, button **Find repeat alerts**: groups with their alerts, **Merge into the oldest** per group or
  **Merge all groups**. The list shows `(N merged)` next to the event count; the alert detail lists what was merged into it.
- **API:** `GET /v1/alert-duplicates`, `POST /v1/alerts/merge` (`{primary_id, ids}`, up to 200, all must be active and from
  the same rule and group, else 409), `POST /v1/alert-duplicates/merge` (everything, one savepoint per group),
  `GET /v1/alerts/:id/merged`. Uses `alerts:read` / `alerts:write`, so no role changes are needed.
- **Schema:** `alerts.merged_into_id` and `alerts.merged_count`, added by the normal schema-init job and safe to re-run.
- Not built: merging automatically on a schedule or as alerts are raised, undoing a merge (reopening a merged alert works but
  it stays linked and is not offered for merging again), merging alerts from different rules, and keeping the sample events
  of the merged alerts (the kept alert shows its own).

### Regex safety (what exists)
- One checker, `src/security/regex-safety.js`, used everywhere a user can supply a pattern.
- **Parsing rules (`~=`, `regextract`)** run in the Node process, where a bad pattern can freeze ingest. Patterns are
  parsed and refused at save time if they have nested repeats `(a+)+`, repeated alternatives that start the same
  way `(a|ab)+`, a repeated group that can match nothing `(a|)*`, two adjacent overlapping repeats `\d+\d+`, a
  back-reference, more than 4 open-ended repeats, or more than 300 characters. Values are also cut to 4096
  characters before matching, which bounds the cost of anything that slips through.
- **Detection rules and XQL `~=`** are matched by PostgreSQL (already under `statement_timeout`), so they get the
  length limit (500) and a back-reference ban only.
- The check is conservative: it can refuse a harmless pattern, and the error message says what to change.
- Not built: running user patterns on an RE2 engine (would remove the need for the structural check). A hard timeout now exists for the
  HTTP ingest lane when parser workers are on (see "Parser workers"); detection rules and XQL are still bounded by PostgreSQL's `statement_timeout`.

### Content packs (what exists)
- A pack is one file in `src/packs/catalog/<id>.js` (file name = id): name, version, the log sources it expects, and a
  list of detection rules (correlation or BIOC). Packs are validated at load; a bad pack is skipped with a log line and
  fails `tests/packs.test.js`.
- Three residential packs ship: **Home Linux server** (SSH and sudo), **Home router and firewall** (OpenWrt-style
  messages) and **Home Mac** (commands that weaken macOS protections). They match on fields the built-in parsers already
  produce or on raw text, so no new parser is needed.
- Portal page **Content packs**: install, add missing rules, restore shipped rules, remove. API: `GET /v1/packs`,
  `POST /v1/packs/:id/install` (`{enabled, overwrite}`), `DELETE /v1/packs/:id` (`?delete_alerts=true` needed if the
  rules have raised alerts). Uses `detections:rules:read` / `detections:rules:write`, so no role changes; gated on the
  `content-packs` module being on.
- Installed rules are ordinary `detection_rules` rows with `builtin_key = pack:<pack>:<rule>`. That makes install
  idempotent through the existing unique index and needs no schema change. Installing again never overwrites edits;
  "restore" does, and keeps the enabled state. The rules page shows them as built-in (no Delete button there; remove
  the pack instead) and its Reset button works for them.
- Not built: parser and dashboard content in packs, pack upgrade notices (the version is shown but not tracked per
  tenant), per-rule tuning inside the Packs page, packs signed and delivered from a marketplace (Phase 4).

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

## Status of Phase 3 (updated this build)

| Item | State |
|---|---|
| ClickHouse server in `k8s/` (StatefulSet, volume, password Secret) | Done, optional and not used until `ASIX_EVENT_STORE=clickhouse` (see below and `docs/clickhouse-server.md`) |
| Copy existing events from PostgreSQL to ClickHouse | Not started |
| ClickHouse backup and restore test | Not started |
| Kafka between broker and parser; parser processes outside the API | Not started |
| S3 archive, HA control-plane DB, multi-node capacity dashboard | Not started |

### ClickHouse server (what exists)
- `k8s/11-clickhouse.yaml`: one `clickhouse/clickhouse-server:24.8` pod with a 20Gi volume, database and user `asix`, a password in the secret
  `clickhouse-secret` made once by `deploy.sh`, reachable only inside the cluster as `clickhouse:8123`, memory capped at 75% of a 2Gi limit, and
  ClickHouse's own diagnostic tables trimmed so they cannot outgrow the events.
- **Optional:** `./sync-and-deploy.sh --with-clickhouse` (or `ASIX_DEPLOY_CLICKHOUSE=1`) deploys it; once it exists every deploy keeps it up to date.
  A Home install that does not ask is unchanged. **Deploying it does not move events:** the API switches only when `ASIX_EVENT_STORE` is set to
  `"clickhouse"` in `k8s/30-asix-api.yaml`, and that switch does not copy existing events and is not covered by the nightly backup. Read
  `docs/clickhouse-server.md` before switching.
- Checked on a real ClickHouse 24.8.14.39 with the manifest's own config file (store, search, rule-match and retention suites pass as user `asix`; the
  real `src/server.js` ingested into it) and by validating every manifest against the Kubernetes schema (`scripts/ci/validate-k8s.py`, CI job
  `k8s-manifests`). Deployed on the k3s box: the pod came up Running, the image created user and database `asix`, the config file was loaded, the API
  pods reached it with the secret's password, and the volume is `Retain`. **Not yet tried:** load, and a restart with events in it.
- Not built: the event copy tool, ClickHouse backup, anything beyond one node (replication, Keeper, TLS to the API, a NetworkPolicy).

## Open decisions (ask before committing)
- Smallest Home machine to design against (assumed: 4 vCPU / 8 GB / 100 GB until told otherwise).
- Licensing model: open core vs. fully commercial with locked modules (business decision; the
  signed-license mechanism is the same either way).
- Enterprise search engine: ClickHouse alone vs. ClickHouse + OpenSearch (can wait until Phase 3).
