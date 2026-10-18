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
- **Parser pool page (done):** Settings, Parser pool shows how parsing runs, the pool's counters and how many events were stored unparsed in the
  last 24 hours / 3 days / 7 days, by reason (`GET /v1/parser/status`, uses `capacity:read`, read-only, no schema or role change). The counters belong to
  the API pod that answers and restart with it; the unparsed count comes from the event store, so it covers all pods and either engine. Details:
  `docs/parser-workers.md`.
- Not built: re-parsing events stored unparsed, counters that add up across API pods, parser processes outside the API and Kafka between broker and
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
- **Syslog over TLS (done, optional):** `bootstrap-broker.sh --tls-cert/--tls-key` adds an RFC 5425 listener (default 6514) as a second Vector
  config file; events take the same rewrite, buffer and HTTPS sink. Optional mutual TLS with `--tls-client-ca`. Checked against Vector 0.47.0
  (handshake, both framings, mutual TLS accept and refuse, the bootstrap script with and without TLS); not yet tried on a real broker VM
  under systemd or with real devices. Details: `docs/broker-vm.md`.
- **Brokers page (done, read-only):** Settings, Brokers lists the broker VMs that report to this install (`GET /v1/brokers`, uses `collectors:read`, no schema or role
  change), recognised by the heartbeat's `vector-<version>` version text (`src/brokers/broker-view.js`). Each shows status (with its own connected threshold), Vector
  version, events in the last 24 hours (from the event store; the page still loads if that fails), installer key state, and what needs attention (key revoked or deleted,
  not seen for N minutes). The top shows totals and whether Vector versions are mixed, and the page gives the `bootstrap-broker.sh` command for a new broker (key left as a
  placeholder). Checked on real PostgreSQL 16 (`tests/brokers-db.test.js`, CI `postgres` job) and in unit and route tests (`tests/brokers.test.js`); the page has not been seen in a browser.
- **Rotate key (done):** the Brokers page has a **Rotate key** button per broker (`POST /v1/brokers/:id/rotate-key`, uses `collectors:write`, no schema or role change). It makes a
  new installer key named `<broker>-key-<yyyymmdd-hhmm>` (platform copied from the old key, else linux) and returns it once with the bootstrap command filled in. **The old key is
  not revoked**, so nothing is cut off: run the command on the broker, wait until its heartbeat arrives (it moves the broker's row to the new key by itself, which leaves the
  old key with no collectors), then press **Revoke old key** in the dialog or revoke it on the Installers page. Only the key hash is stored. A broker whose key was revoked or
  deleted can be rotated too. Checked on real PostgreSQL 16 (`tests/broker-rotate-key-db.test.js`, CI `postgres` job: both keys send a heartbeat, the broker moves to the new one,
  the revoked old one is refused) and in unit and route tests (`tests/broker-rotate-key.test.js`). The button has not been seen in a browser; not tried on a real broker VM.
- **Upgrades, first slice (done):** see "Broker upgrades" below: a target Vector version, a per-broker "Behind / Up to date" flag, and `scripts/deploy/upgrade-broker.sh` to run on the VM.
- Not built: pushing the new key to the broker (re-running the bootstrap script is still by hand), changing a broker from the portal otherwise (config push, running an upgrade from the portal, capacity per broker), TLS on the in-cluster Node collector, certificate renewal,
  non-syslog sources on the broker, Kafka between broker and parser (Phase 3). The syslog port can be set from the portal for brokers that opted in (see "Broker config pull" below). The connected threshold is per collector now (see "Collector connected threshold" below), and
  a broker can raise an alert when it goes Disconnected (see "Collector disconnect alerts" below).

### Broker upgrades (what exists, first slice)
- **The gap it closes:** the Brokers page showed Vector versions and said "more than one version is in use" but not which broker was behind or what to do about it. Upgrading was
  `apt` by hand with no check that the new Vector still accepts the broker's config (0.59 broke the old one).
- **A target, not a push.** Brokers page, **Vector version target** card (`GET` and `PUT /v1/broker-settings`, body `{ "vector_target": "0.60.0" | null }`; uses `collectors:read` /
  `collectors:write`, no role change). Only plain `x.y.z` is accepted (a 400 otherwise); empty or `null` clears it. Each broker in `GET /v1/brokers` now carries `upgrade`: `none` (no target),
  `current`, `behind`, `ahead` or `unknown` (the broker's version or the target is not plain `x.y.z`); the response also carries `vector_target`, `upgrade_command`, and the summary
  `behind_target`. Versions are compared as numbers (0.9.0 is older than 0.59.0). Behind is **not** a problem in `problems` and raises no alert. **ASIX runs nothing on a broker.**
- **The script:** `scripts/deploy/upgrade-broker.sh [--version X.Y.Z] [--dry-run]`, run as root on the broker VM. Installs the package, runs `vector validate` on that broker's own config (and
  `vector-tls.yaml` if there is one) against the NEW binary before restarting, restarts only if that passes, waits for Vector's health check, sends one heartbeat. A failed check leaves
  Vector running on the old binary and prints the downgrade command. Refuses a downgrade or an unknown version. Details: `docs/broker-vm.md`, "Upgrading Vector".
- **Schema:** table `broker_settings` (one row per tenant, `vector_target` with a CHECK on the format, row-level security like the other tenant tables; no row = no target), created by the
  normal schema-init job and safe to re-run. If the table is missing (schema job not yet run) the Brokers page still loads, with no target.
- Checked on real PostgreSQL 16 with the schema applied twice (`tests/broker-upgrade-db.test.js`, in the CI `postgres` job: no row means no target, set / update / clear on one row, the
  `updated_by` column, the states `behind` / `current` / `unknown` from real collector rows, another tenant does not see it, the database refuses a malformed value;
  `brokers-db`, `broker-rotate-key-db`, `heartbeat-db`, `collector-watch-all-db` still pass), in unit and route tests (`tests/broker-upgrade.test.js`) and with every system command
  stubbed for the script (`tests/upgrade-broker-script.test.js`: order of the steps, no restart on a bad config, refusals, dry run, TLS file included, unhealthy restart). `npm test` (356
  tests) and `npm run lint` clean; `scripts/ci/validate-k8s.py` 0 failures; portal script parses. **Run on the first real broker VM (vm1, 2026-10-18, arm64, Vector 0.59.0): `--dry-run`, `--version 0.60.0` (refused cleanly: the repository has no such version and nothing changed) and no
  argument ("already the newest version", nothing restarted). The real install, config check, restart and heartbeat path has not run: the Vector repository offers only 0.58.0 and 0.59.0 for arm64, so there was nothing newer to install. The
  card and the Upgrade column have not been seen in a browser, the new CI line has not run on GitHub, not yet run on the k3s box.**
- Not built: running the upgrade from the portal (it needs an agent or a pull on the broker and a decision on how that is authenticated and signed; the config pull below is the first use of a pull, for the syslog port only), a per-broker target, a rollback
  command that undoes a restart that failed (the script prints the way back, it does not run it), non-apt systems, config push.

### Broker config pull (what exists, first slice)
- **The gap it closes:** the Brokers page could show and rotate but not change anything, and the open question was how a broker could be configured from the portal without ASIX running anything on it (see "Not built" under Broker upgrades). The answer built here is a **pull**: a broker that opted in asks ASIX for its config and applies it after its own checks. One setting so far, the syslog port.
- **Opt in on the broker:** `bootstrap-broker.sh --accept-config` writes `ASIX_ACCEPT_CONFIG=true` and installs a root timer (`asix-broker-config.timer`, every 5 minutes) for `deploy/broker/asix-broker-config.sh`. Without the flag nothing is installed and ASIX cannot change the broker; re-running the bootstrap without it removes the timer.
- **Setting:** Brokers page, **Syslog port for brokers** card; `GET` and `PUT /v1/broker-config` (`collectors:read` / `collectors:write`, no role change). Stored in `broker_settings.syslog_port` (new nullable column with a 1 to 65535 CHECK, added by the normal schema job and safe to re-run; the Vector version target on the same row is untouched). Reserved ports (22, 443, 8686, 30443) are refused with a reason. If the column is missing (schema job not yet run) the page shows a notice instead of the card.
- **Pull lane:** `GET /v1/ingest/broker-config` with the broker's ingestion key (same key check and rate limit as the heartbeat; revoked or unknown key = 401): `{ config: { syslog_port: N | null }, interval_seconds: 300 }`. Read only.
- **The broker's rules:** it re-checks the port itself (so a wrong value from ASIX cannot lock it out), edits only the `ASIX_SYSLOG_PORT` line (backup kept), runs `vector validate`, restarts Vector, waits for health, and on any failure puts the old file back, restarts Vector on it and remembers the rejected port so it is not retried every 5 minutes. It never opens the firewall. Details and the steps: `docs/broker-vm.md`, "Config from ASIX".
- Checked: real PostgreSQL 16 with the schema applied twice (`tests/broker-config-db.test.js`, CI `postgres` job: the portal route and the broker lane agree, update on one row, the Vector target survives both settings in either order, refused values change nothing, the database CHECK refuses 70000, another tenant sees nothing, no key / unknown key / revoked key get 401; `brokers-db`, `broker-upgrade-db`, `broker-rotate-key-db`, `heartbeat-db`, `collector-watch-all-db`, `offsite-backup-db` still pass), route and rule tests (`tests/broker-config.test.js`), and the broker script with `id`, `vector`, `systemctl` and `curl` stubbed (`tests/broker-config-script.test.js`: no opt-in means no request, the URL and key, null and same port do nothing, a new port edits one line and keeps the mode and a backup, validate runs before the restart, unsafe and malformed answers are ignored, a failed validate / restart / health check puts the old file back, a rejected port is not retried and a different one clears it). `npm test` (404 tests) and `npm run lint` clean; `scripts/ci/validate-k8s.py` 0 failures; portal script parses. **Run on the k3s box and on broker-1 (vm1, Ubuntu aarch64, Vector 0.59.0) 2026-10-18:** the bootstrap re-run with `--accept-config` validated and installed the timer; with no port set, two timer runs did nothing (exit clean, no change); after the port was set to 1514 on ASIX, one pull logged "ASIX asks for syslog port 1514 (now 514). Applying." then "Done: syslog port 514 -> 1514, Vector healthy", `broker.env` said `ASIX_SYSLOG_PORT=1514`, Vector listened on 1514 UDP and TCP and nothing listened on 514. **Not yet seen:** the test line from `logger -P 1514` arriving in Events (sent, not confirmed), setting the port back to 514, a failed validate, restart or health check on a real broker (stubs only), a refused port from the portal, the card in a browser, the new CI line on GitHub.
- **What each broker applied (done 2026-10-18):** the gap it closes: the Brokers page showed the setting, not whether any broker had picked it up. After **every** run that asked ASIX, `asix-broker-config.sh` now tells ASIX which syslog port it listens on and which port it rejected (an `EXIT` trap, best effort: a failed report changes nothing and never the script's exit status). `POST /v1/ingest/broker-config/report` with `{ collector, syslog_port, rejected_port | null }` and the broker's own ingestion key (same key check and rate limit as the pull; the GET stays read only). It is **information, not a setting**: it is stored on the broker's own collector row (`collectors.config_syslog_port`, `config_rejected_port`, `config_reported_at`, new nullable columns with 1 to 65535 CHECKs, added by the normal schema job and safe to re-run) and found by key AND name, so one key cannot write another broker's row (`recorded: false`), and a report never creates a row. `GET /v1/brokers` now returns `syslog_port` and, per broker, `config` = `{ state, configured_port, reported_port, rejected_port, reported_at }` with `state` one of `none | unknown | applied | rejected | pending | stale` (rules in `configState()` in `src/brokers/config.js`: applied = reported port equals the asked port; rejected = it reports rejecting the asked port; pending = a different port, report under 15 minutes old; stale = same but older; unknown = a port is asked for and the broker never reported; none = nothing asked), and the summary has `config_applied` and `config_not_applied`. The Brokers page has a **Syslog port** column (Applied / Pending / Rejected / Not asking / Not reporting) and an "N of M applied" pill on the port card. None of it is a "needs attention" problem and none raises an alert. Uses `collectors:read`, no role change. Table of states and what to do: `docs/broker-vm.md`, "What the Brokers page shows".
- Checked (reports): real PostgreSQL 16 with the schema applied twice (`tests/broker-config-db.test.js`, same CI `postgres` line, now with the real heartbeat creating the rows, the real report route and the real `GET /v1/brokers`: unknown, pending, rejected, applied, a later heartbeat keeps the report, another key in the same tenant / another tenant's key / a name with no row all get `recorded: false` and write nothing, another tenant's page sees only its own broker, a moved or cleared port, an old report going stale, the database CHECKs refuse bad ports; the test was also run with the key condition weakened and fails there), unit and route tests (`tests/broker-config.test.js`: body rules, the SQL, `configState` for every state and the 15 minute edge, the route with no key / bad key / bad body / malformed / oversized JSON / database failure; `tests/brokers.test.js`: state in `shape`, `summarize` counts, the listing and the page still loading when the setting cannot be read), and the broker script with `id`, `vector`, `systemctl` and `curl` stubbed (`tests/broker-config-script.test.js`, 21 tests: what is reported after a change, with nothing to change, after a rejection, after an unhealthy restart is put back, when the report cannot be sent, a name with a quote, no name, no port line, a garbled port line, and nothing sent when the broker did not opt in or is not root). `npm test` (413 tests) and `npm run lint` clean; `scripts/ci/validate-k8s.py` 0 failures; portal script parses and the new cell function was run for all seven states. **Also run once with the REAL broker script and REAL `curl` against the real routes and PostgreSQL in the sandbox** (only `id`, `vector` and `systemctl` stubbed): no port set (reported 514, none), port set (pending), applied 1514 (applied), 2514 failing validate (rejected, port 1514 still reported), the next run not retrying (still rejected), 3514 applied, port cleared (none). **Not yet run on the k3s box or on broker-1 (the script on the broker must be replaced and the schema job must run on deploy first), the column and the card line have not been seen in a browser, the CI line was not changed so nothing new has run on GitHub.**
- **A port for one broker (done 2026-10-18):** the gap it closes: the syslog port was one value for every broker, so a broker that had to listen elsewhere (another device class, a port already taken on that VM) could not be given its own. `PUT /v1/brokers/:id/syslog-port` with `{ syslog_port: N | null }` (`collectors:write`, no role change; Brokers page, **Port** button per row) sets `collectors.syslog_port_override` (new nullable column with a 1 to 65535 CHECK, added by the normal schema job, safe to re-run; only a broker, meaning a collector whose version reads `vector-<version>`, of the caller's own tenant can be set, otherwise 404). It wins over the tenant-wide port for that broker only and works with no tenant-wide port. The pull is `GET /v1/ingest/broker-config?collector=<name>`; the answer keeps the same shape (`config.syslog_port`), the row is found by key AND name, and a missing, odd or repeated name, or a database without the column, gets the tenant-wide answer. `GET /v1/brokers` returns per broker `config.source` (`broker | tenant | none`) and `config.override_port`, the state is judged against the effective port, and the summary has `port_overrides`. The broker script sends its name (only a plain name, never anything else in the URL). **Needs the new script on each broker** (re-run the bootstrap with `--accept-config`); an older script is told the tenant-wide port. Nothing about the broker's own checks, the way back or the reports changed. Checked: real PostgreSQL 16 with the schema applied twice (`tests/broker-port-override-db.test.js`, CI `postgres` job: own port, tenant-wide port, both, clear, a key reading only its own broker's port, another tenant's key and broker, a non-broker collector, refused values, the database CHECK, a revoked key, heartbeat and tenant-wide saves leaving the override alone; the test fails with the key-and-name condition weakened; `broker-config-db`, `brokers-db`, `broker-upgrade-db`, `broker-rotate-key-db`, `heartbeat-db`, `collector-watch-all-db`, `core-reads-db` still pass), unit and route tests (`tests/broker-port-override.test.js`, 15 tests), and the broker script with `id`, `vector`, `systemctl` and `curl` stubbed (`tests/broker-config-script.test.js`, two new cases: the name in the URL, odd names left out, an own port applied and put back on failure). `npm test` (431 tests) and `npm run lint` clean; `scripts/ci/validate-k8s.py` 0 failures; portal script parses and the cell function was run for every state and both sources. **Run on broker-1 (vm1) 2026-10-18 after a deploy: the real script with the real `curl` applied an own port, 1514 to 2514, Vector healthy and listening on 2514 UDP and TCP.** Not yet seen: the test line in Events, the column showing Applied (own), clearing the port to go back, a rejected own port, the Port button in a browser, the new CI line on GitHub.
- **Leave one broker out of the tenant-wide port (done 2026-10-18):** the gap it closes: the tenant-wide port reached every broker that opted in, and an own port could only name a port, so a broker that had to keep the port it has could not be exempted. `PUT /v1/brokers/:id/syslog-port-exclude` with `{ exclude: true | false }` (`collectors:write`, no role change; Brokers page, **Leave out** / **Follow port** button per row) sets `collectors.syslog_port_exclude` (new `BOOLEAN NOT NULL DEFAULT false` column, added by the normal schema job, safe to re-run; only a broker of the caller's own tenant can be set, otherwise 404). A left-out broker is answered `config.syslog_port: null` (no opinion; the broker script already does nothing for null), so it keeps the port it listens on; **an own port still wins** (`effectivePort(tenant, own, exclude)`: own, else null if left out, else tenant-wide). The pull reads the flag only when it matters (a name was sent, no own port, a tenant-wide port set), found by key AND name, in its own transaction: a database without the column still gets the tenant-wide answer. `GET /v1/brokers` returns per broker `config.excluded` and `config.source` can now be `excluded`; the summary has `port_excluded` (left out and without an own port). A left-out broker is asked for nothing, so its state is `none` (neither applied nor not applied); the port card's pill now counts only brokers that are asked for a port (`config_applied + config_not_applied`), where before it used every broker as the total. **No change to the broker script**, so nothing to re-run on a broker that already sends its name; a broker on a script older than the per-broker port is told the tenant-wide port whatever the flag says. Leaving a broker out does not send it back to an older port: it keeps what it listens on. Checked: real PostgreSQL 16 with the schema applied twice (`tests/broker-port-exclude-db.test.js`, CI `postgres` job: not left out by default, the column refuses NULL, left out gets null while another broker still gets the tenant-wide port, an older script with no name still gets it, a key reads only its own broker's flag (broker-c's key naming broker-a, another tenant's key, a name with no row), the Brokers page source / state / counts, an own port wins and clearing it returns to left out, heartbeat, report and tenant-wide saves leave the flag alone, no tenant-wide port leaves it dormant, putting it back, bad body / bad id / another tenant's broker / a non-broker 404 write nothing, a revoked key gets 401; the test fails with the key condition dropped from the flag lookup and fails with the broker-only condition dropped from the write; `broker-port-override-db`, `broker-config-db`, `brokers-db`, `broker-upgrade-db`, `broker-rotate-key-db`, `heartbeat-db`, `collector-watch-all-db`, `collector-watch-exclude-db`, `core-reads-db` still pass), unit and route tests (`tests/broker-port-exclude.test.js`, 17 tests: rules, SQL, page shape, summary, route validation and failures, the pull in every combination, a missing column). `npm test` (449 tests) and `npm run lint` clean; `scripts/ci/validate-k8s.py` 0 failures; portal script parses and the cell function was run for left out (with and without a tenant-wide port), left out with an own port, applied, pending, none and unknown. **Not yet run on the k3s box or on a real broker, the button and the pill have not been seen in a browser, the new CI line has not run on GitHub.** How to use it and the caveats: `docs/broker-vm.md`, "Leaving one broker out of the tenant-wide port".
- **Signed config (done 2026-10-18):** the gap it closes: the pull was protected only by the HTTPS connection and the broker's ingestion key, which is not enough to build anything riskier on (a remote upgrade, a changed source). With `ASIX_CONFIG_SIGNING_KEY` set (the Secret `asix-platform/asix-config-signing`, optional in `k8s/30-asix-api.yaml`; made by `scripts/deploy/make-config-signing-key.sh [--apply]`, openssl only, never overwrites a key file or a Secret), `GET /v1/ingest/broker-config` adds `signed: { v, alg, key_id, payload, signature }` next to the unchanged `config` (`src/brokers/config-signing.js`). The payload is one small JSON text, `{"v":1,"collector":"broker-1"|null,"issued_at":<epoch s>,"syslog_port":N|null}`, sent base64 so a broker verifies the exact bytes; ECDSA P-256 with SHA-256, DER signature, so `openssl dgst -sha256 -verify` is all a broker needs. A broker installed with `bootstrap-broker.sh --accept-config --config-pubkey FILE` (the file may hold several public keys; every one must be P-256; needs openssl; `ASIX_CONFIG_PUBKEY_FILE` in `broker.env`) acts **only** on the signed text: it must verify against one key, be for this broker's name (or for none if the broker has no usable name) and be within `ASIX_CONFIG_MAX_SKEW_S` (default 600) seconds of the broker's clock; the unsigned `config` is ignored; anything else changes nothing (exit 1, reason in the journal). The broker's own port rules, validate, restart and put-back are unchanged. A broker without a public key, and an ASIX without a signing key, behave exactly as before. An unusable key (not PEM, not P-256) is logged and the answers go out unsigned (a requiring broker refuses them) instead of the pull failing. Portal: the Syslog port card shows **Answers signed (key ...)**, **Answers not signed** or **Signing key unusable**, and a **Copy public key** button (`GET /v1/broker-config` returns `config.signing`, the public key only). No schema, role or SQL change. **Limits, stated plainly:** the private key lives on ASIX, so this protects against a spoofed address, tampering in transit and anything that can write the database but cannot read the Secret; it does not protect against someone who can read the Secret (an offline signing key is not built); replacing the signing key is a manual procedure (`docs/broker-vm.md`, "Signed config"); the Brokers page cannot tell which brokers verify signatures (a broker does not report that). Checked: unit and route tests (`tests/config-signing.test.js`: key loading, PKCS8 and SEC1, literal `\n`, RSA and P-384 refused, the key id equals openssl's, every refusal rule of `verify()`, several keys, the two routes with and without a key, an unusable key); the REAL `asix-broker-config.sh` with REAL openssl, base64, awk, answers made by the real signer, only `id`, `vector`, `systemctl`, `curl` stubbed (`tests/broker-config-signed-script.test.js`, 14 tests: good, signed port used over the unsigned one, signed null, unsigned refused, changed payload / signature / other key, garbled base64, missing key file, another broker, no name, old and future answers and the limit, two keys, a signed port 22, the report still sent, scratch folder removed, shell and JavaScript agree; each of four removed checks makes it fail); the two scripts (`tests/config-signing-scripts.test.js`, 10 tests: the key pair matches and ASIX loads it, never overwrites, `--apply` with a stubbed `k3s`, refuses an existing Secret, bootstrap refusals); **and once by hand in the sandbox as root: the real bootstrap with `--config-pubkey` (env line written, key id printed equals the key script's, a re-run without it removes both), then the INSTALLED script against the real route, signing with the key the key script made, over real `curl`: applied 514 to 1514; the same with the answer changed in transit (config and payload set to 2514): refused, nothing changed; with ASIX unsigned: refused**. A first version of the script was found by the tests to take about 8 seconds per run (a `sed` repeat count of 2000 compiles slowly); it now measures the length in the shell. `npm run lint` clean; `scripts/ci/validate-k8s.py` 0 failures; portal script parses and the new line was run for its four states. **Not yet run on the k3s box or on broker-1, the pill and the Copy button have not been seen in a browser, the new tests have not run on GitHub (they need openssl, which the CI runners have).**
- Not built: any setting but the syslog port (TLS port, buffer size, sources), an offline signing key and a way to see which brokers verify signatures, firewall changes, a way to push the opt-in to an existing broker without re-running the bootstrap script, Kafka between broker and parser.

### Collector connected threshold (what exists)
- A collector is **Connected** if it was last seen within its threshold: 15 minutes unless the collector has its own. A slow sender (a nightly job) can be given a
  longer one, a chatty one a shorter one. The rule is one small module, `src/collectors/status.js`, and `GET /v1/collectors` uses it for both the status column and
  the `status=` filter. Each collector in the response now carries `connected_within_min` (the threshold in force) and `connected_custom` (it was set on purpose);
  `connected_within_minutes` at the top is still the default.
- **Set it:** Collectors page, **Threshold** button (empty goes back to the default), or `PUT /v1/collectors/:id/threshold` with `{ "minutes": 1..10080 }` or
  `{ "minutes": null }`. Anything else is a 400; another tenant's collector is a 404. Uses `collectors:write`, so no role change.
- **Schema:** `collectors.connected_within_min INTEGER` (NULL = default), added by the normal schema-init job and safe to re-run. A heartbeat or an event never
  changes it. Nothing is ever deleted or hidden because of it: it only moves the line between Connected and Disconnected.
- Checked on real PostgreSQL 16 with the schema applied twice (`tests/collector-threshold-db.test.js`, in the CI `postgres` job: default, custom, back to default,
  other tenant refused, a heartbeat leaves it alone) and in unit and route tests (`tests/collector-status.test.js`, in `npm test`). The button has not been seen in a browser.
- Not built: a default for the whole tenant (set per collector only), a threshold for sources that appear only in events (the in-cluster syslog collector keeps its
  heartbeat row, so it can be set; a source with no row cannot). The "went Disconnected" alert is done: see "Collector disconnect alerts" below.

### Collector disconnect alerts (what exists)
- **Opt in per collector:** Collectors page, **Alert if down** button (Stop alerting turns it off), or `PUT /v1/collectors/:id/watch` with `{ "watch": true | false }`
  (uses `collectors:write`, so no role change). Every collector starts off, so deploying this raises nothing by itself. The Brokers page shows the setting.
- **What it does:** a watchdog (`src/collectors/watchdog.js`, started with the API like the rule runner; every 60 s, one replica at a time through a PostgreSQL
  advisory lock) looks at the watched collectors. One that is past its connected threshold (the same rule and the same per-collector threshold as the Collectors page,
  `src/collectors/status.js`) gets one alert: rule `Collector disconnected`, title `Collector disconnected: <name>`, severity `high`, group `collector:<id>`, no
  detection rule behind it (like the IOC matcher's alerts). The alert goes through the notification channels that already exist: nothing was added there, a channel
  whose minimum severity is `high` or lower and whose rule filter allows it sends it once.
- **One alert per outage:** a collector that stays down keeps its one alert (open or acknowledged). If an analyst closes it while the collector is still down, no new
  alert is raised for that outage (the alert remembers the `last_seen` it was raised for). When the collector sends again, the alert is closed with an "ASIX" note;
  the next outage raises a new alert. The alert is also closed (with a note) when watching is turned off, the collector is deleted, or its threshold is raised above the gap.
- **After an API restart:** collectors could not report while the API was down, so no new alert is raised for the first 5 minutes (`ASIX_WATCHDOG_GRACE_SECONDS`);
  closing still works. A collector that has never been seen is skipped. `ASIX_WATCHDOG_SEVERITY` changes the severity (`critical`, `high`, `medium`, `low`);
  `ASIX_WATCHDOG_ENABLED=false` stops the watchdog; `ASIX_WATCHDOG_INTERVAL_SECONDS` (default 60, minimum 15).
- **Schema:** `collectors.watch_disconnect BOOLEAN NOT NULL DEFAULT false`, added by the normal schema-init job and safe to re-run. Nothing is deleted or hidden.
- Checked on real PostgreSQL 16 with the schema applied twice (`tests/collector-watch-db.test.js`, in the CI `postgres` job: not watched raises nothing, start-up grace,
  one alert for the down collector and none for the connected, unwatched or other tenant's, no duplicate while open or acknowledged, no repeat after a manual close,
  closed with a note on reconnect, a new outage raises a new alert, custom threshold, watching off, collector deleted, and the real notification dispatcher sending it
  once) and in unit and route tests (`tests/collector-watchdog.test.js`, in `npm test`). **Not yet run on the k3s box or seen in a browser.**
- Not built: a per-collector severity, a separate "recovered" notification (the alert closes with a note, nothing is sent), (the tenant-wide "watch everything" switch is done: see "Collector watch everything" below),
  (An alert when a broker's installer key is revoked or deleted is done: see "Broker key alerts" below. An alert for a collector that stops sending events while its heartbeat keeps arriving is done: see "Collector silence alerts" below.)

### Collector silence alerts (what exists)
- **The gap it closes:** the heartbeat keeps an idle broker or the built-in syslog collector Connected, so "Collector disconnected" cannot see a device that quietly stopped sending
  behind a healthy broker. This alert looks at the newest *event* instead.
- **Opt in per collector:** Collectors page, **Alert if silent** button (asks for minutes, 5 to 4320; empty turns it off), or `PUT /v1/collectors/:id/silent-watch` with
  `{ "minutes": 5..4320 }` or `{ "minutes": null }` (uses `collectors:write`, so no role change). Every collector starts off, so deploying this raises nothing by itself.
  The Collectors list returns `watch_silent_min` and shows an "Alert if silent" column. A source that only appears in events has no row to hold the setting, so it cannot be watched (same as the threshold).
- **What it does:** the same watchdog cycle that checks for Disconnected collectors (every 60 s, one replica at a time, same start-up grace, same `ASIX_WATCHDOG_*` settings) now also
  runs `src/collectors/silence.js`. It asks the event store for the newest event per collector over the last 7 days (`groupCounts`, so it works on PostgreSQL and ClickHouse; events are matched
  to the collector by name) and raises one alert when that is older than the collector's limit: rule `Collector sending no events`, title `Collector sending no events: <name>`, severity `high`
  (`ASIX_WATCHDOG_SEVERITY` applies), group `silent:<id>`, no detection rule behind it. It goes through the existing notification channels; nothing was added there.
- **Not raised for a Disconnected collector:** if the collector itself is past its connected threshold, the "Collector disconnected" alert is the right one and this stays quiet (so one outage does not
  raise two alerts). A silent alert that is already open stays open if the collector then goes Disconnected.
- **One alert per silence:** a collector that stays silent keeps its one alert (open or acknowledged). If an analyst closes it while the collector is still silent, no new alert is raised for that
  same silence (the alert remembers the newest event it was raised for). When events arrive again the alert is closed with an "ASIX" note; the next silence raises a new alert. It is also closed (with a
  note) when the watch is turned off, the collector is deleted, or the limit is raised above the gap.
- **Limits of the look-back:** a collector with no event at all in the last 7 days is skipped (nothing to measure from), and an alert already open for it stays open. That is why the limit tops out at 3 days.
  A watched collector that has never sent an event raises nothing.
- **Schema:** `collectors.watch_silent_min INTEGER` (NULL = off), added by the normal schema-init job and safe to re-run. Nothing is deleted or hidden.
- Checked on real PostgreSQL 16 with the schema applied twice and the real PostgreSQL event store (`tests/collector-silence-db.test.js`, in the CI `postgres` job: nothing watched raises nothing, one alert for the
  silent collector and none for the flowing, unwatched, Disconnected, no-events or other tenant's, raised for the newest event, the real notification dispatcher sending it once, no duplicate while open or acknowledged,
  no repeat after a manual close, closed with a note when events return, a new silence raises a new alert, limit raised, Disconnected collector left to the other alert until it counts as Connected, watch off, collector deleted,
  and the list route returning the setting) and in unit and route tests (`tests/collector-silence.test.js`, in `npm test`). **Not run on ClickHouse (the only store call is `groupCounts`, which the conformance suites already
  cover on both engines), not yet run on the k3s box, the new button and column not seen in a browser, the new CI line not run on GitHub.**
- Not built: a per-collector severity, a limit above 3 days, (the tenant-wide "watch everything" limit is done: see "Collector watch everything" below), a "recovered" notification (the alert closes with a note, nothing is sent), silence per source type or per
  device behind a broker (it is per collector, so a broker with ten devices is silent only when all ten are), a watch for sources that appear only in events.

### Broker key alerts (what exists)
- **The gap it closes:** a broker whose installer key was revoked or deleted is rejected by ASIX, but it only showed as "Collector disconnected" after its threshold, with no cause. This alert is
  immediate and says what to do.
- **No new setting, no schema change, no new button:** it applies to brokers (collectors whose version reads `vector-<version>`) that already have **Alert if down** on. It runs in the same watchdog cycle
  (same start-up grace, same `ASIX_WATCHDOG_SEVERITY`, same notification channels) as `src/collectors/key-watch.js`.
- **What it does:** a watched broker still tied to a revoked key, or whose key was deleted (`collectors.key_id` is NULL), gets one alert: rule `Broker installer key unusable`, title
  `Broker installer key unusable: <name>`, severity `high`, group `brokerkey:<id>`, no detection rule behind it. The summary tells the operator to press **Rotate key** on the Brokers page and re-run the bootstrap script.
- **Rotation raises nothing:** the new key is active and the heartbeat moves the broker onto it before the old key is revoked, so a revoked key with no broker on it is not a problem. Revoking the old key
  *before* the broker moved does raise it, which is correct.
- **One alert per problem:** it stays while the problem stays. It closes (with an "ASIX" note) when the broker is on an active key again, the watch is turned off, or the broker is deleted. If an analyst
  closes it while the same key is still bad it is not raised again for that key; a different problem (the replacement key revoked, or the key deleted) raises a new one.
- Checked on real PostgreSQL 16 with the real heartbeat lane, the real rotate-key, revoke and delete routes and the real notification dispatcher (`tests/broker-key-watch-db.test.js`, in the CI `postgres`
  job: only the watched broker on a bad key raises, not healthy, unwatched, non-broker or other-tenant ones; sent once; no repeat; closed on rotation; the normal rotation order raises nothing; deleted key
  raises a new alert; watch off and broker deleted close it; the watchdog's real `runOnce` runs it without error) and in unit tests (`tests/broker-key-watch.test.js`, in `npm test`).
  **Not yet run on the k3s box or a real broker, the new CI line has not run on GitHub.**
- Not built: an alert for a key that is about to expire (keys do not expire), a separate alert for a key revoked on a collector that is not a broker, a "recovered" notification.

### Collector watch everything (what exists)
- **The gap it closes:** "Alert if down" and "Alert if silent" were per collector, so a new collector or broker was not watched until someone pressed the button on its row. One tenant-wide switch now covers every collector,
  including ones that appear later.
- **Two settings, both off until chosen** (Collectors page, **Watch everything** card; `GET` and `PUT /v1/collector-watch-defaults`, uses `collectors:read` / `collectors:write`, no role change; body `{ "disconnect": true|false, "silent_min": 5..4320|null }`, at
  least one, what is left out is kept):
  - `disconnect`: every collector gets the "Collector disconnected" alert, and every broker the "Broker installer key unusable" alert, as if "Alert if down" were on for it.
  - `silent_min`: every collector with no limit of its own gets the "Collector sending no events" alert after that many minutes. **A collector's own "Alert if silent" limit always wins**, longer or shorter.
- **It only adds.** It never changes the per-collector settings, and turning it off leaves anything switched on by hand switched on. One collector can be left out of it (see "Leave one collector out" below).
- **Retired collectors are left out.** A collector not seen for more than `ASIX_WATCH_ALL_MAX_AGE_DAYS` days (default 7, 1 to 90) is treated as gone; otherwise turning the switch on would raise one alert for every machine ever decommissioned.
  A collector switched on by hand is never left out. If a collector ages out while its alert is open, the watchdog closes the alert with an "ASIX" note ("no longer watched"). The card says how many collectors are left out.
- **Turning it off** closes, on the next watchdog cycle, the alerts that only the switch was holding up (note: "no longer watched"), and leaves the hand-switched collectors' alerts alone. Turning it on again for the same outage does not raise a
  second alert (the same rule as for a collector switched on by hand: one alert per outage).
- **Where the rules live:** `src/collectors/watch-all.js`. The watchdogs send the rule to PostgreSQL as part of their existing collector query (`WHERE_DISCONNECT`, `SILENT_MIN_SQL`), so `plan()` in `watchdog.js`, `silence.js` and `key-watch.js` is unchanged. The same
  rules exist in plain code (`watchesDisconnect`, `silentMinutes`) for the Collectors page, which shows **On (all)** / **After N min (all)** on rows covered by the switch (the stored last-seen time is used, as the watchdogs do).
  `tests/collector-watch-all-db.test.js` runs the SQL and the plain code on the same rows.
- **Schema:** table `collector_watch_defaults` (one row per tenant, row-level security like the other tenant tables; no row = off), created by the normal schema-init job and safe to re-run.
- Checked on real PostgreSQL 16 with the schema applied twice (`tests/collector-watch-all-db.test.js`, in the CI `postgres` job: off by default, bad requests refused and nothing stored, a Disconnected collector covered and a connected, retired or other-tenant one not,
  a hand-switched old collector kept, the broker on a revoked key alerted, the silent limit with a collector's own longer limit winning, the list showing what covers each row, SQL and plain-code rules equal, turning each off closing only its own alerts, a new outage after
  turning back on) and in unit and route tests (`tests/collector-watch-all.test.js`, in `npm test`). `collector-silence-db`, `collector-watch-db`, `collector-threshold-db`, `broker-key-watch-db`, `brokers-db`, `heartbeat-db` still pass; `npm run lint` clean;
  `scripts/ci/validate-k8s.py` 0 failures; portal script parses. **Not yet run on the k3s box, the card and the "(all)" pills have not been seen in a browser, the new CI line has not run on GitHub, not run on ClickHouse (the silent check's only store call is `groupCounts`, which the
  conformance suites cover).**
- **Leave one collector out (done):** Collectors page, **Leave out of all** button (shown while a switch is on, and on a collector already left out, where it reads **Include in all**), or
  `PUT /v1/collectors/:id/watch-exclude` with `{ "exclude": true | false }` (uses `collectors:write`, no role change; a non-boolean is a 400, another tenant's collector a 404). A collector left out is
  not covered by either switch setting (no "Collector disconnected", no "Collector sending no events" from the silent limit, no "Broker installer key unusable" for a broker). **It only leaves the switch:**
  "Alert if down" and a limit under "Alert if silent" set by hand on that collector still apply, as before. An alert that only the switch was holding open for it is closed on the next watchdog cycle with an
  "ASIX" note ("no longer watched"); putting it back covers it again. The list shows `watch_exclude` and the rows say **Left out** instead of **Off**. Schema: `collectors.watch_exclude BOOLEAN NOT NULL DEFAULT false`
  (schema-init job, safe to re-run). The rule is one more condition in the same shared SQL (`WHERE_DISCONNECT`, `SILENT_MIN_SQL`) and in `key-watch.js`'s query, and in the plain-code rules.
  Checked on real PostgreSQL 16 with the schema applied twice (`tests/collector-watch-exclude-db.test.js`, in the CI `postgres` job: left-out collectors raise nothing for any of the three alerts, a hand-set
  one and one with its own limit still do, the list and the plain-code rules agree with the SQL, leaving one out closes its alert with a note, putting one back raises it again, another tenant's collector is
  refused; the test was also run with the SQL change removed and fails there) and in unit and route tests (`tests/collector-watch-exclude.test.js`). `collector-watch-all-db`, `collector-silence-db`, `collector-watch-db`,
  `broker-key-watch-db`, `collector-threshold-db`, `brokers-db`, `heartbeat-db`, `core-reads-db` still pass; `npm test` (365 tests), `npm run lint` and `scripts/ci/validate-k8s.py` clean; portal script parses.
  **Not run on the k3s box, the button and the "Left out" pills have not been seen in a browser, the new CI line has not run on GitHub.** Not built: leaving a collector out of one alert only (it is both), a bulk
  "leave out" for several collectors.
- Not built: a severity per setting, a switch for sources that appear only in events (they have no row), a count of how many alerts the switch would raise before it is turned on, the Brokers page showing the switch (it shows only what was set on the broker).

### Alert triage (what exists)
- Each alert can be assigned to a user of the same tenant (or unassigned), and carries analyst notes
  (stored with the author's name at the time, so notes survive a user being deleted; deleting a user
  just unassigns their alerts).
- The Alerts list has an assignee column and filter (anyone / me / unassigned), and tick-boxes to
  acknowledge or close up to 200 alerts at once. The alert detail shows the assignee picker and notes.
- Uses the existing `alerts:read` / `alerts:write` permissions, so no role changes are needed.
- Needs the new schema (`alerts.assignee_id`, `alert_notes`); it is applied by the normal schema-init
  job on deploy and is safe to re-run.
- **"My open alerts" tile (done):** the Command Center shows, under the severity row, how many open or acknowledged alerts are assigned to the signed-in
  user (by severity, how many are still open, and how long the oldest unhandled one has waited) and the five that most need attention (worst severity,
  open before acknowledged, newest first), each linking to the Alerts page filtered to "assigned to me". With nothing assigned it links to the unassigned
  alerts instead. `GET /v1/my-alerts` (uses `alerts:read`; a service account has no user, so it answers `applicable: false` and the tile is not drawn). The tile
  is also hidden when the Alerts module is not on. Checked on real PostgreSQL 16 (`tests/my-alerts-db.test.js`, in the CI `postgres` job) and in unit tests.
- Not built: notes on status changes, note editing or deletion.

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

### License limits (what exists)
- **One place for the rules:** `src/modules/limits.js` (pure functions). The limits come from the signed license, or the profile's defaults when there is
  no valid license (Home and Enterprise both default to 1 tenant and 90 days; a failed module snapshot falls back to the Home defaults).
- **Retention cap, enforced on save:** `PUT /v1/storage/retention` answers `403 LICENSE_LIMIT` when `default_days` or an override is above the cap, or an
  override is keep-forever (null) while a cap is set. Only what the request changes is checked, so switching automatic purge on or off is never blocked.
  `GET /v1/storage/retention` now also returns `limit_days` and `over_limit` (stored settings above the cap). The portal sets the inputs' `max` to the cap
  and shows a notice.
- **Nothing is deleted or changed because of a limit:** an expired or removed license, or a lower cap, leaves stored retention settings and all data as they
  are and reports them as over the limit. The retention job is unchanged: it purges only by the rules the tenant saved.
- **Tenants:** `checkTenantCreate(count, limits)` returns the refusal (`LICENSE_LIMIT`) to use before inserting a tenant. `GET /v1/modules` now returns
  `usage.tenants` and `over_limit`, and the Modules page shows the count next to the limit. No route creates tenants yet (`src/tenant/tenant-service.js` is a stub), so
  nothing calls it today.
- Checked with `tests/limits.test.js` (rules, and the real storage route with the sign-in chain and database stubbed). Not built: a per-tenant cap, SSO/other limit
  keys, an audit entry when a save is refused beyond the normal request audit.

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
- **License limits (enforced, see below):** `retention_days_max` is applied when retention rules are saved; `tenants` is a
  rule ready for tenant creation to call (there is no tenant-creation route yet). The Home retention cap of 90 days
  is a placeholder until the licensing decision below is made.
- **Portal menu follows module state (done):** the portal reads `GET /v1/modules` (at most once a minute) and greys any menu entry whose module is not on,
  tagged "locked" (or "soon" for a planned module). Opening one shows why (profile, license or dependency) and a link to Modules instead of calling the API.
  The path-to-module map (`MENU_MODULE`) is one block in `src/portal/index.html`. It only shapes the menu: the server still decides what is allowed, a user
  without `modules:read` or a failed read greys nothing, and the Modules page is never greyed. On a Home install every Home module is on, so today nothing is
  greyed; it shows up when a module is locked (for example a Home module whose dependency is off) or an Enterprise page is added.
  There is still no per-tenant module toggle (that would need a schema change).

## Status of Phase 3 (updated this build)

| Item | State |
|---|---|
| ClickHouse server in `k8s/` (StatefulSet, volume, password Secret) | Done, optional and not used until `ASIX_EVENT_STORE=clickhouse` (see below and `docs/clickhouse-server.md`) |
| Copy existing events between PostgreSQL and ClickHouse | Done (see below and `docs/clickhouse-server.md`); run on the k3s box 2026-10-17 (2679 events, verified) |
| ClickHouse backup and restore test | Done (see below and `docs/clickhouse-backup.md`); run on the k3s box 2026-10-17 (20 days backed up and verified, 2679 events restored into a new table) |
| Live event store switched to ClickHouse on the k3s box | Done 2026-10-17 (`ASIX_EVENT_STORE=clickhouse`; catch-up copies, test event, restart of `clickhouse-0` with 2684 events intact); not yet seen under load |
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
- Not built: ClickHouse backup, anything beyond one node (replication, Keeper, TLS to the API, a NetworkPolicy).

### Event copy tool (what exists)
- `node src/events/copy-events.js --from postgres --to clickhouse` (and the reverse) copies a tenant's events between the stores and reads every
  copy back and compares it. It runs inside an API pod, per tenant, in batches, with `--tenant`, `--since`, `--until`, `--batch`, `--dry-run`, `--no-verify`.
- It skips events **by id**, so it is safe to repeat and to run again after switching `ASIX_EVENT_STORE` to catch the events written in between. A copy back does
  not duplicate events (ClickHouse keeps milliseconds, PostgreSQL microseconds, so the stores' `(id, received_at)` idempotency alone would). It deletes nothing and
  never overwrites a different event that holds the same id (it reports it).
- Checked on real PostgreSQL 16 and ClickHouse 24.8.14.39 through the real command line (`tests/copy-events-db.test.js`, run by the CI job `clickhouse`) and with
  in-memory stores (`tests/copy-events.test.js`, in `npm test`). **Run on the k3s box 2026-10-17 (2679 events, all verified); not measured at millions of events.**
- Not built: copying anything but events, a progress file to resume (use `--since`), parallel tenants, a portal button.

### ClickHouse backup (what exists)
- The nightly job (`asix-backup`) now also backs up the events held in ClickHouse when ClickHouse is deployed: one encrypted file per UTC day (all tenants),
  incremental (a day is re-read only when its count changed or it is one of the last two), a manifest with a content digest per day, `BACKUP_KEEP` days of grace
  for days that retention removed. About weekly it loads everything into a scratch table and compares each day with the manifest, then drops the table.
- Recorded in `backup_runs` (new column `kind`), shown by the Data safety page: critical when ClickHouse is the event store and has no backup, a failed or stale
  backup, or no test restore; warnings otherwise. `scripts/restore-backup.sh ch-list | ch-verify | ch-restore --as <table> | ch-restore --yes` (restore only adds).
- Checked on real PostgreSQL 16 and ClickHouse 24.8.14.39: unit tests, a gated real-database test (CI job `clickhouse`), and the real nightly job and `restore.js`
  commands end to end. A bug found on the way (two runs in one second could write the same file name) is fixed and has a test. **Run on the k3s box 2026-10-17 (nightly job's
  ClickHouse part, `ch-verify`, `ch-restore --as`); not measured at millions of events.**
- Not built: ClickHouse's native `BACKUP`, restoring one tenant, a portal screen (findings appear in the existing list). Off-VM copies are built: see "Off-VM copy of the backups" below.

### Off-VM copy of the backups (what exists)
- `scripts/offsite-backup.sh` copies the encrypted `asix-*` backup files (PostgreSQL and ClickHouse) to another machine with rsync over SSH (or to a local folder), checks the copy with a
  dry-run rsync (same names and sizes), and records a `backup_runs` row of `kind = 'offsite'`. `--install-timer` saves the settings and runs it every night at 03:30. Setup and details: `docs/offsite-backup.md`.
- The Data safety page shows a **Copy on another machine** card. The info finding "Backups are stored on this VM" stays until a good copy is under 36 hours old; a failed latest copy is a warning;
  a last good copy over 36 hours old is a warning, over 72 hours critical. No schema change (`backup_runs.kind` is a free text column).
- It never deletes on the other machine. The files are useless without the backup passphrase, which must be kept outside the VM too.
- Checked on real PostgreSQL 16 and over real SSH on one machine, unit tests and a gated DB test (CI `postgres` job). **Run on the k3s box 2026-10-18: first copy to another VM (2.7 MB, checked), shown on the Data safety page; the nightly timer run is not yet seen. The SSH path is not in CI.**
- **Pruning the other machine (done, optional, off until `--keep-days N`):** after a checked and recorded copy it deletes the `asix-*` files on the other machine that are both older than N days (N of at least 7) and no longer on this VM. `--prune-preview` lists them and changes nothing. It refuses with no `asix-*` files here, never runs after a failed copy, refuses to delete more than half of the other machine's files unless `--allow-large-prune`, and a prune problem is a warning, not a failed copy. Setting saved by `--install-timer` as `OFFSITE_KEEP_DAYS`; `--keep-days off` clears it. No schema, portal or role change. Checked against a local folder (`tests/offsite-backup-script.test.js`, 15 tests) and over real OpenSSH on one machine (preview, real run, wrong key). **Not yet run on the k3s box; the SSH path is not in CI.** Details and the disaster-recovery caveat: `docs/offsite-backup.md`.
- Not built: S3 or object storage, showing pruning on the Data safety page, a portal button, an alert when the timer is missing before any copy was recorded.

## Open decisions (ask before committing)
- Smallest Home machine to design against (assumed: 4 vCPU / 8 GB / 100 GB until told otherwise).
- Licensing model: open core vs. fully commercial with locked modules (business decision; the
  signed-license mechanism is the same either way).
- Enterprise search engine: ClickHouse alone vs. ClickHouse + OpenSearch (can wait until Phase 3).
