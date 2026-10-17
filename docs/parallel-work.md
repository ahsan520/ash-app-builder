# Working on this repo from multiple Claude sessions

This project has repeatedly hit the same failure mode: two sessions (or a session and a
teammate) editing `src/gateway/index.js` or `src/portal/index.html` at the same time, each
unaware of the other's changes. One side's work gets silently discarded when the other's zip
is uploaded. The fix is structural, not just "be careful."

## Backend: already split (as of this doc)
`src/gateway/index.js` is now a 60-line file that only sets up Express and mounts routers. All
route handlers live in `src/gateway/routes/<domain>.js`, one file per feature area:
`core`, `detections`, `search`, `alerts`, `threat-intel`, `collectors`, `notifications`,
`storage`, `capacity`, `parsing`, `data-model`, `modules`, `alert-triage`, `alert-dedupe`, `packs`. Collector heartbeats are not a gateway route: they are mounted from `src/ingest/heartbeat.js` before the JSON parser, like the HTTP ingest lane. Shared helpers (`db`, the auth middleware chain,
`guarded()`, `apiError()`, `UUID_RE`, `SEVERITIES`, `ALERT_STATUSES`) live in `src/gateway/shared.js`
and are imported, never redefined, by each route file.

**Rule going forward:** a new feature's routes go in a NEW file under `src/gateway/routes/`, not
appended to an existing one unless they genuinely belong to that domain. Two sessions building
unrelated features then touch different files and cannot collide.

**Events go through the event store (Phase 2).** New code writes events with `getEventStore().insertBatch()` from
`src/events` and does not run `INSERT INTO events` itself. **XQL search now reads through the store too**
(`xql.parse()` makes a query plan, `getEventStore().search(tenantId, plan)` runs it on any engine; see
`docs/event-store.md`). Detection rules, the IOC matcher, the counts on the collectors, storage and capacity pages and the retention preview and row purge
all go through the store now. Partition drops and the events part of the storage page (`dropPartitionsBefore`, `storageStats`) go through it too. What still uses SQL directly is creating PostgreSQL's daily partitions (`ensurePartitions`) and the control-plane table sizes on the storage page: do not add new raw `events` queries where a store method already does the job.

## Modules: one manifest file per module
Modules register themselves by dropping a file in `src/modules/manifests/<id>.js` (the file name
must equal the `id`). Two sessions adding two modules touch two different files. The registry
validates ids, tiers, entitlements and dependencies (unknown reference, cycle, or a Home module
requiring an Enterprise one all fail at load), and `tests/modules.test.js` loads every manifest, so
a bad manifest breaks the test run rather than production. Do not add module lists to
`gateway/index.js` or the portal by hand; enablement is resolved in `src/modules/index.js` from
`ASIX_PROFILE` plus the signed license.

## Frontend: still one file, by necessity
`src/portal/index.html` has no build step — it is shipped and parsed as a single HTML+JS document,
so it cannot be split into real ES modules without introducing a bundler (a bigger change than
this pass covers). Collision risk here is reduced instead by convention:
- Every page is one `async function pgXxx()` with a unique name, plus whatever page-local
  `let`/`const` state it owns, grouped under a `// ---- <Feature name> ----` banner comment.
- When adding a page, **append a new banner + function** at the end of the relevant group rather
  than editing an existing one in place, and add exactly one line to `NAV` or `SETTINGS` to wire
  it in.
- Before editing, diff the live file against the last zip you were handed (or ask for the
  current one) so you know your starting point actually matches what you're about to change.

## Task table (Phase 1 of `docs/product-plan.md`)
Update the Status column in the same change that does the work, so the next session sees it.

| Task | Status | Main files (prefer new files) |
|---|---|---|
| Data safety (backups, restore test, volume checks) | done | `src/storage/safety.js`, `src/backup/*`, portal "Data safety" |
| Module / profile skeleton + signed-license entitlements | done (skeleton) | `src/modules/*`, `src/gateway/routes/modules.js`, `scripts/license-tool.js`, portal "Modules" |
| Alert triage: assign, notes, bulk acknowledge/close | done | `src/gateway/routes/alert-triage.js`, `alerts.js` (assignee filter/column), `12-schema-init.yaml` (`alerts.assignee_id`, `alert_notes`), portal "Alerts", `tests/alert-triage.test.js` |
| Alert dedupe / merge repeat alerts | done (manual + merge-all; no scheduled auto-merge) | `src/alerts/dedupe.js` (new), `src/gateway/routes/alert-dedupe.js` (new), mounted in `src/gateway/index.js`, `alerts.js` (returns `merged_into_id`, `merged_count`), `12-schema-init.yaml` (`alerts.merged_into_id`, `alerts.merged_count`), portal "Alerts" (Find repeat alerts), `tests/alert-dedupe.test.js`, `tests/alert-dedupe-db.test.js` |
| Collector heartbeat (idle built-in source should not read as Disconnected) | done | `src/ingest/heartbeat.js` (new), mounted in `src/gateway/index.js`, `src/gateway/routes/collectors.js` (merges key-less rows), `src/ingestion/syslog-server.js` (sends it), `tests/heartbeat.test.js`, `tests/heartbeat-db.test.js` |
| Regex-safety fix (user-supplied patterns, ReDoS) | done | `src/security/regex-safety.js` (new), wired into `src/ingestion/parsing-rules.js`, `src/detection/rule-query.js`, `src/search/xql.js`; `tests/regex-safety.test.js` |
| CI (run `tests/*.test.js` on push) | done | `.github/workflows/ci.yml`, `eslint.config.js`, `test` and `lint` scripts in `package.json` |
| Broker VM on Vector | done (syslog only, see `docs/broker-vm.md`) | `deploy/broker/*` (Vector config, tests, heartbeat timer), `scripts/deploy/bootstrap-broker.sh`, `docs/broker-vm.md`; reuses the HTTP ingest lane and per-installer ingestion keys, no schema change |
| Content packs (residential) | done (rules only; parsers and dashboards not yet) | `src/packs/*` (loader, service, `catalog/<id>.js` one file per pack), `src/gateway/routes/packs.js`, manifest `content-packs` now `available`, portal "Content packs", `tests/packs.test.js`, `tests/packs-db.test.js` |

## Task table (Phase 2 of `docs/product-plan.md`, foundation for scale)
| Task | Status | Main files (prefer new files) |
|---|---|---|
| Event envelope + event-store interface + Postgres adapter + conformance suite | done (see `docs/event-store.md`) | `src/events/*` (new), `tests/event-store-conformance.js`, `tests/event-envelope.test.js`, `tests/event-store-memory.test.js`, `tests/event-store-postgres.test.js`, `tests/event-ingest-db.test.js`; ingest writes switched in `src/ingest/http-ingest.js` and `src/gateway/routes/core.js`; no schema change |
| XQL query plan + `store.search()` (the query form that is not SQL), search route moved behind the store | done | `src/search/xql-plan.js` (plan shape, validator), `src/search/xql.js` (now parse only), `src/search/xql-postgres.js`, `src/search/xql-clickhouse.js`, `src/search/xql-eval.js` (in memory), `search()` in `src/events/{event-store,postgres-store,clickhouse-store,memory-store}.js`, `src/gateway/routes/search.js`, `tests/xql-golden.test.js`, `tests/event-search-{conformance,memory,postgres,clickhouse}`, `tests/search-route.test.js`, fixtures in `tests/fixtures/` |
| Move the counts on the collectors, storage and capacity pages and `/v1/search/fields` behind the store | done | `groupCounts`, `timeRange`, `fieldStats` in `src/events/{event-store,postgres-store,clickhouse-store,memory-store}.js`; callers `src/gateway/routes/{collectors,search,storage}.js`, `src/storage/retention.js` (`summary`), `src/capacity/capacity.js`; `tests/event-store-conformance.js` (new block), `tests/read-counts.test.js`, `tests/read-counts-db.test.js`. Run on real PostgreSQL 16 and ClickHouse 24.8.14.39 |
| Move detection rules, the IOC matcher and the alert sample events behind the store | done (see `docs/event-store.md` "Detection rules"; checked on in-memory, PostgreSQL and ClickHouse 24.8, and against the old SQL builder on 1,914 rule definitions) | `src/search/match-spec.js` (new), `matchGroups` in `src/events/*`, `matchToSql` / `matchToClickHouse` / `runMatch` in `src/search/xql-{postgres,clickhouse,eval}.js`, `@path` fields in `xql-plan.js`, `src/detection/{rule-query,rule-runner,ioc-matcher}.js`, `routes/{detections,alerts}.js`, `tests/event-match-*.js`, `tests/detection-store-db.test.js`; `querySQL` and `queryAggregated` removed |
| Move the events list, data sources and Command Center reads in `routes/core.js` behind the store | done (see `docs/event-store.md`, "The events list, data sources and Command Center behind the store") | `listEvents`, `dataSources`, `ingestionStats` in `src/events/{event-store,postgres-store,clickhouse-store,memory-store}.js`; `src/gateway/routes/core.js`; `tests/event-store-conformance.js` (new block), `tests/core-reads.test.js`, `tests/core-reads-db.test.js`. Run on real PostgreSQL 16 and ClickHouse 24.8.14.39 |
| Move the retention job behind the store | done (see `docs/event-store.md`, "The retention job behind the store"; run on in-memory, PostgreSQL 16 and ClickHouse 24.8.14.39) | `expiredCounts`, `deleteExpired` in `src/events/{event-store,postgres-store,clickhouse-store,memory-store}.js`, `src/events/pg-partitions.js` (new, shared partition reader), `src/storage/retention.js` (preview and purge ask the store; partition housekeeping skipped unless the engine is postgres), `tests/event-store-conformance.js` (new block), `tests/retention-db.test.js`, `tests/retention-clickhouse.test.js`, CI jobs `postgres` and `clickhouse` |
| ClickHouse retention by partition drop, and ClickHouse storage sizes | done (real ClickHouse 24.8.14.39 and PostgreSQL 16; table TTL deliberately not used, see `docs/event-store.md`) | `storageStats`, `dropPartitionsBefore` in `src/events/{event-store,postgres-store,clickhouse-store,memory-store}.js`, `src/storage/retention.js` (`dropExpiredPartitions` and `summary` are engine-agnostic now), `tests/event-store-conformance.js` (second block, `prepareDay` hook), `tests/clickhouse-partitions.test.js` (stubbed HTTP, runs in the `test` job), `tests/retention-db.test.js`, `tests/retention-clickhouse.test.js` |
| ClickHouse adapter (same conformance suite) | done (verified against a real ClickHouse 24.8; an earlier version claimed this but never ran: it used an npm client that was not in `package.json`, lost milliseconds and miscounted inserts) | `src/events/clickhouse-store.js` (fetch, no new dependency), registered in `src/events/index.js`, `tests/event-store-clickhouse.test.js`, CI job `clickhouse` in `.github/workflows/ci.yml`; gated behind `ASIX_TEST_DB=1`. `search()` and `matchGroups()` are implemented and pass `tests/event-search-conformance.js` and `tests/event-match-conformance.js` on real ClickHouse 24.8 |
| Parsers as separate workers | not started | `src/ingestion/*`, `src/ingest/http-ingest.js` |

## Checklist for any session picking up a task here
1. Confirm which zip/version you're starting from; diff it against what's currently described as
   "latest" before writing anything.
2. State which task (see the task table) you're doing, in your first message, so a human
   coordinating multiple sessions can avoid double-booking a file.
3. Prefer new files over edits to shared files (`shared.js`, `index.html`, `index.js`,
   `12-schema-init.yaml`) wherever the feature allows it.
4. Run the in-repo tests before declaring a feature done: `node tests/modules.test.js`,
   `tests/alert-triage.test.js`, `tests/alert-dedupe.test.js`, `tests/bioc-rules.test.js`, `tests/data-model-rules.test.js`,
   `tests/clickhouse-partitions.test.js`, `tests/parsing-rules.test.js`, `tests/regex-safety.test.js`, `tests/packs.test.js`, `tests/heartbeat.test.js`, `tests/event-envelope.test.js`, `tests/event-store-memory.test.js`, `tests/event-match-memory.test.js`, `tests/xql-golden.test.js`, `tests/event-search-memory.test.js`, `tests/search-route.test.js`, `tests/read-counts.test.js`, `tests/core-reads.test.js` (they need `npm ci` first; `modules.test.js` uses `jose`). CI (`.github/workflows/ci.yml`) now runs `npm run lint` (ESLint `no-undef`) and `npm test` (every `tests/*.test.js`, on Node 20 and 22) on each push; run both locally before packaging. New tests must be named `*.test.js` to be picked up. Tests that need a database stay gated behind `ASIX_TEST_DB=1` (they skip themselves without it); CI runs them in the `postgres` job (platform schema from `k8s/12-schema-init.yaml`) and the `clickhouse` job (a ClickHouse 24.8 service). New gated test files must be added to the list in those jobs in `.github/workflows/ci.yml`. (`tests/retention-db.test.js` and `tests/retention-clickhouse.test.js` (needs both Postgres and ClickHouse), `tests/packs-db.test.js`, `tests/heartbeat-db.test.js`, `tests/alert-dedupe-db.test.js`, `tests/event-store-postgres.test.js`, `tests/read-counts-db.test.js`, `tests/core-reads-db.test.js`, `tests/event-ingest-db.test.js` and `tests/detection-store-db.test.js` are the pattern: they skip themselves without that variable). A task is not "done" because a gated test exists: run it once against the real server before writing "done" in this table. Broker config changes: also run `vector test deploy/broker/vector.yaml deploy/broker/vector-tests.yaml` (needs the Vector binary; not in CI).
5. Route files must `require` everything they use. The route split once dropped the imports in
   `data-model.js` and `search.js`, which caused 500s in production. Before packaging, check for
   undefined names, for example `npx eslint --no-config-lookup --rule '{"no-undef":"error"}' src`
   (with `sourceType: commonjs` and node globals), (this is now `npm run lint`).
6. Anything that touches the database should be run once against a real Postgres, not only stubs:
   apply `k8s/12-schema-init.yaml`'s `schema.sql` twice (it must be idempotent), then run
   `ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/alert-triage.test.js` as the pattern.
7. A new permission string (for example `modules:read`) must also be added to the `portal-admin`
   role in `scripts/deploy/bootstrap-portal.sh`, in both the INSERT and the UPDATE lists, and that
   script re-run, or the portal page will show a 403.

## What to build next (Phase 2, in this order)
Start from `docs/event-store.md` ("What is left"). Done so far: XQL search, the page counts, detection rules and the IOC matcher,
the events list, data sources and Command Center reads, and now the retention preview and purge (`expiredCounts`, `deleteExpired`), and ClickHouse partition retention and storage sizes (`dropPartitionsBefore`, `storageStats`).
1. When no caller is left, delete the `xql.compile` / `compileCondition` wrappers (only `tests/xql-golden.test.js` calls them
   now; it pins the old compiler's SQL, so rework or retire it together with them).
2. A ClickHouse table created on deploy (today run `ensureSchema()` by hand), so a ClickHouse install needs no manual step.
3. Then parsers as separate workers (the last Phase 2 item in `docs/product-plan.md`).
(ClickHouse retention by partition drop and the ClickHouse storage page are done: see `docs/event-store.md`.)
Smaller, independent items that were open before and still are: license-limit enforcement (`tenants`, `retention_days_max`),
portal menu that follows module state, a "my open alerts" tile.

## How to run the database tests (repeat this before declaring a DB-touching change done)
```bash
sudo apt-get install -y postgresql                        # any 16
python3 - <<'PY'                                          # schema.sql out of the ConfigMap
import yaml
for d in yaml.safe_load_all(open('k8s/12-schema-init.yaml')):
    if d and d.get('kind') == 'ConfigMap': open('/tmp/schema.sql','w').write(d['data']['schema.sql'])
PY
sudo -u postgres psql -c "CREATE USER asix_admin SUPERUSER PASSWORD 'pw'" -c 'CREATE DATABASE asix_platform OWNER asix_admin'
PGPASSWORD=pw psql -h 127.0.0.1 -U asix_admin -d asix_platform -f /tmp/schema.sql      # twice: must be idempotent
for t in event-store-postgres event-search-postgres event-match-postgres search-route detection-store-db retention-db; do ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=pw node --test tests/$t.test.js; done
# ClickHouse: any 24.x server; create a database, then
curl -s http://127.0.0.1:8123/ -d 'CREATE DATABASE IF NOT EXISTS asix'
for t in event-store-clickhouse event-search-clickhouse event-match-clickhouse retention-clickhouse; do ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=pw ASIX_CLICKHOUSE_URL=http://default@127.0.0.1:8123/asix node --test tests/$t.test.js; done   # retention-clickhouse also needs the Postgres above
```
Two traps seen while building this: an event is identified by `(id, received_at)` across ALL tenants, so test data with
fixed ids collides with rows a crashed earlier run left behind (`tests/fixtures/xql-dataset.js` generates fresh ids per
run for that reason); and piping a test run into `head` kills it before its cleanup runs.

## Known gaps to check
- `.github/workflows/ci.yml` in the zip this was built from had only the `test` job (earlier notes said the DB jobs existed; they
  did not). The `postgres` and `clickhouse` jobs are in it now. Every step script was extracted from the YAML and run locally against
  PostgreSQL 16 and ClickHouse 24.8.14.39 (schema applied twice with errors fatal; ClickHouse with a password on `default`), all
  green. The workflow has not run on GitHub: the service-container health checks and the ClickHouse image's `CLICKHOUSE_*` variables
  are untested there. If a separate workflow in the repo already
  runs these tests, keep one of the two.
- `ASIX_EVENT_STORE=clickhouse` was documented but not registered in `src/events/index.js` in that zip; it is now.
- Several tests listed above (`modules`, `regex-safety`, `packs`, `alert-triage`, `alert-dedupe`) were not in the zip
  this was built from. Diff against the repo before relying on that list.
