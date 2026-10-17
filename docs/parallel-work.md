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

The parse step of the HTTP ingest lane lives in `src/ingestion/parse-service.js` (inline, or on worker threads when `ASIX_PARSER_WORKERS` is set); `http-ingest.js` only calls it. Change parsing behaviour in `parse-batch.js` (it is what the workers run too), not in `http-ingest.js`.

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
| Remove the `xql.compile` / `compileCondition` wrappers; create the ClickHouse table on deploy | done (wrappers: `tests/xql-golden.test.js` and `tests/bioc-rules.test.js` call the parser and the Postgres emitter directly; init: real `src/server.js` started against an empty ClickHouse database and against an unreachable one) | `src/search/xql.js`, `src/search/xql-postgres.js` (`conditionToSql` kept only as the golden test's oracle), `init()` in `src/events/event-store.js` and `src/events/clickhouse-store.js`, `src/server.js` (calls `init()` before listening, exits if it fails), `tests/clickhouse-partitions.test.js` (init cases), `tests/event-store-conformance.js` (`init()` repeatable), `tests/event-store-clickhouse.test.js` (real-server init cases) |
| ClickHouse adapter (same conformance suite) | done (verified against a real ClickHouse 24.8; an earlier version claimed this but never ran: it used an npm client that was not in `package.json`, lost milliseconds and miscounted inserts) | `src/events/clickhouse-store.js` (fetch, no new dependency), registered in `src/events/index.js`, `tests/event-store-clickhouse.test.js`, CI job `clickhouse` in `.github/workflows/ci.yml`; gated behind `ASIX_TEST_DB=1`. `search()` and `matchGroups()` are implemented and pass `tests/event-search-conformance.js` and `tests/event-match-conformance.js` on real ClickHouse 24.8 |
| Parsers as separate workers | done as worker threads in the API, off by default (see `docs/parser-workers.md`; checked with real workers, with a fake worker that hangs, crashes and runs out of memory, on PostgreSQL 16 through the real HTTP lane inline and on 2 workers, and with the real `src/server.js`) | `src/ingestion/{parse-batch,rule-sets,parser-worker,parser-pool,parse-service}.js` (new), `getRuleSources` in `src/ingestion/rules-store.js`, `src/ingest/http-ingest.js` (calls `parse-service`; 503 `INGEST_BUSY`; `parsed._parse_error`), `src/server.js` (starts and stops the pool), `k8s/30-asix-api.yaml` (`ASIX_PARSER_WORKERS="0"`, `ASIX_PARSER_TIMEOUT_MS`), `tests/parse-batch.test.js`, `tests/parser-pool.test.js`, `tests/parse-ingest-db.test.js`, `tests/fixtures/fake-parser-worker.js`, CI step "Ingest parsing on parser workers" |

## Task table (Phase 3 of `docs/product-plan.md`, enterprise data plane)
| Task | Status | Main files (prefer new files) |
|---|---|---|
| ClickHouse server in `k8s/` (StatefulSet, volume, password Secret), optional | done and deployed on the k3s box (see `docs/clickhouse-server.md`; pod Running, user/database created by the image, config loaded, the API reaches it with the secret's password, volume `Retain`; also checked on a real ClickHouse 24.8.14.39 with the four ClickHouse suites and the real `src/server.js` on it; manifests schema-checked). Not yet tried under load or across a restart with data in it | `k8s/11-clickhouse.yaml` (new), `k8s/30-asix-api.yaml` (`ASIX_EVENT_STORE`, `CLICKHOUSE_PASSWORD`, `ASIX_CLICKHOUSE_URL`), `deploy.sh` (step "6-ch/9", opt-in), `sync-and-deploy.sh` (`--with-clickhouse`), `scripts/ci/validate-k8s.py` (new), CI job `k8s-manifests`, `docs/clickhouse-server.md` |
| Copy existing events between PostgreSQL and ClickHouse | done (see `docs/clickhouse-server.md`, "Copying events"; real PostgreSQL 16 and ClickHouse 24.8.14.39 through the real command line, plus in-memory stores; run on the k3s box 2026-10-17: dry run, then 2679 events copied and every one read back and compared, 0 already there; not measured at scale) | `src/events/copy-events.js` (new; lives in `src/` because the image has no `scripts/`), `tests/copy-events.test.js` (unit, in `npm test`), `tests/copy-events-db.test.js` (gated, in the CI `clickhouse` job), `docs/clickhouse-server.md` |
| ClickHouse backup and restore test | done (see `docs/clickhouse-backup.md`; real PostgreSQL 16 + ClickHouse 24.8.14.39: unit tests, gated DB test, the real nightly job and `restore.js` end to end; script arguments with a stubbed `k3s`; run on the k3s box 2026-10-17: manual `backup-now-*` job wrote 20 daily files and verified them, `ch-verify` gave 20 days / 2679 rows, `ch-restore --as` into an empty table restored 2679 (already there 0); not measured at scale) | `src/backup/clickhouse-backup.js` (new), `src/backup/backup.js`, `src/backup/restore.js`, `src/events/clickhouse-store.js` (`dropTable`), `k8s/32-backup.yaml`, `k8s/12-schema-init.yaml` (`backup_runs.kind`), `src/storage/safety.js`, `scripts/restore-backup.sh`, `tests/clickhouse-backup.test.js` (unit), `tests/clickhouse-backup-db.test.js` (gated, CI `clickhouse` job) |

## Checklist for any session picking up a task here
1. Confirm which zip/version you're starting from; diff it against what's currently described as
   "latest" before writing anything.
2. State which task (see the task table) you're doing, in your first message, so a human
   coordinating multiple sessions can avoid double-booking a file.
3. Prefer new files over edits to shared files (`shared.js`, `index.html`, `index.js`,
   `12-schema-init.yaml`) wherever the feature allows it.
4. Run the in-repo tests before declaring a feature done: `node tests/modules.test.js`,
   `tests/alert-triage.test.js`, `tests/alert-dedupe.test.js`, `tests/bioc-rules.test.js`, `tests/data-model-rules.test.js`,
   `tests/clickhouse-partitions.test.js`, `tests/parsing-rules.test.js`, `tests/regex-safety.test.js`, `tests/packs.test.js`, `tests/heartbeat.test.js`, `tests/event-envelope.test.js`, `tests/event-store-memory.test.js`, `tests/event-match-memory.test.js`, `tests/xql-golden.test.js`, `tests/event-search-memory.test.js`, `tests/search-route.test.js`, `tests/read-counts.test.js`, `tests/core-reads.test.js`, `tests/parse-batch.test.js`, `tests/parser-pool.test.js`, `tests/copy-events.test.js`, `tests/clickhouse-backup.test.js` (and `python3 scripts/ci/validate-k8s.py` after any change under `k8s/`; needs `pip install kubernetes-validate pyyaml`) (they need `npm ci` first; `modules.test.js` uses `jose`). CI (`.github/workflows/ci.yml`) now runs `npm run lint` (ESLint `no-undef`) and `npm test` (every `tests/*.test.js`, on Node 20 and 22) on each push; run both locally before packaging. New tests must be named `*.test.js` to be picked up. Tests that need a database stay gated behind `ASIX_TEST_DB=1` (they skip themselves without it); CI runs them in the `postgres` job (platform schema from `k8s/12-schema-init.yaml`) and the `clickhouse` job (a ClickHouse 24.8 service). New gated test files must be added to the list in those jobs in `.github/workflows/ci.yml`. (`tests/retention-db.test.js` and `tests/retention-clickhouse.test.js` (needs both Postgres and ClickHouse), `tests/packs-db.test.js`, `tests/heartbeat-db.test.js`, `tests/alert-dedupe-db.test.js`, `tests/event-store-postgres.test.js`, `tests/read-counts-db.test.js`, `tests/core-reads-db.test.js`, `tests/event-ingest-db.test.js`, `tests/parse-ingest-db.test.js` (CI also runs it a second time with `ASIX_PARSER_WORKERS=2`), `tests/copy-events-db.test.js` and `tests/clickhouse-backup-db.test.js` (need both PostgreSQL and ClickHouse; run in the `clickhouse` job) and `tests/detection-store-db.test.js` are the pattern: they skip themselves without that variable). A task is not "done" because a gated test exists: run it once against the real server before writing "done" in this table. Broker config changes: also run `vector test deploy/broker/vector.yaml deploy/broker/vector-tests.yaml` (needs the Vector binary; not in CI).
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

## What to build next
**Phase 2 is done.** Phase 3 (enterprise data plane, see `docs/product-plan.md`) has started: the ClickHouse server is in `k8s/` (optional, unused until `ASIX_EVENT_STORE=clickhouse`). Next, in this order:
1. **Proved on the k3s box on 2026-10-17** (all steps passed; `ASIX_EVENT_STORE` is still `postgres`). Steps, for repeating after a change: deploy; `copy-events.js --dry-run`, then the copy; run one backup by hand (`k3s kubectl -n asix-platform create job --from=cronjob/asix-backup backup-now-$(date +%s)`); `sudo scripts/restore-backup.sh ch-verify`; one `ch-restore --as <table>`. Result: copy 2679 events verified, ClickHouse backup of 20 days verified, `ch-restore --as` restored 2679 into an empty table. **Next:** run `copy-events.js --since <time printed by the first copy>`, set `ASIX_EVENT_STORE` to `"clickhouse"` in `k8s/30-asix-api.yaml`, deploy, run the `--since` copy again, check the portal's event pages, then delete `clickhouse-0` and confirm the count survives the restart.
2. Then the broker and collector items, and Kafka between broker and parser (parser processes outside the API would replace the worker threads of `docs/parser-workers.md`).
Before or alongside: turn parser workers on on the k3s box (`ASIX_PARSER_WORKERS` in `k8s/30-asix-api.yaml`, with a higher memory limit) and watch the API log for `[parser]` lines for a few days; this has only been run in tests and against a local server so far.
Before switching a real install: `copy-events.js --dry-run` and the copy have run on the k3s box (2679 events in the 512Mi API pod, no problem); speed and memory with much larger histories are still unmeasured.
Smaller, independent items that were open before and still are: license-limit enforcement (`tenants`, `retention_days_max`), portal menu that follows module state, a "my open alerts" tile, a portal view of the parser pool, re-parsing events stored with `parsed._parse_error`.

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
for t in event-store-postgres event-search-postgres event-match-postgres search-route detection-store-db retention-db parse-ingest-db; do ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=pw node --test tests/$t.test.js; done
ASIX_PARSER_WORKERS=2 ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=pw node --test tests/parse-ingest-db.test.js   # the same ingest test on the parser workers
# ClickHouse: any 24.x server; create a database, then
curl -s http://127.0.0.1:8123/ -d 'CREATE DATABASE IF NOT EXISTS asix'
for t in event-store-clickhouse event-search-clickhouse event-match-clickhouse retention-clickhouse; do ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=pw ASIX_CLICKHOUSE_URL=http://default@127.0.0.1:8123/asix node --test tests/$t.test.js; done   # retention-clickhouse also needs the Postgres above
```
Two traps seen while building this: an event is identified by `(id, received_at)` across ALL tenants, so test data with
fixed ids collides with rows a crashed earlier run left behind (`tests/fixtures/xql-dataset.js` generates fresh ids per
run for that reason); and piping a test run into `head` kills it before its cleanup runs.

## Known gaps to check
- `scripts/restore-backup.sh` arrived without its executable bit in a zip ("Permission denied" on the k3s box, 2026-10-17). Run `git update-index --chmod=+x scripts/restore-backup.sh` (and the other `scripts/*.sh`), or call it as `bash scripts/restore-backup.sh`.
- Run on the k3s box 2026-10-17 and passing: the copy, the manual backup job, `ch-verify`, `ch-restore --as`. Still untried: ClickHouse under real load and across a restart with events in it, and `ASIX_EVENT_STORE=clickhouse` on that box.
- `k8s/11-clickhouse.yaml` and the `deploy.sh` ClickHouse step ran on the k3s box on 2026-10-17 and passed the checks listed in `docs/clickhouse-server.md`. Still untried: ClickHouse under real load and after a restart with events in it. The CI job `k8s-manifests` has not run on GitHub (the script was run locally, with a negative test).
- The CI step "Ingest parsing on parser workers" and `parse-ingest-db` in the `postgres` job's list are new and have not run on GitHub. The same commands were run locally against PostgreSQL 16 (schema applied twice first), inline and with `ASIX_PARSER_WORKERS=2`, all green; `npm run lint` and `npm test` (153 tests) too.
- `.github/workflows/ci.yml` in the zip this was built from had only the `test` job (earlier notes said the DB jobs existed; they
  did not). The `postgres` and `clickhouse` jobs are in it now. Every step script was extracted from the YAML and run locally against
  PostgreSQL 16 and ClickHouse 24.8.14.39 (schema applied twice with errors fatal; ClickHouse with a password on `default`), all
  green. The workflow has not run on GitHub: the service-container health checks and the ClickHouse image's `CLICKHOUSE_*` variables
  are untested there. If a separate workflow in the repo already
  runs these tests, keep one of the two.
- `ASIX_EVENT_STORE=clickhouse` was documented but not registered in `src/events/index.js` in that zip; it is now.
- Several tests listed above (`modules`, `regex-safety`, `packs`, `alert-triage`, `alert-dedupe`) were not in the zip
  this was built from. Diff against the repo before relying on that list.
