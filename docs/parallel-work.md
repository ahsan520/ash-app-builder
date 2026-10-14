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
`src/events` and does not run `INSERT INTO events` itself. Reads still use SQL until the search, detection and
retention paths are moved behind the store (see `docs/event-store.md`); do not add new raw `events` queries
where a store method already does the job.

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
| Move reads behind the store: search (XQL), detection rules, IOC matcher, retention | not started (needs a query form that is not SQL) | `src/search/xql.js`, `src/detection/*`, `src/storage/retention.js`, `src/gateway/routes/{search,collectors,storage}.js`, `src/capacity/capacity.js` |
| ClickHouse adapter (same conformance suite) | not started | `src/events/clickhouse-store.js` (new), one line in `src/events/index.js`, `tests/event-store-clickhouse.test.js` |
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
   `tests/parsing-rules.test.js`, `tests/regex-safety.test.js`, `tests/packs.test.js`, `tests/heartbeat.test.js`, `tests/event-envelope.test.js`, `tests/event-store-memory.test.js` (they need `npm ci` first; `modules.test.js` uses `jose`). CI (`.github/workflows/ci.yml`) now runs `npm run lint` (ESLint `no-undef`) and `npm test` (every `tests/*.test.js`, on Node 20 and 22) on each push; run both locally before packaging. New tests must be named `*.test.js` to be picked up. Tests that need Postgres stay gated behind `ASIX_TEST_DB=1` and do not run in CI yet (`tests/packs-db.test.js`, `tests/heartbeat-db.test.js`, `tests/alert-dedupe-db.test.js`, `tests/event-store-postgres.test.js` and `tests/event-ingest-db.test.js` are the pattern: they skip themselves without that variable). Broker config changes: also run `vector test deploy/broker/vector.yaml deploy/broker/vector-tests.yaml` (needs the Vector binary; not in CI).
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
