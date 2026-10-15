# Event envelope and event store

Phase 2 of `docs/product-plan.md`, step 1. Events now have one shape (the **envelope**) and are written
through one interface (the **event store**), so the storage engine can change from Postgres to ClickHouse
without touching ingest, search or detections.

Code: `src/events/` (`envelope.js`, `event-store.js`, `postgres-store.js`, `memory-store.js`, `index.js`).
Contract tests: `tests/event-store-conformance.js`. No schema change: the envelope is the `events` table.

## The envelope

| Field | Meaning |
|---|---|
| `v` | Envelope version, `1`. Not stored; a row without it is v1. |
| `id` | UUID. Omit it and the store assigns one. If you set it you must also set `received_at`: the pair `(id, received_at)` is the idempotency key. |
| `tenant_id` | UUID. Taken from the call, never trusted from the event (a mismatch is rejected). |
| `source_type` | Dataset, for example `syslog`. 1 to 100 characters, no control characters. |
| `collector_id` | Which collector or broker sent it, or `null`. Up to 255 characters. |
| `received_at` | When ASIX got it. Omit it and the store stamps "now". |
| `event_time` | When the source says it happened, or `null`. |
| `raw` | The original payload. Required, never empty, up to 65,536 characters. |
| `parsed` | Parsed fields, an object (up to 1 MiB as JSON). `parsed.xdm.*` is the data model mapping. |

`makeEnvelope()` validates and cleans, and never guesses. Times become ISO-8601 UTC (a time with no zone is
read as UTC). NUL characters are removed from `raw` and from every string in `parsed`; PostgreSQL refuses them
and one such event used to fail a whole batch. `undefined`, functions and the key `__proto__` are dropped.
Anything else that is wrong throws `EnvelopeError` (`code: 'INVALID_ENVELOPE'`, with the field name).

## The event store

```js
const { getEventStore } = require('../events');
const store = getEventStore();                       // ASIX_EVENT_STORE=postgres (default)
await store.insertBatch(tenantId, [{ source_type: 'syslog', raw: '...', parsed: {} }], { client });
```

| Method | Returns |
|---|---|
| `insertBatch(tenantId, events, opts?)` | `{ inserted, skipped, ids }`. All or nothing: one bad event rejects the batch (the error says which). Up to 5,000 events. `ids` are in input order. |
| `getByIds(tenantId, ids)` | Envelopes in the order asked; ids that do not exist are left out. Up to 1,000 ids. |
| `scan(tenantId, { since, until, source_type, collector_id, order, limit, after })` | `{ events, next }`. Ordered by `(received_at, id)`, so events with the same time still page exactly once. `since` is inclusive, `until` exclusive. `limit` 1 to 1,000 (default 100). `next` is `null` on the last page; pass it back as `after`. Cursors are opaque and only valid with the adapter that made them. |
| `count(tenantId, filter?)` | Number of matching events (same filters as `scan`). |
| `sourceTypes(tenantId, { since? })` | Distinct source types, sorted, at most 100. |
| `deleteBefore(tenantId, cutoff)` | `{ deleted }`: events with `received_at` before the cutoff. |
| `search(tenantId, plan, opts?)` | `{ rows, truncated, mode, columns }`. Runs an XQL query plan (`xql.parse(text, { from, to, limit })`, see "XQL search" below) on this adapter, for this tenant only. Works on every adapter. |
| `groupCounts(tenantId, { by, since?, until? })` | `[{ key, events, first_seen, last_seen }]`. Counts per `collector_id`, `source_type` or UTC `day` (key `YYYY-MM-DD`) of `received_at`, with the earliest and latest time of each group. `since` inclusive, `until` exclusive. Events with no collector are not a `collector_id` group. At most 1,000 groups; most events first (ties by key), days oldest first. Works on every adapter. |
| `timeRange(tenantId)` | `{ oldest, newest }`: earliest and latest `received_at` as ISO times, or nulls when the tenant has no events. |
| `fieldStats(tenantId, { sample?, xdmSample? })` | `{ fields, xdm }`, each `[{ name, events }]`. `fields`: top-level keys of `parsed` over the newest `sample` events (default 2,000, max 10,000). `xdm`: leaf paths under `parsed.xdm` (as `xdm.a.b`; arrays are leaves, empty objects have none) over the newest `xdmSample` events (default 500, max 5,000) whose `parsed.xdm` is an object. Most events first, ties by name, at most 200 and 500 names. Newest means `(received_at, id)` descending. |
| `querySQL(tenantId, sql, params, opts?)` | `{ rows, fields }`. Runs XQL-compiled PostgreSQL SQL. **Postgres adapter only.** It adds no tenant filter of its own: the SQL from `xql.compile` must carry it. |
| `queryAggregated(tenantId, spec)` | Group-by counts for detection rules and the IOC matcher. **Postgres adapter only** (`spec.group_expr` is a trusted PostgreSQL fragment from the rule definition, never user input). |

Every method needs a tenant id and only ever sees that tenant's events. Errors: `EventStoreError` with `code`
`INVALID_TENANT`, `INVALID_BATCH`, `BATCH_TOO_LARGE`, `INVALID_QUERY`, `INVALID_CURSOR` or `NOT_IMPLEMENTED` (adapter lacks the method); the ClickHouse adapter also raises `BACKEND_ERROR` / `BACKEND_UNAVAILABLE`.

**Idempotency.** Inserting an event whose `(id, received_at)` already exists is a no-op, counted in `skipped`.
That is what a queue that delivers at least once (Kafka, Phase 3) needs. Events without an id are always new.

### Postgres adapter
- Reads and writes the existing `events` table, plain or daily-partitioned (both are tested).
- Every call runs in `db.withTenant()`, so row-level security applies on top of the explicit tenant filter.
- `opts.client` (insert only): use the caller's open transaction. The caller must already have set the tenant
  (`db.withTenant` does). Both ingest lanes use this, so events, collector bookkeeping and the audit row still
  commit together.
- Inserts are one `INSERT ... SELECT unnest(...) ON CONFLICT DO NOTHING` per batch.
- `timestamp` columns are treated as UTC, as everywhere else in ASIX. Keep PostgreSQL's timezone on UTC.

### XQL search (`store.search`)
XQL text is parsed once into a **query plan**, and the store runs the plan. The plan holds no SQL, so an engine that is
not PostgreSQL can run the same query.

```js
const xql = require('../search/xql');
const plan = xql.parse('dataset = syslog | filter host = "web01" | comp count() as hits by app_name',
                       { from: '2026-10-01T00:00:00.000Z', to: null, limit: 1000 });
const { rows, truncated, mode, columns } = await getEventStore().search(tenantId, plan);
```
- `src/search/xql-plan.js` defines the plan (stages `dataset`, `filter`, `fields`, `comp`, `sort`, `limit`; a small expression
  tree) and `validatePlan()`, which `search()` runs first: field names must be plain identifiers, sizes and depth are bounded,
  the limit is 1 to 5,000. A bad plan is `INVALID_QUERY`. Values never become part of query text: PostgreSQL and ClickHouse bind
  them as parameters.
- Engines: `src/search/xql-postgres.js` (SQL, also still behind `xql.compile()` for BIOC rules and old callers, byte for byte
  what the old compiler wrote, except that a field called `constructor` or `toString` is now an ordinary field), `src/search/xql-clickhouse.js` (reads `parsed` with the JSON functions; output columns are
  renamed c0, c1... so a user alias such as `parsed` cannot shadow a real column), `src/search/xql-eval.js` (in memory).
- Rows are keyed by output column. `raw` rows are `{ _id, _time (Date), source_type, collector_id, _raw, parsed }`; `fields` and
  `comp` rows hold text (and `null`) for fields and numbers for aggregates (a number or a numeric string: compare numerically).
- **What a query means** (the same on every engine, written at the top of `xql-plan.js` and checked by the suite): fields are
  columns or paths into `parsed`; text equality is exact, `contains` and `~=` ignore case; `=` is null when the field is missing
  (so `not host = "a"` also drops events with no host) while `!=`, `contains`, `in`, `~=` and numeric comparisons never are;
  numeric comparison only matches values that look like numbers; `count(f)` counts events where `f` exists; missing values form
  their own group and sort last; time bounds are inclusive and use the event time, or the received time when there is none;
  ties have no defined order.
- **Differences between engines** (not hidden, not fixable without losing something): the regex dialect (`~=`: PostgreSQL ARE on
  Postgres, RE2 on ClickHouse, JavaScript in memory; write patterns in the common subset, a pattern one engine rejects is a
  `BACKEND_ERROR`); the text of a whole object or array value (PostgreSQL prints canonical jsonb, ClickHouse the stored compact
  JSON); numbers are exact decimals on PostgreSQL and Float64 on ClickHouse and in memory; text sorts by the database collation
  on PostgreSQL and by bytes elsewhere; on ClickHouse a path with more than 3 numeric parts is `NOT_IMPLEMENTED`.
- **Tests.** `tests/event-search-conformance.js` is the contract (`event-search-memory` runs in CI; `-postgres` and `-clickhouse`
  are gated by `ASIX_TEST_DB=1` like the store suite). Its large part compares each engine with
  `tests/fixtures/xql-search-expected.json`, made on real PostgreSQL by `tests/fixtures/gen-xql-search-expected.js`, which
  refuses to write unless the in-memory engine agrees. Regenerate it only when the language's meaning is changed on purpose.
  `tests/xql-golden.test.js` pins the SQL and the error messages of the old compiler. `tests/search-route.test.js` goes through
  the real route (memory in CI, Postgres when gated).
- Adding an adapter now also means implementing `_search` and running `runSearchConformance` unchanged.

### Memory adapter
For tests and local experiments only (`ASIX_EVENT_STORE=memory`; refused when `NODE_ENV=production`). It lets
the contract run in CI with no database and is the shortest example of an adapter.

### ClickHouse adapter
`ASIX_EVENT_STORE=clickhouse` selects `src/events/clickhouse-store.js`. It uses ClickHouse's HTTP interface through
Node's built-in `fetch`, so there is **no extra npm dependency**.

| Setting | Meaning |
|---|---|
| `ASIX_CLICKHOUSE_URL` | `http://user:password@host:8123/<database>` (database defaults to `asix`). Required in production. |
| `ASIX_CLICKHOUSE_TIMEOUT_MS` | Per-request timeout, default 30000. Reads also run under `max_execution_time=20` s. |

- **Table.** `store.ensureSchema()` creates it (idempotent); the DDL is `schemaSql()` in the adapter file:
  `ReplacingMergeTree`, `PARTITION BY toYYYYMMDD(received_at)`, `ORDER BY (tenant_id, received_at, id)`, times as
  `DateTime64(3, 'UTC')` (the envelope's millisecond precision), `collector_id` and `event_time` nullable,
  `parsed` stored as JSON text. Nothing creates the table on deploy yet (there is no ClickHouse in `k8s/` until
  Phase 3): run `ensureSchema()` when you bring a server up.
- **Idempotency does not depend on merges.** ReplacingMergeTree only removes duplicates when parts merge, which can be
  much later. So `insertBatch` first looks up which `(id, received_at)` pairs already exist and inserts only the new
  ones (`inserted` / `skipped` are exact), repeats inside one batch count once, and every read that could see two copies
  uses `FINAL`. Two identical inserts racing at the same instant can both pass the lookup; `FINAL` still returns one.
- **Tenant isolation** is the explicit `tenant_id = {t:UUID}` condition on every statement (ClickHouse has no
  row-level security here). Tenant and event ids and timestamps are validated before they reach the SQL; free-text filters
  and cursor values travel as ClickHouse query parameters, never spliced into the statement.
- **Deletes.** `deleteBefore` counts, then runs a lightweight `DELETE` that finishes before it returns. Dropping whole day
  partitions is still the cheaper way for the retention job to expire large tables.
- **Known limits.** One `INSERT` that spans several days writes several parts and is not atomic across them (validation
  happens first, so a failure after that point means a backend outage; re-sending the batch is safe because inserts are
  idempotent). `querySQL` and `queryAggregated` are **not implemented**: XQL compiles to PostgreSQL SQL and rules pass a
  PostgreSQL group expression, so they throw `NOT_IMPLEMENTED` rather than return wrong data. Moving reads behind the store
  with a non-SQL query form is what unblocks them. One adapter per process.
- **Tests.** `tests/event-store-clickhouse.test.js` runs the conformance suite plus ClickHouse-specific cases (millisecond
  paging, re-sent events with no merge, hostile filter strings, unicode, error codes) against a real server, in a throwaway
  `events_test_<random>` table it drops itself. Run it with
  `ASIX_TEST_DB=1 ASIX_CLICKHOUSE_URL=http://default:pass@127.0.0.1:8123/asix node tests/event-store-clickhouse.test.js`.
  CI runs it in the `clickhouse` job (a ClickHouse 24.8 service container); the normal `test` job skips it. It has been
  run against ClickHouse 24.8.14.39.

**Paging order on ClickHouse.** Events with the same `received_at` are ordered, and the scan cursor compares, by the id as text
(`toString(id)`), not as ClickHouse's UUID type: ClickHouse sorts UUIDs differently from the hex-string order the contract and the
other adapters use, and an earlier version of the adapter failed the "pages through everything" test about three runs in four
because of it. Trade-off: the id tie-break no longer follows the table's sort key (the `received_at` prefix still does).

## Adding an adapter
1. Create `src/events/<name>-store.js`: `class X extends EventStore`, implement the underscore hooks listed at
   the bottom of `event-store.js`. Arguments arrive validated and normalised, so the adapter only talks to its engine.
2. Add one line to `FACTORIES` in `src/events/index.js`.
3. Add `tests/event-store-<name>.test.js` that calls `runConformance('<name>', setup)`, and `tests/event-search-<name>.test.js`
   that calls `runSearchConformance('<name>', setup)` (see "XQL search"). The adapter is done when both suites pass unchanged. Gate it behind an environment variable if it needs a server, like the Postgres one.

## What changed in ingest
- `POST /v1/ingest/http` (key lane) and `POST /v1/ingest/events` (broker lane) write through the store.
- The broker lane inserted one row per event in a loop; it is now one statement per batch.
- Events with a missing or empty `raw`, a bad `event_time` or a non-UUID tenant used to fail inside PostgreSQL as a
  500. They are now a `400` with code `INGEST_INVALID_EVENT` and a message naming the event and field.
- NUL characters no longer fail a batch. A `parsed` object over 1 MiB is refused (400).
- Everything else is unchanged: same routes, auth, rate limits, parsing rules, data model pass and audit rows.

## Page counts behind the store (done)
The collectors list, `/v1/search/fields`, the storage page's range and 14-day chart, the retention page's source list and
capacity's ingest rate now read through `groupCounts`, `timeRange`, `fieldStats`, `sourceTypes` and `count`. They are
store methods, not plans, because they are about *arrival* time (`received_at`), and a plan's time bounds use the event
time. `tests/event-store-conformance.js` holds every adapter to the same answers (run on in-memory, PostgreSQL and
ClickHouse 24.8), and `tests/read-counts-db.test.js` checks the routes against the SQL they replaced on real PostgreSQL.
Small, deliberate differences from the old SQL: the sample for field names breaks ties by id (the old query left ties
undefined); names tied on count sort by byte order; `xdm` paths are capped at 500 names; an `xdm` value that is not an
object (a string, say) no longer contributes odd paths; a collector list over 1,000 senders is cut at 1,000.
Engine-specific housekeeping stays where it is (table sizes, partitions, `pg_database_size` on the storage and capacity pages).

## What is left (next in Phase 2)
- Reads that still use SQL directly: detection rules (`rule-query.js`, `rule-runner.js`: a rule holds a trusted PostgreSQL
  fragment, `group_expr`), the IOC matcher, the retention job (`preview`, partition drops, the all-tenant row count), the
  dashboard and event-list reads in `routes/core.js` (events list, per-source totals, 24 hour totals, top lists) and the
  sample events in `routes/alerts.js` (`getByIds` already does this). Express each as a plan where the plan can say it
  (most are `comp count() by ...`), and add a store method only for engine-specific housekeeping. Then remove `querySQL`, `queryAggregated` and the
  `xql.compile` / `compileCondition` wrappers. Order and starting points: `docs/parallel-work.md`, "What to build next".
- Parsers as separate workers.
- The syslog listener and the in-cluster collector reach the store through the HTTP lane, so they are covered.
