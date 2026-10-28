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
| `scan(tenantId, { since, until, source_type, collector_id, order, limit, after })` | `{ events, next, cursor }`. Ordered by `(received_at, id)`, so events with the same time still page exactly once. `since` is inclusive, `until` exclusive. `limit` 1 to 1,000 (default 100). `next` is `null` on the last page; pass it back as `after`. `cursor` is a checkpoint just after the last event returned (`null` for an empty page): keep it and pass it back as `after` to resume exactly there, however many events arrive meanwhile (the IOC matcher does this). Cursors are opaque and only valid with the adapter that made them. |
| `count(tenantId, filter?)` | Number of matching events (same filters as `scan`). |
| `sourceTypes(tenantId, { since? })` | Distinct source types, sorted, at most 100. |
| `deleteBefore(tenantId, cutoff)` | `{ deleted }`: events with `received_at` before the cutoff. |
| `search(tenantId, plan, opts?)` | `{ rows, truncated, mode, columns }`. Runs an XQL query plan (`xql.parse(text, { from, to, limit })`, see "XQL search" below) on this adapter, for this tenant only. Works on every adapter. |
| `groupCounts(tenantId, { by, since?, until? })` | `[{ key, events, first_seen, last_seen }]`. Counts per `collector_id`, `source_type` or UTC `day` (key `YYYY-MM-DD`) of `received_at`, with the earliest and latest time of each group. `since` inclusive, `until` exclusive. Events with no collector are not a `collector_id` group. At most 1,000 groups; most events first (ties by key), days oldest first. Works on every adapter. |
| `timeRange(tenantId)` | `{ oldest, newest }`: earliest and latest `received_at` as ISO times, or nulls when the tenant has no events. |
| `listEvents(tenantId, { source_type?, collector_id?, from?, to?, q?, limit?, offset? })` | Envelopes, newest first by event time (received time when there is none), ties by id descending. Filters are ANDed: `source_type` and `collector_id` exact, `from` / `to` inclusive on the event time, `q` a case-insensitive substring of `raw` taken literally (`%` and `_` are ordinary characters). `limit` 1 to 500 (default 50), `offset` 0 to 100,000. |
| `dataSources(tenantId, { recentSince? })` | `[{ source_type, collector_id, events_total, events_recent, last_received }]`: one row per source type and collector over ALL the tenant's events; `events_recent` counts those with an event time (else received time) after `recentSince` (default 24 hours ago). Most recently received first, ties by source type then collector (none last); at most 1,000 rows. |
| `ingestionStats(tenantId, { by?, now?, groups? })` | The Command Center numbers: `{ totals, hourly, groups }`. `totals` `{ events, bytes, events_1h, source_types, collectors, last_received }` cover the 24 hours before `now` by event time (received time when none; no upper bound; strictly after the start), `bytes` is the UTF-8 size of `raw`, `events_1h` those also received in the last hour. `hourly` is 24 `{ hour, n }`, whole UTC hours ending with the current one, zero-filled, oldest first. `groups` is the window grouped by `by` (`source_type`, or `collector_id` with `(none)` for no collector), most events first, ties by key, at most `groups` (default 12, max 100). |
| `fieldStats(tenantId, { sample?, xdmSample? })` | `{ fields, xdm }`, each `[{ name, events }]`. `fields`: top-level keys of `parsed` over the newest `sample` events (default 2,000, max 10,000). `xdm`: leaf paths under `parsed.xdm` (as `xdm.a.b`; arrays are leaves, empty objects have none) over the newest `xdmSample` events (default 500, max 5,000) whose `parsed.xdm` is an object. Most events first, ties by name, at most 200 and 500 names. Newest means `(received_at, id)` descending. |
| `expiredCounts(tenantId, policy, { now? })` | `[{ source_type, events, oldest }]`: what a purge would delete right now, read-only. `policy` is `{ default_days, overrides: [{ source_type, retention_days }] }` (see "The retention job behind the store" below). Source types with nothing expired are left out; most events first, ties by source type. `oldest` is an ISO `received_at`. |
| `deleteExpired(tenantId, policy, { now?, deadline?, batch? })` | `{ deleted, by_source, truncated }`: permanently deletes this tenant's events that are past their retention. `deadline` (epoch milliseconds) stops it before the next batch or statement; `truncated` is then true and running it again carries on. `batch` (1 to 100,000, default 10,000) is the row count per `DELETE` on engines that delete in batches. The PostgreSQL adapter also reports `partitions_scanned`. |
| `storageStats()` | `{ partitioned, events_rows, events_bytes, default_partition_rows, partitions: [{ name, from, to, rows, bytes }] }`: the on-disk layout of all tenants' events for the storage page. `partitions` are whole UTC days, newest first (`from` the day, `to` the next day, exclusive). Row counts are estimates where the engine only has estimates. |
| `dropPartitionsBefore(day)` | `{ dropped, failed }`: drops every whole daily partition whose day is before `day` (`YYYY-MM-DD`, UTC) for **all tenants at once**; the caller only asks once no tenant can still need those days. Oldest first. A partition that cannot be dropped lands in `failed: [{ name, error }]` and does not stop the others. Never touches newer days or the PostgreSQL catch-all partition. |
| `matchGroups(tenantId, spec, opts?)` | `[{ key, n, first_at, last_at, sample_ids, sample_raw }]`. What a detection rule asks: which groups of events inside a time frame match a filter, and how many in each (see "Detection rules" below). Works on every adapter. |

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
- `deleteExpired` deletes in batches per daily partition (`ctid` is only unique inside one table), visiting only the
  partitions that can hold an expired row (and `events_default`). Dropping whole partitions is PostgreSQL housekeeping and
  stays in `src/storage/retention.js`. The partition layout is read by `src/events/pg-partitions.js`, shared by both.

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
- **Wildcard dataset names (2026-10-28).** `dataset = *`, `dataset = endpoint*`, `dataset = *event*`, `dataset in (syslog, win*)`. A `*` in a dataset name stands for any run of characters, including none; `*` alone is every source type (no condition). A name without `*` stays an exact match, case-sensitive. Quote a name that has a dash or other punctuation (`dataset = "endpoint-alert"`; `dataset = endpoint-*` works unquoted too, but `endpoint-alert` unquoted does not). A `*` anywhere else (in a filter value or a field name) is still a syntax error. The plan is unchanged (`names` simply holds the text with its `*`); the three engines ask the same helpers in `xql-plan.js` (`hasWildcard`, `globToLike`, `datasetMatches`): PostgreSQL and ClickHouse bind one `LIKE` pattern per wildcard name (the name's own `%`, `_` and `\` are escaped so they stay literal) and keep exact names in `IN (...)`, joined with OR; the in-memory engine uses an anchored regular expression. Checked in `tests/xql-dataset-wildcard.test.js` (parser, both SQL texts, in-memory engine) and `tests/xql-dataset-wildcard-db.test.js` (real PostgreSQL); the ClickHouse SQL is checked as text only, not run against a ClickHouse server.
- Engines: `src/search/xql-postgres.js` (SQL, byte for byte
  what the old compiler wrote, except that a field called `constructor` or `toString` is now an ordinary field; the old
  `xql.compile()` / `compileCondition()` wrappers are gone), `src/search/xql-clickhouse.js` (reads `parsed` with the JSON functions; output columns are
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
  `tests/xql-golden.test.js` pins the SQL and the error messages of the old compiler (it calls `parse` + `toSql` and `parseCondition` + `conditionToSql`
  directly; `conditionToSql` has no other caller and exists as that test's oracle). `tests/search-route.test.js` goes through
  the real route (memory in CI, Postgres when gated).
- Adding an adapter now also means implementing `_search` and running `runSearchConformance` unchanged (and `_matchGroups` with `runMatchConformance`).

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

- **Table.** `store.init()` creates it when the API starts (see "Created on deploy" below); `store.ensureSchema()` is the call underneath (idempotent); the DDL is `schemaSql()` in the adapter file:
  `ReplacingMergeTree`, `PARTITION BY toYYYYMMDD(received_at)`, `ORDER BY (tenant_id, received_at, id)`, times as
  `DateTime64(3, 'UTC')` (the envelope's millisecond precision), `collector_id` and `event_time` nullable,
  `parsed` stored as JSON text.
- **Idempotency does not depend on merges.** ReplacingMergeTree only removes duplicates when parts merge, which can be
  much later. So `insertBatch` first looks up which `(id, received_at)` pairs already exist and inserts only the new
  ones (`inserted` / `skipped` are exact), repeats inside one batch count once, and every read that could see two copies
  uses `FINAL`. Two identical inserts racing at the same instant can both pass the lookup; `FINAL` still returns one.
- **Tenant isolation** is the explicit `tenant_id = {t:UUID}` condition on every statement (ClickHouse has no
  row-level security here). Tenant and event ids and timestamps are validated before they reach the SQL; free-text filters
  and cursor values travel as ClickHouse query parameters, never spliced into the statement.
- **Deletes.** `deleteBefore` counts, then runs a lightweight `DELETE` that finishes before it returns. `deleteExpired`
  does the same once per source type that has expired events (scalar query parameters only), so a per-source policy works;
  see "The retention job behind the store". Whole old days are dropped with `dropPartitionsBefore` (below), which reads and rewrites
  no rows.
- **Known limits.** One `INSERT` that spans several days writes several parts and is not atomic across them (validation
  happens first, so a failure after that point means a backend outage; re-sending the batch is safe because inserts are
  idempotent). Detection rules run here too (`matchGroups`). One adapter per process.
- **Tests.** `tests/event-store-clickhouse.test.js` runs the conformance suite plus ClickHouse-specific cases (millisecond
  paging, re-sent events with no merge, hostile filter strings, unicode, error codes) against a real server, in a throwaway
  `events_test_<random>` table it drops itself. Run it with
  `ASIX_TEST_DB=1 ASIX_CLICKHOUSE_URL=http://default:pass@127.0.0.1:8123/asix node tests/event-store-clickhouse.test.js` (and `event-search-clickhouse`, `event-match-clickhouse`).
  CI runs it in the `clickhouse` job (a ClickHouse 24.8 service container); the normal `test` job skips it. It has been
  run against ClickHouse 24.8.14.39.

**Paging order on ClickHouse.** Events with the same `received_at` are ordered, and the scan cursor compares, by the id as text
(`toString(id)`), not as ClickHouse's UUID type: ClickHouse sorts UUIDs differently from the hex-string order the contract and the
other adapters use, and an earlier version of the adapter failed the "pages through everything" test about three runs in four
because of it. Trade-off: the id tie-break no longer follows the table's sort key (the `received_at` prefix still does).

## Detection rules and the IOC matcher behind the store (done)
**Rules.** `rule-query.js` turns a rule definition into a *match spec* (`src/search/match-spec.js`), and
`getEventStore().matchGroups(tenantId, spec)` runs it. The spec holds no SQL:

| Field | Meaning |
|---|---|
| `after` | ISO time. Only events with event time (received time when there is none) **strictly after** it count. |
| `filter` | A plan expression (`src/search/xql-plan.js`) or `null`. The rule's regex, source type, field filters and BIOC condition are all AND-ed into one. |
| `group` | `{ by: 'none' }` (one group, key `all`), `{ by: 'field', field }` (the text of a field; a missing value is the group `unknown`) or `{ by: 'capture', pattern }` (the first capture group of an unanchored, case-sensitive match on `raw`; no match or an empty capture is `unknown`). |
| `threshold`, `limit` | Keep groups with at least `threshold` events (default 1); at most `limit` groups (default and maximum 1,000). |

Rows come back biggest group first (ties by key) with the earliest and latest event time of the group, up to five sample
event ids (newest first) and the raw text of the newest event. `validateMatchSpec()` runs first on every adapter, so even a
hand-built spec cannot inject anything; a bad spec is `INVALID_QUERY`.

**`@path` fields.** In a plan, `@xdm.source.ipv4` or `@user-agent` is always a path into `parsed`, never a column, and may
contain hyphens or start with a digit. XQL text cannot produce it. Rules use it for every field that is not `raw`,
`source_type` or `collector_id`, so a rule field called `dataset` or `_time` stays the parsed field the author meant.

**What the engines do.** Postgres: one grouped query (`xql-postgres.js` `matchToSql`, every value a bound parameter).
ClickHouse: one grouped query (`xql-clickhouse.js` `matchToClickHouse`); the five newest ids come from sorting one small
(time, id) pair per matching event of the group, which is fine for rule time frames and is the thing to revisit if a single
group can reach many millions. Memory: `xql-eval.js` `runMatch`.

**Checked against the old code.** The old SQL builder and the new path were run side by side on real PostgreSQL over 1,914
rule definitions (regex, source type, every filter operator, `xql` with `or` and `not`, every group-by, thresholds and
windows) on 400 events: identical groups, counts, first/last times, sample ids and raw lines. `tests/event-match-conformance.js`
holds every adapter to the same answers (in-memory in CI; Postgres and ClickHouse when gated).

**Small, deliberate differences.**
- The time frame's start is computed by the API server's clock (it was the database's `localtimestamp`).
- A rule is checked as a whole when it is saved (`Rule is not valid: ...`), so a rule with too many or too long conditions
  is refused then instead of failing on every run.
- A `group_by` of `constructor` (or another name every JavaScript object has) used to pass the check and break the rule; it is refused now.
- Rows with equal counts are ordered by group key (they had no defined order).
- An `or` in a rule's `xql` is now AND-ed correctly with the rule's other conditions on every engine (each part is a paren node).

**IOC matcher.** It reads the indicators and its saved place from Postgres, reads the next events through `scan()` (pages of
1,000, up to 5,000 per cycle), then raises alerts and moves the place forward in one Postgres transaction. The place is a
store cursor over `(received_at, id)` kept in `ioc_scan_state`, and it only moves when the alerts are saved, so a crash
re-reads the same events and nothing is skipped. If the event store cannot be read the cycle fails for that tenant and the place does not move.
**Alert detail** (`routes/alerts.js`) loads the sample events with `getByIds()`.

`tests/detection-store-db.test.js` (`ASIX_TEST_DB=1`) runs the rule runner, the rule test endpoint, the alert detail route and the
IOC matcher end to end on real PostgreSQL, including more events than one page and an unreadable store.

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

## The events list, data sources and Command Center behind the store (done)
`GET /v1/search/events`, `GET /v1/data-sources` and `GET /v1/dashboard/ingestion` (in `routes/core.js`) read through
`listEvents`, `dataSources` and `ingestionStats`. They are store methods rather than plans because a plan cannot say what they
need: the console list returns both `received_at` and `event_time` and pages by offset, the Command Center sums the size of
`raw` and buckets by hour, and the data sources page groups by two columns over all time. Each has one conformance block
(`tests/event-store-conformance.js`, run on in-memory, PostgreSQL and ClickHouse 24.8), `tests/core-reads.test.js` runs the
routes on the in-memory store, and `tests/core-reads-db.test.js` holds them to the old SQL, written out in the test, on real
PostgreSQL. Deliberate differences from the old SQL:
- `q` on the events list is a plain substring. Before, `%` and `_` in it were ILIKE wildcards (`100%` matched anything
  containing `100`); now they match themselves, as in the Search page's `contains`.
- Ties on the event time are ordered by id (before: undefined), so paging by `offset` is stable.
- `from` / `to` are read as UTC times ("2026-10-01", "2026-10-01 10:00:00" and ISO all work); anything that is not a time, or
  a repeated parameter, is now a 400 `INVALID_QUERY` instead of a 500. `offset` above 100,000 is a 400. A fractional
  `limit` or `offset` is truncated.
- `bytes_24h` and the group byte counts are numbers (PostgreSQL returned them as strings). The data sources page reads at most
  1,000 (source type, collector) rows.
- Windows are measured on the application's clock, not the database's.

## The retention job behind the store (done)
`src/storage/retention.js` asks the store for the two things that touch events: the preview ("Check what would be
deleted") is `expiredCounts()`, and the row purge (manual **Purge now** and the scheduled run) is `deleteExpired()`. The
policy, the advisory lock, the run log, the time limit and the result shape of the API are unchanged.

**The policy.** `{ default_days, overrides: [{ source_type, retention_days }] }`, which is what `loadPolicy()` already returns.
An event is expired when `received_at` is older than `now` minus the days that apply to its source type: the override's days
when it has one, `null` meaning keep forever, else `default_days`. Days are whole numbers from 1 to 3,650. The base class
validates the policy before any adapter sees it (a bad one is `INVALID_QUERY`, nothing is deleted): at most 1,000 overrides,
source types of 1 to 255 characters, no duplicates.

**How each adapter does it**
- *PostgreSQL:* the preview is the query that used to be in `retention.js` (one pass, partition pruning on the shortest
  retention). The purge is the same batched `DELETE ... ctid = ANY(ARRAY(SELECT ctid ... LIMIT batch))` per partition and per rule.
- *ClickHouse:* first the source types that have anything older than the shortest retention (with the oldest event of each),
  then, for each one whose own cut-off is passed, a count and a lightweight `DELETE`. At most 1,000 source types are looked at in
  one call; `truncated` is true if there were more, and the next run continues.
- *Memory:* a filter over the rows.

**Dropping whole days (`dropPartitionsBefore`, `storageStats`).** Row deletes handle per-tenant, per-source rules; the cheap path
for old data is to drop a whole daily partition once the day is older than every tenant's longest retention. The rule lives in
`dropExpiredPartitions()` in `retention.js` and is the same for every engine: it drops only when every tenant has automatic purge
on and no keep-forever rule, takes the longest retention of any tenant or source, turns that into a UTC cut-off day, and asks the
store to drop the days before it. The engine does the dropping:
- *PostgreSQL:* `DROP TABLE events_pYYYYMMDD` for partitions whose range ends on or before the cut-off; `events_default` is never dropped.
- *ClickHouse:* `ALTER TABLE ... DROP PARTITION ID 'YYYYMMDD'` (the table is partitioned by `toYYYYMMDD(received_at)`, UTC days),
  oldest first. ClickHouse refuses to drop a partition above its server setting `max_partition_size_to_drop` (50 GB by default): that
  day is reported in `failed`, the run is logged `partial` or `failed`, and newer days are still dropped; raise the setting on the
  server if you keep such big days. Row counts for the storage page come from `system.parts`, which still counts rows that lightweight
  deletes have hidden but a merge has not yet removed, so they can run a little high after a purge.
- *Memory:* one pseudo-partition per UTC day.

A ClickHouse **table TTL is deliberately not used**: a TTL is one rule for the whole table, but retention here is per tenant and per
source, so a TTL could only be a global maximum, and the row `DELETE`s plus partition drops already cover that.

**Still PostgreSQL-only.** Creating the daily partitions ahead of time (`ensurePartitions`; ClickHouse creates partitions itself on
insert, so the scheduled run reports `partitioned: false` there) and the sizes of the control-plane tables on the storage page
(`database_bytes` and the "largest tables" list describe the PostgreSQL database that holds tenants, rules and alerts, whatever the
events engine). The events part of the storage page (`partitions`, `events_rows`, `events_bytes`) comes from the store on any engine.

**Checked by.** One conformance block (`tests/event-store-conformance.js`: exact cut-offs, per-source rules, keep forever, batches, a
passed deadline, tenant isolation, awkward source type names, bad input), run on in-memory, PostgreSQL 16 and ClickHouse 24.8.
`tests/retention-db.test.js` runs the whole job on the partitioned table: the preview must equal the old SQL (written out in the
test), a purge must delete exactly what the preview counted from daily partitions and from `events_default`, the scheduled run
must skip tenants with automatic purge off, and an expired partition is still dropped. `tests/retention-clickhouse.test.js` runs the
job with events in ClickHouse and the policy and run log in PostgreSQL, including the storage summary and the scheduled drop of an old
ClickHouse partition. The conformance suite has a second block for `storageStats` / `dropPartitionsBefore` (a test-setup hook,
`prepareDay`, lets PostgreSQL create the day's partition first), and `tests/clickhouse-partitions.test.js` checks the SQL and the
"ClickHouse refuses to drop it" path with a stubbed HTTP client in the plain `test` job.

**Deliberate differences from before**
- The cut-off is computed on the application's clock, not the database's (`localtimestamp`), as in the other store reads.
- `oldest` in the preview is an ISO time with `Z`; it was a database timestamp that serialised the same way on a UTC host.
- Preview ties on the count are ordered by source type (before: undefined).
- Partition drops: the cut-off day is computed on the application's clock (UTC), not the database's. One partition that cannot be
  dropped no longer aborts the whole run; it is reported in `failed` and the run is logged `partial` or `failed`.
- A policy is validated as a whole first: more than 1,000 overrides, a source type over 255 characters or a duplicate is refused.
  (The API already limited an update to 50 overrides and 100 characters.)

## Created on deploy (`store.init()`)
`src/server.js` calls `getEventStore().init()` once, before the API starts listening. PostgreSQL and the memory store do nothing
there (PostgreSQL's schema is applied by `k8s/12-schema-init.yaml`). The ClickHouse adapter runs `CREATE TABLE IF NOT EXISTS` and
retries while ClickHouse is still coming up (10 attempts, 3 seconds apart; `initRetry` in the constructor changes that). If it still
cannot, the process logs `[events] the event store could not be initialised: ...` and **exits**, so the platform restarts it and the
failure is visible instead of an API that accepts requests it cannot store.
- The database named in `ASIX_CLICKHOUSE_URL` must already exist (the official image makes it from `CLICKHOUSE_DB`); `init()` creates
  the table, not the database, and needs the CREATE TABLE privilege once.
- A table that was made by hand with a different partition key keeps working, but `init()` logs one warning that whole-day retention
  will not drop anything from it (row deletes still work, and a monthly partition is never mistaken for a day).
- Checked by: `tests/clickhouse-partitions.test.js` (stubbed HTTP: one CREATE, retries, giving up, the warning), the conformance suite
  (`init()` can be called repeatedly, on every engine), `tests/event-store-clickhouse.test.js` (a real server: created from nothing,
  second call harmless, data kept; a monthly table is warned about and left alone), and by starting the real `src/server.js` against an
  empty ClickHouse database (the table appeared with `toYYYYMMDD(received_at)`) and against an unreachable one (exit code 1, nothing listening).

## What is left
- A ClickHouse server in `k8s/`: done, optional (`k8s/11-clickhouse.yaml`, `docs/clickhouse-server.md`). The API creates the table; the server
  creates the database. Switching `ASIX_EVENT_STORE` does not copy existing events by itself: run `src/events/copy-events.js` first (`docs/clickhouse-server.md`). ClickHouse is covered by the nightly backup (`docs/clickhouse-backup.md`).
- Parsers as separate workers: done, see `docs/parser-workers.md`. Phase 2 has no open items.
- The syslog listener and the in-cluster collector reach the store through the HTTP lane, so they are covered.
