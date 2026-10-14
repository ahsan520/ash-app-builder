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

Every method needs a tenant id and only ever sees that tenant's events. Errors: `EventStoreError` with `code`
`INVALID_TENANT`, `INVALID_BATCH`, `BATCH_TOO_LARGE`, `INVALID_QUERY` or `INVALID_CURSOR`.

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

### Memory adapter
For tests and local experiments only (`ASIX_EVENT_STORE=memory`; refused when `NODE_ENV=production`). It lets
the contract run in CI with no database and is the shortest example of an adapter.

## Adding an adapter (for example ClickHouse, Phase 2 next steps)
1. Create `src/events/<name>-store.js`: `class X extends EventStore`, implement the underscore hooks listed at
   the bottom of `event-store.js`. Arguments arrive validated and normalised, so the adapter only talks to its engine.
2. Add one line to `FACTORIES` in `src/events/index.js`.
3. Add `tests/event-store-<name>.test.js` that calls `runConformance('<name>', setup)`. The adapter is done when
   that suite passes unchanged. Gate it behind an environment variable if it needs a server, like the Postgres one.

## What changed in ingest
- `POST /v1/ingest/http` (key lane) and `POST /v1/ingest/events` (broker lane) write through the store.
- The broker lane inserted one row per event in a loop; it is now one statement per batch.
- Events with a missing or empty `raw`, a bad `event_time` or a non-UUID tenant used to fail inside PostgreSQL as a
  500. They are now a `400` with code `INGEST_INVALID_EVENT` and a message naming the event and field.
- NUL characters no longer fail a batch. A `parsed` object over 1 MiB is refused (400).
- Everything else is unchanged: same routes, auth, rate limits, parsing rules, data model pass and audit rows.

## Not built yet (next in Phase 2)
- Reads still use SQL directly: XQL search (`src/search/xql.js`), detection rules (`rule-query.js`, `rule-runner.js`),
  the IOC matcher, the retention job (partition drops), and the counts in the collectors, storage, capacity and
  search routes. Moving them behind the store needs a query form that is not SQL (XQL compiles to SQL today).
- A ClickHouse adapter, and parsers as separate workers.
- The syslog listener and the in-cluster collector reach the store through the HTTP lane, so they are covered.
