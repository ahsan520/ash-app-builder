# Parser workers

Phase 2 of `docs/product-plan.md`, last item. The parse step of the HTTP ingest lane (parsing rules, then the data model
pass) can now run on a pool of worker threads instead of inside the API's request handler.

Code: `src/ingestion/parse-batch.js`, `rule-sets.js`, `parser-worker.js`, `parser-pool.js`, `parse-service.js` (all new),
`getRuleSources()` in `src/ingestion/rules-store.js`, the call in `src/ingest/http-ingest.js`. No schema change.

## What it is, and what it is not
- **It is** `worker_threads` inside each API replica. The API still receives, authenticates, rate-limits and stores; only the
  parse step moves.
- **It is not** a separate process or pod, and it is **off by default**. With `ASIX_PARSER_WORKERS` unset or `0` parsing runs
  inline exactly as before (same code, same 30 s compiled-rule cache). Separate parser processes fed by Kafka are Phase 3.
- The broker lane (`POST /v1/ingest/events`) never ran parsing rules, so it is not affected.

## Why
| Problem inline | With workers |
|---|---|
| A pattern or input that runs for ever freezes every request on that replica (regex-safety only reduces the chance) | The batch is cut off at the time limit, its worker is terminated and replaced; the API keeps serving |
| A crash or out-of-memory inside a parser takes the API down | It takes one worker down (each is capped at 192 MB of heap) |
| Parsing uses one core, shared with everything else | Parsing uses the workers' threads |
| A flood of ingest requests queues up without limit | A full queue answers `503 INGEST_BUSY` with `Retry-After: 2` |

## Settings (environment of the API)
| Variable | Default | Meaning |
|---|---|---|
| `ASIX_PARSER_WORKERS` | `0` | Worker threads per replica, 0 to 16. `0` = parse inline. Anything else that is not a whole number in that range logs a line and means `0`. |
| `ASIX_PARSER_TIMEOUT_MS` | `5000` | Time limit for one batch (up to 1,000 events). |
| `ASIX_PARSER_QUEUE` | `100` | Batches allowed to wait for a free worker. `0` means never wait. |

`k8s/30-asix-api.yaml` carries the first and the second, set to `"0"` and `"5000"`. To turn it on, set the first to `"2"`, raise
the pod memory limit (each worker adds roughly 40 to 60 MB; 768Mi is a sensible start for 2 workers) and run
`./sync-and-deploy.sh`. The API logs `[parser] 2 parser worker thread(s), ...` at start.

## How a batch flows
1. `http-ingest.js` builds the items as before, then calls `parse-service.parseForIngest(tenantId, sourceType, items)`.
2. Inline: compiled rules from `rules-store.getActiveSets` / `getModelSets`, then `parseItems()`.
3. Workers: `rules-store.getRuleSources(tenantId)` gives the tenant's rule **text** and a key (a hash of both texts, so tenants on
   the built-in rules share one key). The pool sends the batch to a free worker. Compiled rules cannot cross a thread boundary,
   so a worker compiles the text itself (`rule-sets.buildSets`: same order and same fall-back as `rules-store`) and keeps the
   last 32 rule sets. The text is sent with a batch only the first time a worker needs it; a worker that does not have it asks
   (`need_rules`) and gets it. Saving rules changes the key, so the next batch carries the new text.
4. Both paths end in the same function, `parseItems()`, so a batch gives the same events whichever path ran it
   (`tests/parse-ingest-db.test.js` holds it to that).

## When a worker fails
| Event | What happens to the events | Answer to the sender |
|---|---|---|
| Batch exceeds the time limit (`PARSE_TIMEOUT`) | Stored **unparsed**, each with `parsed._parse_error = "PARSE_TIMEOUT"`; the worker is replaced | `202` |
| Worker crashes or runs out of memory (`PARSE_WORKER_CRASH`) | Same, with that code | `202` |
| The batch throws inside the worker (`PARSE_FAILED`) | Same, with that code; the worker keeps running | `202` |
| The same tenant and rule text fails 3 batches in a row | For 60 s its events are stored unparsed at once, without trying (`PARSE_QUARANTINED`); the API logs it. A success resets the count | `202` |
| Every worker busy and the queue full (`PARSER_BUSY`) | **Not accepted, nothing stored** | `503 INGEST_BUSY`, `Retry-After: 2` (the broker's disk buffer and the syslog collector's spool retry) |

Search `parsed._parse_error` to find events that were stored unparsed (Log search: `filter _parse_error != null`), or open **Settings, Parser pool** (below). They are not re-parsed later: there is no re-parse job.

## Parser pool page and API (read-only)
- Portal: **Settings, Parser pool** (under Data collection, next to Parsing rules). It shows how parsing runs (inline, or workers with the
  time limit and queue size), the pool's counters, and how many events were stored unparsed in the last 24 hours, 3 days or 7 days, by reason.
- API: `GET /v1/parser/status?hours=24` (1 to 168; default 24). Needs `capacity:read`, so no role change. Answer: `settings` (`mode` `inline` or
  `workers`, `workers`, `timeout_ms`, `queue`), `pool` (the counters from `pool.stats()`, or `null` when inline), `unparsed` (`hours`, `total`,
  `by_reason`, `truncated`) and `unparsed_error` (set, with `unparsed.total` `null`, when the count could not be read; the rest still answers).
- **The counters are per API pod.** They live in the memory of the replica that answered and restart with it, so with several replicas the
  numbers change from request to request. The unparsed count comes from the event store (one XQL query, `filter _parse_error != null | comp count()
  by _parse_error`), so it covers every replica and works on PostgreSQL and ClickHouse alike.
- Code: `src/ingestion/parser-status.js` (new, shaping and the count), `src/gateway/routes/parser-status.js` (new), mounted in `src/gateway/index.js`,
  portal `pgParserPool()` in `src/portal/index.html` (one `SETTINGS` line and one `MENU_MODULE` entry, module `ingestion`).

## Not built
- Pool counters that survive a restart or add up across replicas (the page shows the answering pod's counters only; the API still logs
  timeouts, crashes and quarantines).
- Re-parsing events that were stored unparsed.
- Parser processes outside the API, and Kafka between the broker and the parser (Phase 3).
- A per-tenant worker share (one tenant's busy batches can fill the queue for others; the quarantine only covers batches that time out or crash).
- Running with workers has not been tried on the k3s box yet; the CI job `postgres` runs the ingest test on 2 workers.

## Tests
- `tests/parse-batch.test.js`: `parseItems` against the old inline loop written out, `buildSets` order and fall-back.
- `tests/parser-pool.test.js`: real workers equal inline results (many batches at once, own rules, rule sets alternating, a worker
  that forgot its rules); a fake worker (`tests/fixtures/fake-parser-worker.js`) that hangs, crashes or runs out of memory:
  time limit, replacement, queue limit including `0`, quarantine and its reset, `close()`. No database.
- `tests/parser-status.test.js`: the shaping, the unparsed count on the in-memory store (window, tenant isolation, unknown reasons kept, a failing
  store does not break the answer or leak its message) and the real route with sign-in stubbed (permission `capacity:read`, window bounds, a live pool).
- `tests/parser-status-db.test.js` (gated by `ASIX_TEST_DB=1`): the same count and route on a real `events` table, with a second tenant's events present.
- `tests/parse-ingest-db.test.js` (gated by `ASIX_TEST_DB=1`): the real HTTP lane on PostgreSQL. Built-in and tenant rules, a saved
  change taking effect at once, drops, timeout and crash stored unparsed and marked, the 503 and its collector counts. CI runs it
  inline and again with `ASIX_PARSER_WORKERS=2`.
