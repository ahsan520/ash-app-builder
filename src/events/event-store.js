'use strict';
// The event-store contract. Ingest writes through it and (in the next step) search, detections,
// IOC matching and retention read through it, so the storage engine can change (Postgres ->
// ClickHouse) without touching them.
//
// An adapter extends EventStore and implements only the underscore methods. The public methods
// here validate and normalise every argument first, so all adapters see the same clean input and
// behave the same way. tests/event-store-conformance.js is the executable form of this contract:
// an adapter is correct when it passes that suite.
//
// Public API (all async; tenantId is always the first argument and is always enforced):
//   insertBatch(tenantId, events, opts?)  -> { inserted, skipped, ids }
//   getByIds(tenantId, ids)               -> envelope[]            (requested order, missing ones omitted)
//   scan(tenantId, query?)                -> { events, next, cursor }  (cursor paging, stable order; `cursor` = checkpoint after the last event)
//   count(tenantId, filter?)              -> number
//   sourceTypes(tenantId, { since? })     -> string[]              (distinct, sorted, max 100)
//   deleteBefore(tenantId, cutoff)        -> { deleted }           (received_at < cutoff)
//   search(tenantId, plan, opts?)         -> { rows, truncated, mode, columns }  (an XQL query plan, see src/search/xql-plan.js)
//   matchGroups(tenantId, spec, opts?)    -> [{ key, n, first_at, last_at, sample_ids, sample_raw }]  (detection rules, see src/search/match-spec.js)
//   groupCounts(tenantId, { by, since?, until? }) -> [{ key, events, first_seen, last_seen }]   (counts per collector, source or day)
//   timeRange(tenantId)                   -> { oldest, newest }    (ISO times of the oldest / newest event, or null)
//   fieldStats(tenantId, { sample?, xdmSample? }) -> { fields, xdm }   (field names seen in the newest events, with counts)
//
// Order is always (received_at, id). `since` is inclusive, `until` exclusive, both on received_at.
// Cursors (`next` / `after`) are opaque and only valid with the adapter that produced them.

const crypto = require('crypto');
const { UUID_RE, EnvelopeError, makeEnvelope, normalizeTime } = require('./envelope');
const { validatePlan, PlanError } = require('../search/xql-plan');
const { validateMatchSpec } = require('../search/match-spec');

const MAX_BATCH = 5000;
const MAX_SCAN = 1000;
const DEFAULT_SCAN = 100;
const MAX_IDS = 1000;
const MAX_SOURCE_TYPES = 100;
const GROUP_BY = ['collector_id', 'source_type', 'day'];
const MAX_GROUPS = 1000;
const FIELD_SAMPLE = { def: 2000, max: 10000 };
const XDM_SAMPLE = { def: 500, max: 5000 };
const MAX_FIELD_NAMES = 200;
const MAX_XDM_NAMES = 500;
const MAX_XDM_DEPTH = 20;

class EventStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'EventStoreError';
    this.code = code;
  }
}

// --- cursors: base64url(JSON [received_at_text, id]) ------------------------------------------
const CURSOR_TS_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z?$/;
const encodeCursor = (ts, id) => Buffer.from(JSON.stringify([ts, id]), 'utf8').toString('base64url');
function decodeCursor(cursor) {
  try {
    const [ts, id] = JSON.parse(Buffer.from(String(cursor), 'base64url').toString('utf8'));
    if (typeof ts === 'string' && CURSOR_TS_RE.test(ts) && typeof id === 'string' && UUID_RE.test(id)) return { ts, id: id.toLowerCase() };
  } catch (_) { /* fall through */ }
  throw new EventStoreError('INVALID_CURSOR', 'cursor is not valid');
}

const assertTenant = (tenantId) => {
  if (typeof tenantId !== 'string' || !UUID_RE.test(tenantId)) throw new EventStoreError('INVALID_TENANT', 'tenantId must be a UUID');
  return tenantId.toLowerCase();
};

function optString(v, field) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string' || v.length > 255) throw new EventStoreError('INVALID_QUERY', `${field} must be a string of at most 255 characters`);
  return v;
}

function timeArg(v, field) {
  try { return normalizeTime(v, field); } catch (e) { throw new EventStoreError('INVALID_QUERY', e.message); }
}

function normalizeFilter(f = {}) {
  if (f === null || typeof f !== 'object') throw new EventStoreError('INVALID_QUERY', 'query must be an object');
  return {
    since: timeArg(f.since, 'since'),
    until: timeArg(f.until, 'until'),
    source_type: optString(f.source_type, 'source_type'),
    collector_id: optString(f.collector_id, 'collector_id'),
  };
}

const byCountThenName = (a, b) => (b.events - a.events) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

function intArg(v, { def, max }, field) {
  if (v === undefined || v === null) return def;
  if (!Number.isInteger(v) || v < 1 || v > max) throw new EventStoreError('INVALID_QUERY', `${field} must be a whole number from 1 to ${max}`);
  return v;
}

// Leaf paths of a nested object: objects are walked, arrays and scalars are leaves (an empty object has none).
function leafPaths(o, prefix, depth = 0, out = []) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return out;
  for (const [k, v] of Object.entries(o)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && depth < MAX_XDM_DEPTH) leafPaths(v, `${prefix}${k}.`, depth + 1, out);
    else out.push(prefix + k);
  }
  return out;
}

class EventStore {
  get name() { return 'abstract'; }

  async insertBatch(tenantId, events, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (!Array.isArray(events)) throw new EventStoreError('INVALID_BATCH', 'events must be an array');
    if (events.length > MAX_BATCH) throw new EventStoreError('BATCH_TOO_LARGE', `at most ${MAX_BATCH} events per batch`);
    if (!events.length) return { inserted: 0, skipped: 0, ids: [] };

    const envelopes = events.map((e, i) => {
      try {
        if (e && typeof e === 'object' && e.tenant_id && String(e.tenant_id).toLowerCase() !== tenant) {
          throw new EnvelopeError('tenant_id does not match the batch tenant', 'tenant_id');
        }
        return makeEnvelope({ ...e, tenant_id: tenant });
      } catch (err) {
        if (err instanceof EnvelopeError) { err.message = `event ${i}: ${err.message}`; err.index = i; }
        throw err;
      }
    });
    for (const e of envelopes) if (!e.id) e.id = crypto.randomUUID();

    const { inserted } = await this._insert(tenant, envelopes, opts || {});
    return { inserted, skipped: envelopes.length - inserted, ids: envelopes.map((e) => e.id) };
  }

  async getByIds(tenantId, ids) {
    const tenant = assertTenant(tenantId);
    if (!Array.isArray(ids) || ids.length > MAX_IDS || !ids.every((i) => typeof i === 'string' && UUID_RE.test(i))) {
      throw new EventStoreError('INVALID_QUERY', `ids must be an array of at most ${MAX_IDS} UUIDs`);
    }
    if (!ids.length) return [];
    const wanted = ids.map((i) => i.toLowerCase());
    const found = await this._getByIds(tenant, [...new Set(wanted)]);
    const order = new Map(wanted.map((id, i) => [id, i]));
    return found.sort((a, b) => order.get(a.id) - order.get(b.id));
  }

  async scan(tenantId, query = {}) {
    const tenant = assertTenant(tenantId);
    const f = normalizeFilter(query);
    let limit = query.limit === undefined ? DEFAULT_SCAN : query.limit;
    if (!Number.isInteger(limit) || limit < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    limit = Math.min(limit, MAX_SCAN);
    const order = query.order === undefined ? 'asc' : query.order;
    if (order !== 'asc' && order !== 'desc') throw new EventStoreError('INVALID_QUERY', "order must be 'asc' or 'desc'");
    const after = query.after === undefined || query.after === null ? null : decodeCursor(query.after);

    // ask the adapter for one extra row: it tells us whether another page exists
    const rows = await this._scan(tenant, { ...f, limit: limit + 1, order, after });
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    const next = rows.length > limit && last ? encodeCursor(last.cursorTs, last.event.id) : null;
    // `cursor` is a checkpoint just after the last event returned (null for an empty page). Keep it and pass it back
    // as `after` to carry on exactly where this page ended, however many events arrive meanwhile.
    const cursor = last ? encodeCursor(last.cursorTs, last.event.id) : null;
    return { events: page.map((r) => r.event), next, cursor };
  }

  async count(tenantId, filter = {}) {
    return this._count(assertTenant(tenantId), normalizeFilter(filter));
  }

  async sourceTypes(tenantId, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    return this._sourceTypes(tenant, { since: timeArg(opts.since, 'since'), limit: MAX_SOURCE_TYPES });
  }

  async deleteBefore(tenantId, cutoff) {
    const tenant = assertTenant(tenantId);
    const c = timeArg(cutoff, 'cutoff');
    if (!c) throw new EventStoreError('INVALID_QUERY', 'cutoff is required');
    return this._deleteBefore(tenant, c);
  }

  // Run an XQL query plan (the result of xql.parse(), see src/search/xql-plan.js). The plan holds no SQL: each adapter
  // turns it into its own query or evaluates it, always for this tenant only. The plan is validated first (field
  // names, sizes, limits), so even a hand-built plan cannot inject anything. Rows are keyed by output column; 'raw'
  // mode rows are { _id, _time (Date), source_type, collector_id, _raw, parsed }. `truncated` is true when there were
  // more than plan.limit rows (the extra one is dropped). Numbers may come back as numbers or numeric strings.
  async search(tenantId, plan, opts = {}) {
    const tenant = assertTenant(tenantId);
    try { validatePlan(plan); } catch (e) { if (e instanceof PlanError) throw new EventStoreError('INVALID_QUERY', e.message); throw e; }
    const rows = await this._search(tenant, plan, opts || {});
    const truncated = rows.length > plan.limit;
    return { rows: truncated ? rows.slice(0, plan.limit) : rows, truncated, mode: plan.mode, columns: plan.columns || null };
  }

  // Detection rules: which groups of events inside a time frame match a filter, and how many in each. The spec is
  // made of the plan's expression tree (no SQL), so every adapter runs the same rule the same way. Rows are
  // { key, n, first_at, last_at, sample_ids, sample_raw }, biggest group first; see src/search/match-spec.js.
  // validateMatchSpec() runs first, so even a hand-built spec cannot inject anything.
  async matchGroups(tenantId, spec, opts = {}) {
    const tenant = assertTenant(tenantId);
    let norm;
    try { norm = validateMatchSpec(spec); } catch (e) { if (e instanceof PlanError) throw new EventStoreError('INVALID_QUERY', e.message); throw e; }
    return this._matchGroups(tenant, norm, opts || {});
  }

  // Event counts per collector, per source type, or per UTC day of received_at, in one pass. `by` is one of
  // 'collector_id' | 'source_type' | 'day'; since (inclusive) and until (exclusive) are optional bounds on received_at.
  // Returns [{ key, events, first_seen, last_seen }] (first_seen / last_seen are the earliest and latest received_at
  // as ISO times), at most 1000 groups. Events with no collector are left out of the collector_id groups. Order: by
  // day ascending (key is 'YYYY-MM-DD'); otherwise most events first, ties by key. Feeds the collectors page, the
  // dataset list of the search page and the storage page's per-day chart.
  async groupCounts(tenantId, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    if (!GROUP_BY.includes(opts.by)) throw new EventStoreError('INVALID_QUERY', `by must be one of ${GROUP_BY.join(', ')}`);
    const rows = await this._groupCounts(tenant, { by: opts.by, since: timeArg(opts.since, 'since'), until: timeArg(opts.until, 'until'), limit: MAX_GROUPS });
    return rows.map((r) => ({ key: r.key, events: Number(r.events), first_seen: r.first_seen, last_seen: r.last_seen }));
  }

  // { oldest, newest }: the earliest and latest received_at of this tenant's events as ISO times, or nulls when it has none.
  async timeRange(tenantId) {
    const r = await this._timeRange(assertTenant(tenantId));
    return { oldest: r.oldest || null, newest: r.newest || null };
  }

  // Which fields do events have? Counts the top-level keys of `parsed` over the newest `sample` events (default 2000),
  // and the leaf paths under parsed.xdm (as 'xdm.a.b') over the newest `xdmSample` events (default 500) that have an
  // xdm object. Returns { fields: [{ name, events }], xdm: [{ name, events }] }, most events first, ties by name, at
  // most 200 and 500 names. Feeds the Fields panel of the search page.
  async fieldStats(tenantId, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    const sample = intArg(opts.sample, FIELD_SAMPLE, 'sample');
    const xdmSample = intArg(opts.xdmSample, XDM_SAMPLE, 'xdmSample');
    const [keys, xdms] = await Promise.all([this._fieldKeys(tenant, { limit: sample }), this._xdmSamples(tenant, { limit: xdmSample })]);
    const fields = keys.map((k) => ({ name: k.name, events: Number(k.events) })).sort(byCountThenName).slice(0, MAX_FIELD_NAMES);
    const counts = new Map();
    for (const x of xdms) for (const path of leafPaths(x, 'xdm.')) counts.set(path, (counts.get(path) || 0) + 1);
    const xdm = [...counts].map(([name, events]) => ({ name, events })).sort(byCountThenName).slice(0, MAX_XDM_NAMES);
    return { fields, xdm };
  }

  async close() { /* adapters that own connections override this */ }

  // ---- adapter hooks (input is already validated and normalised) -----------------------------
  // _insert(tenant, envelopes, opts) -> { inserted }       every envelope has an id; skip existing (id, received_at)
  // _getByIds(tenant, uniqueLowercaseIds) -> envelope[]
  // _scan(tenant, { since, until, source_type, collector_id, limit, order, after:{ts,id}|null })
  //      -> [{ event, cursorTs }]  in order, at most `limit` rows; cursorTs is the exact received_at text for the cursor
  // _count(tenant, filter) -> number
  // _sourceTypes(tenant, { since, limit }) -> string[]
  // _deleteBefore(tenant, isoCutoff) -> { deleted }
  // _search(tenant, plan, opts) -> object[]      at most plan.limit + 1 rows, already ordered; plan is validated
  // _matchGroups(tenant, spec, opts) -> [{ key, n, first_at, last_at, sample_ids, sample_raw }]   spec is validated and normalised
  // _groupCounts(tenant, { by, since, until, limit }) -> [{ key, events, first_seen, last_seen }]   in the order documented on groupCounts()
  // _timeRange(tenant) -> { oldest, newest }       ISO times or null
  // _fieldKeys(tenant, { limit }) -> [{ name, events }]   top-level keys of `parsed` over the newest `limit` events, ordered (received_at, id) descending
  // _xdmSamples(tenant, { limit }) -> object[]     the xdm object of the newest `limit` events whose parsed.xdm is an object (same order)
  async _insert(tenant, envelopes, opts) { throw new EventStoreError('NOT_IMPLEMENTED', 'insertBatch'); }
  async _getByIds(tenant, ids) { throw new EventStoreError('NOT_IMPLEMENTED', 'getByIds'); }
  async _scan(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'scan'); }
  async _count(tenant, f) { throw new EventStoreError('NOT_IMPLEMENTED', 'count'); }
  async _sourceTypes(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'sourceTypes'); }
  async _deleteBefore(tenant, cutoff) { throw new EventStoreError('NOT_IMPLEMENTED', 'deleteBefore'); }
  async _search(tenant, plan, opts) { throw new EventStoreError('NOT_IMPLEMENTED', 'search'); }
  async _matchGroups(tenant, spec, opts) { throw new EventStoreError('NOT_IMPLEMENTED', 'matchGroups'); }
  async _groupCounts(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'groupCounts'); }
  async _timeRange(tenant) { throw new EventStoreError('NOT_IMPLEMENTED', 'timeRange'); }
  async _fieldKeys(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'fieldStats'); }
  async _xdmSamples(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'fieldStats'); }
}

module.exports = { EventStore, EventStoreError, MAX_BATCH, MAX_SCAN, DEFAULT_SCAN, MAX_IDS, MAX_SOURCE_TYPES, MAX_GROUPS, GROUP_BY, encodeCursor, decodeCursor };
