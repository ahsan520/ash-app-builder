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
//   listEvents(tenantId, { source_type?, collector_id?, from?, to?, q?, limit?, offset? }) -> envelope[]   (newest event time first, offset paging)
//   dataSources(tenantId, { recentSince? }) -> [{ source_type, collector_id, events_total, events_recent, last_received }]
//   ingestionStats(tenantId, { by?, now?, groups? }) -> { totals, hourly, groups }   (the Command Center numbers)
//   expiredCounts(tenantId, policy, { now? }) -> [{ source_type, events, oldest }]   (what a purge would delete, read-only)
//   deleteExpired(tenantId, policy, { now?, deadline?, batch? }) -> { deleted, by_source, truncated }   (the retention purge)
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
const LIST = { def: 50, max: 500 };
const MAX_OFFSET = 100000;
const MAX_QUERY_TEXT = 500;
const INGEST_BY = ['source_type', 'collector_id'];
const HOUR_MS = 3600000;
const FIELD_SAMPLE = { def: 2000, max: 10000 };
const XDM_SAMPLE = { def: 500, max: 5000 };
const MAX_FIELD_NAMES = 200;
const MAX_XDM_NAMES = 500;
const MAX_XDM_DEPTH = 20;
const DAY_MS = 86400000;
const RETENTION_DAYS = { min: 1, max: 3650 };
const PURGE_BATCH = { def: 10000, max: 100000 };

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

// --- retention policy: { default_days, overrides: [{ source_type, retention_days | null }] } --------------------
// An event is expired when received_at is older than `now` minus the days that apply to its source type: the
// override's days when the source type has one (null = keep forever), else default_days. Sources with no override
// follow the default, so "keep forever" is only ever written as an explicit override.
function normalizePolicy(p) {
  if (p === null || typeof p !== 'object' || Array.isArray(p)) throw new EventStoreError('INVALID_QUERY', 'policy must be an object');
  const days = (v, what) => {
    if (!Number.isInteger(v) || v < RETENTION_DAYS.min || v > RETENTION_DAYS.max) {
      throw new EventStoreError('INVALID_QUERY', `${what} must be a whole number from ${RETENTION_DAYS.min} to ${RETENTION_DAYS.max}`);
    }
    return v;
  };
  const default_days = days(p.default_days, 'default_days');
  const list = p.overrides === undefined || p.overrides === null ? [] : p.overrides;
  if (!Array.isArray(list) || list.length > MAX_GROUPS) throw new EventStoreError('INVALID_QUERY', `overrides must be a list of at most ${MAX_GROUPS} entries`);
  const seen = new Set();
  const overrides = list.map((o) => {
    if (o === null || typeof o !== 'object' || typeof o.source_type !== 'string' || !o.source_type || o.source_type.length > 255 || o.source_type.includes('\0')) {
      throw new EventStoreError('INVALID_QUERY', 'each override needs a source_type of 1 to 255 characters');
    }
    if (seen.has(o.source_type)) throw new EventStoreError('INVALID_QUERY', `duplicate override for source_type "${o.source_type}"`);
    seen.add(o.source_type);
    return { source_type: o.source_type, retention_days: o.retention_days === null ? null : days(o.retention_days, `retention_days for "${o.source_type}"`) };
  }).sort((a, b) => cmpText(a.source_type, b.source_type));
  return { default_days, overrides };
}
const cmpText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// How many days of this source type's events are kept (null = forever). Takes a normalised policy.
function daysFor(policy, sourceType) {
  const o = policy.overrides.find((x) => x.source_type === sourceType);
  return o ? o.retention_days : policy.default_days;
}

// The shortest retention that applies to anything: no event newer than now minus this can be expired.
const shortestDays = (policy) => Math.min(policy.default_days, ...policy.overrides.filter((o) => o.retention_days !== null).map((o) => o.retention_days));

const cutoffIso = (nowMs, days) => new Date(nowMs - days * DAY_MS).toISOString();

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

  // The newest events first, for a console list: event time (else received time) descending, ties by id descending.
  // Optional filters, all ANDed: source_type and collector_id (exact), from (inclusive) and to (inclusive) on the event
  // time, and q, a case-insensitive substring of the raw text (taken literally: % and _ are ordinary characters). `limit`
  // is 1 to 500 (default 50) and `offset` 0 to 100,000. Returns envelopes. Feeds GET /v1/search/events.
  async listEvents(tenantId, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    const q = opts.q === undefined || opts.q === null || opts.q === '' ? null : opts.q;
    if (q !== null && (typeof q !== 'string' || q.length > MAX_QUERY_TEXT || q.includes('\0'))) throw new EventStoreError('INVALID_QUERY', `q must be text of at most ${MAX_QUERY_TEXT} characters`);
    const offset = opts.offset === undefined || opts.offset === null ? 0 : opts.offset;
    if (!Number.isInteger(offset) || offset < 0 || offset > MAX_OFFSET) throw new EventStoreError('INVALID_QUERY', `offset must be a whole number from 0 to ${MAX_OFFSET}`);
    const rows = await this._listEvents(tenant, {
      source_type: optString(opts.source_type, 'source_type'), collector_id: optString(opts.collector_id, 'collector_id'),
      from: timeArg(opts.from, 'from'), to: timeArg(opts.to, 'to'), q, offset, limit: intArg(opts.limit, LIST, 'limit'),
    });
    return rows.map((e) => ({ ...e, parsed: e.parsed || {} }));
  }

  // One row per (source type, collector) over ALL of the tenant's events: how many in total, how many have an event time
  // (else received time) after `recentSince` (an ISO time, default 24 hours ago), and the latest received_at. Most
  // recently received first, ties by source type then collector (a missing collector last); at most 1,000 rows.
  // Feeds GET /v1/data-sources.
  async dataSources(tenantId, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    const recentSince = timeArg(opts.recentSince, 'recentSince') || new Date(Date.now() - 24 * HOUR_MS).toISOString();
    const rows = await this._dataSources(tenant, { recentSince, limit: MAX_GROUPS });
    return rows.map((r) => ({ source_type: r.source_type, collector_id: r.collector_id === undefined ? null : r.collector_id,
      events_total: Number(r.events_total), events_recent: Number(r.events_recent), last_received: r.last_received }));
  }

  // The Command Center numbers. `now` (an ISO time, default the current time) fixes three windows: the last 24 hours and the
  // last hour (events are in the 24 hour window by event time, else received time) and 24 whole UTC hours ending with the
  // current hour. Returns
  //   totals  { events, bytes, events_1h, source_types, collectors, last_received }   events in the 24 hour window; bytes is the
  //           size of their raw text in UTF-8 bytes; events_1h those also received in the last hour; source_types / collectors
  //           the distinct counts (events with no collector do not count); last_received the latest received_at (or null)
  //   hourly  24 x { hour, n }   oldest first, hour an ISO time on the hour, 0 for an hour with no events (event time)
  //   groups  [{ key, events, bytes }]   the 24 hour window grouped by `by` ('source_type' by default, or 'collector_id', where
  //           a missing collector is '(none)'), most events first, ties by key, at most `groups` (default 12, max 100)
  async ingestionStats(tenantId, opts = {}) {
    const tenant = assertTenant(tenantId);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    const by = opts.by === undefined || opts.by === null ? 'source_type' : opts.by;
    if (!INGEST_BY.includes(by)) throw new EventStoreError('INVALID_QUERY', `by must be one of ${INGEST_BY.join(', ')}`);
    const now = Date.parse(timeArg(opts.now, 'now') || new Date().toISOString());
    const groups = intArg(opts.groups, { def: 12, max: 100 }, 'groups');
    const hourEnd = Math.floor(now / HOUR_MS) * HOUR_MS;
    const hourStart = hourEnd - 23 * HOUR_MS;
    const r = await this._ingestionStats(tenant, {
      by, groups, since: new Date(now - 24 * HOUR_MS).toISOString(), recent: new Date(now - HOUR_MS).toISOString(), hourFrom: new Date(hourStart).toISOString(),
    });
    const perHour = new Map(r.hours.map((h) => [h.hour, Number(h.n)]));
    const hourly = Array.from({ length: 24 }, (_, i) => { const hour = new Date(hourStart + i * HOUR_MS).toISOString(); return { hour, n: perHour.get(hour) || 0 }; });
    const t = r.totals;
    return {
      totals: { events: Number(t.events), bytes: Number(t.bytes), events_1h: Number(t.events_1h), source_types: Number(t.source_types), collectors: Number(t.collectors), last_received: t.last_received || null },
      hourly,
      groups: r.groups.map((g) => ({ key: g.key, events: Number(g.events), bytes: Number(g.bytes) })),
    };
  }

  // What a purge would delete right now (read-only): the events past their retention, per source type, with the received
  // time of the oldest one. [{ source_type, events, oldest }], most events first, ties by source type; source types with
  // nothing expired are left out. `now` (an ISO time, default the current time) is the instant the policy is applied at.
  // Feeds the "Check what would be deleted" button of the storage page.
  async expiredCounts(tenantId, policy, opts = {}) {
    const tenant = assertTenant(tenantId);
    const pol = normalizePolicy(policy);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    const now = timeArg(opts.now, 'now') || new Date().toISOString();
    const rows = await this._expiredCounts(tenant, pol, { now });
    return rows.map((r) => ({ source_type: r.source_type, events: Number(r.events), oldest: r.oldest || null }))
      .sort((a, b) => (b.events - a.events) || cmpText(a.source_type, b.source_type));
  }

  // The retention purge: permanently deletes this tenant's events that are past their retention (see normalizePolicy
  // above for the rule). Returns { deleted, by_source: { <source_type>: n }, truncated }. `deadline` (epoch milliseconds)
  // stops the work early: `truncated` is then true and running it again carries on. `batch` (1 to 100,000, default
  // 10,000) is how many rows an engine that deletes in batches removes per statement. Adapters may add fields of their own
  // (the Postgres one reports `partitions_scanned`). It does not drop whole partitions: that stays with each engine's own housekeeping.
  async deleteExpired(tenantId, policy, opts = {}) {
    const tenant = assertTenant(tenantId);
    const pol = normalizePolicy(policy);
    if (opts === null || typeof opts !== 'object') throw new EventStoreError('INVALID_QUERY', 'options must be an object');
    const now = timeArg(opts.now, 'now') || new Date().toISOString();
    if (opts.deadline !== undefined && opts.deadline !== null && !Number.isFinite(opts.deadline)) throw new EventStoreError('INVALID_QUERY', 'deadline must be a time in epoch milliseconds');
    const batch = intArg(opts.batch, PURGE_BATCH, 'batch');
    const r = await this._deleteExpired(tenant, pol, { now, deadline: opts.deadline === undefined ? null : opts.deadline, batch });
    return { ...r, deleted: Number(r.deleted), by_source: r.by_source || {}, truncated: !!r.truncated };
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
  // _listEvents(tenant, { source_type, collector_id, from, to, q, offset, limit }) -> envelope[]   in the order documented on listEvents()
  // _dataSources(tenant, { recentSince, limit }) -> [{ source_type, collector_id, events_total, events_recent, last_received }]
  // _ingestionStats(tenant, { by, groups, since, recent, hourFrom }) -> { totals, hours: [{ hour, n }] (hours with events only, ISO on the hour, none before hourFrom), groups }
  // _groupCounts(tenant, { by, since, until, limit }) -> [{ key, events, first_seen, last_seen }]   in the order documented on groupCounts()
  // _timeRange(tenant) -> { oldest, newest }       ISO times or null
  // _fieldKeys(tenant, { limit }) -> [{ name, events }]   top-level keys of `parsed` over the newest `limit` events, ordered (received_at, id) descending
  // _xdmSamples(tenant, { limit }) -> object[]     the xdm object of the newest `limit` events whose parsed.xdm is an object (same order)
  // _expiredCounts(tenant, policy, { now }) -> [{ source_type, events, oldest }]   policy is normalised; oldest is an ISO time
  // _deleteExpired(tenant, policy, { now, deadline, batch }) -> { deleted, by_source, truncated }   deadline is epoch ms or null
  async _insert(tenant, envelopes, opts) { throw new EventStoreError('NOT_IMPLEMENTED', 'insertBatch'); }
  async _getByIds(tenant, ids) { throw new EventStoreError('NOT_IMPLEMENTED', 'getByIds'); }
  async _scan(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'scan'); }
  async _count(tenant, f) { throw new EventStoreError('NOT_IMPLEMENTED', 'count'); }
  async _sourceTypes(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'sourceTypes'); }
  async _deleteBefore(tenant, cutoff) { throw new EventStoreError('NOT_IMPLEMENTED', 'deleteBefore'); }
  async _search(tenant, plan, opts) { throw new EventStoreError('NOT_IMPLEMENTED', 'search'); }
  async _matchGroups(tenant, spec, opts) { throw new EventStoreError('NOT_IMPLEMENTED', 'matchGroups'); }
  async _listEvents(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'listEvents'); }
  async _dataSources(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'dataSources'); }
  async _ingestionStats(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'ingestionStats'); }
  async _groupCounts(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'groupCounts'); }
  async _timeRange(tenant) { throw new EventStoreError('NOT_IMPLEMENTED', 'timeRange'); }
  async _fieldKeys(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'fieldStats'); }
  async _xdmSamples(tenant, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'fieldStats'); }
  async _expiredCounts(tenant, policy, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'expiredCounts'); }
  async _deleteExpired(tenant, policy, q) { throw new EventStoreError('NOT_IMPLEMENTED', 'deleteExpired'); }
}

module.exports = { EventStore, EventStoreError, daysFor, shortestDays, cutoffIso, DAY_MS, MAX_BATCH, MAX_SCAN, DEFAULT_SCAN, MAX_IDS, MAX_SOURCE_TYPES, MAX_GROUPS, GROUP_BY, encodeCursor, decodeCursor };
