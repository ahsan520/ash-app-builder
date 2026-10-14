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
//   scan(tenantId, query?)                -> { events, next }      (cursor paging, stable order)
//   count(tenantId, filter?)              -> number
//   sourceTypes(tenantId, { since? })     -> string[]              (distinct, sorted, max 100)
//   deleteBefore(tenantId, cutoff)        -> { deleted }           (received_at < cutoff)
//
// Order is always (received_at, id). `since` is inclusive, `until` exclusive, both on received_at.
// Cursors (`next` / `after`) are opaque and only valid with the adapter that produced them.

const crypto = require('crypto');
const { UUID_RE, EnvelopeError, makeEnvelope, normalizeTime } = require('./envelope');

const MAX_BATCH = 5000;
const MAX_SCAN = 1000;
const DEFAULT_SCAN = 100;
const MAX_IDS = 1000;
const MAX_SOURCE_TYPES = 100;

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
    return { events: page.map((r) => r.event), next };
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

  async close() { /* adapters that own connections override this */ }

  // ---- adapter hooks (input is already validated and normalised) -----------------------------
  // _insert(tenant, envelopes, opts) -> { inserted }       every envelope has an id; skip existing (id, received_at)
  // _getByIds(tenant, uniqueLowercaseIds) -> envelope[]
  // _scan(tenant, { since, until, source_type, collector_id, limit, order, after:{ts,id}|null })
  //      -> [{ event, cursorTs }]  in order, at most `limit` rows; cursorTs is the exact received_at text for the cursor
  // _count(tenant, filter) -> number
  // _sourceTypes(tenant, { since, limit }) -> string[]
  // _deleteBefore(tenant, isoCutoff) -> { deleted }
  async _insert(tenant, envelopes, opts) { throw new Error('not implemented'); }
  async _getByIds(tenant, ids) { throw new Error('not implemented'); }
  async _scan(tenant, q) { throw new Error('not implemented'); }
  async _count(tenant, filter) { throw new Error('not implemented'); }
  async _sourceTypes(tenant, q) { throw new Error('not implemented'); }
  async _deleteBefore(tenant, cutoff) { throw new Error('not implemented'); }
}

module.exports = { EventStore, EventStoreError, MAX_BATCH, MAX_SCAN, DEFAULT_SCAN, MAX_IDS, MAX_SOURCE_TYPES, encodeCursor, decodeCursor };
