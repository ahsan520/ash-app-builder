'use strict';
// The event envelope: the ONE shape an event has between ingest and storage, whatever the
// storage engine is (Postgres today, ClickHouse later). It matches the columns of the existing
// `events` table, so adopting it needs no schema change.
//
//   {
//     v: 1,                         envelope version (not stored; rows without it are v1)
//     id: uuid | null,              null = the store assigns one. If set, received_at must be set too:
//                                   the pair (id, received_at) is the idempotency key (re-inserting
//                                   the same pair is a no-op), which is what a queue that delivers
//                                   at-least-once needs.
//     tenant_id: uuid,
//     source_type: string,          dataset, e.g. 'syslog' (1-100 chars)
//     collector_id: string | null,  which collector/broker sent it (max 255 chars)
//     received_at: ISO string|null, when ASIX got it; null = the store stamps "now"
//     event_time: ISO string|null,  when the source says it happened
//     raw: string,                  original untouched payload, never empty
//     parsed: object                parsed fields; parsed.xdm.* holds the data model mapping
//   }
//
// makeEnvelope() validates and cleans; it never guesses. Bad input throws EnvelopeError.

const ENVELOPE_VERSION = 1;
const LIMITS = Object.freeze({
  SOURCE_TYPE: 100,
  COLLECTOR_ID: 255,
  RAW: 65536,                 // characters
  PARSED_BYTES: 1024 * 1024,  // serialized JSON
  JSON_DEPTH: 32,
});
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUL_RE = /\u0000/g;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

class EnvelopeError extends Error {
  constructor(message, field) {
    super(message);
    this.name = 'EnvelopeError';
    this.code = 'INVALID_ENVELOPE';
    this.field = field || null;
  }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date);

// Any time-like input -> ISO-8601 UTC string (ms precision), or null for "not given".
// Strings without a zone are read as UTC. Anything else that does not parse is an error.
function normalizeTime(value, field) {
  if (value === undefined || value === null || value === '') return null;
  let d;
  if (value instanceof Date) d = value;
  else if (typeof value === 'number' && Number.isFinite(value)) d = new Date(value);
  else if (typeof value === 'string') {
    let t = value.trim();
    if (!/^\d{4}-\d{2}-\d{2}/.test(t)) throw new EnvelopeError(`${field} is not an ISO-8601 time`, field);
    t = t.replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T').replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
    if (!/(Z|[+-]\d{2}:\d{2})$/i.test(t)) t += 'Z';
    d = new Date(t);
  } else throw new EnvelopeError(`${field} is not a time`, field);
  if (Number.isNaN(d.getTime())) throw new EnvelopeError(`${field} is not a valid time`, field);
  return d.toISOString();
}

// Deep-clean a value into plain JSON: strips NUL characters (PostgreSQL rejects them in text and
// jsonb, which would otherwise fail a whole batch), drops undefined/functions/symbols, turns Dates
// into ISO strings and BigInts into strings, and skips the key "__proto__".
function cleanJson(value, depth = 0) {
  if (depth > LIMITS.JSON_DEPTH) throw new EnvelopeError(`parsed is nested deeper than ${LIMITS.JSON_DEPTH} levels`, 'parsed');
  switch (typeof value) {
    case 'string': return value.replace(NUL_RE, '');
    case 'number': return Number.isFinite(value) ? value : null;
    case 'boolean': return value;
    case 'bigint': return String(value);
    case 'object': {
      if (value === null) return null;
      if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
      if (Array.isArray(value)) return value.map((v) => { const c = cleanJson(v, depth + 1); return c === undefined ? null : c; });
      const out = {};
      for (const k of Object.keys(value)) {
        if (k === '__proto__') continue;
        const c = cleanJson(value[k], depth + 1);
        if (c !== undefined) out[k.replace(NUL_RE, '')] = c;
      }
      return out;
    }
    default: return undefined; // undefined, function, symbol
  }
}

function makeEnvelope(input) {
  if (!isPlainObject(input)) throw new EnvelopeError('event must be an object');

  if (typeof input.tenant_id !== 'string' || !UUID_RE.test(input.tenant_id)) throw new EnvelopeError('tenant_id must be a UUID', 'tenant_id');

  let id = null;
  if (input.id !== undefined && input.id !== null) {
    if (typeof input.id !== 'string' || !UUID_RE.test(input.id)) throw new EnvelopeError('id must be a UUID', 'id');
    id = input.id.toLowerCase();
  }

  if (typeof input.source_type !== 'string') throw new EnvelopeError('source_type is required', 'source_type');
  const source_type = input.source_type.trim();
  if (!source_type || source_type.length > LIMITS.SOURCE_TYPE || CONTROL_RE.test(source_type)) {
    throw new EnvelopeError(`source_type must be 1-${LIMITS.SOURCE_TYPE} characters with no control characters`, 'source_type');
  }

  let collector_id = null;
  if (input.collector_id !== undefined && input.collector_id !== null && input.collector_id !== '') {
    if (typeof input.collector_id !== 'string' || input.collector_id.length > LIMITS.COLLECTOR_ID || CONTROL_RE.test(input.collector_id)) {
      throw new EnvelopeError(`collector_id must be a string of at most ${LIMITS.COLLECTOR_ID} characters`, 'collector_id');
    }
    collector_id = input.collector_id;
  }

  const received_at = normalizeTime(input.received_at, 'received_at');
  const event_time = normalizeTime(input.event_time, 'event_time');
  if (id && !received_at) throw new EnvelopeError('an event with an id must also have received_at (the pair is its idempotency key)', 'received_at');

  if (typeof input.raw !== 'string') throw new EnvelopeError('raw is required and must be a string', 'raw');
  const raw = input.raw.replace(NUL_RE, '');
  if (!raw) throw new EnvelopeError('raw must not be empty', 'raw');
  if (raw.length > LIMITS.RAW) throw new EnvelopeError(`raw is longer than ${LIMITS.RAW} characters`, 'raw');

  let parsed = {};
  if (input.parsed !== undefined && input.parsed !== null) {
    if (!isPlainObject(input.parsed)) throw new EnvelopeError('parsed must be an object', 'parsed');
    parsed = cleanJson(input.parsed);
    if (Buffer.byteLength(JSON.stringify(parsed), 'utf8') > LIMITS.PARSED_BYTES) {
      throw new EnvelopeError(`parsed is larger than ${LIMITS.PARSED_BYTES} bytes`, 'parsed');
    }
  }

  return { v: ENVELOPE_VERSION, id, tenant_id: input.tenant_id.toLowerCase(), source_type, collector_id, received_at, event_time, raw, parsed };
}

module.exports = { ENVELOPE_VERSION, LIMITS, UUID_RE, EnvelopeError, makeEnvelope, normalizeTime, cleanJson };
