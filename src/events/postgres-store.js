'use strict';
// Postgres adapter: reads and writes the existing `events` table (plain or daily-partitioned),
// so it needs no schema change. Every call runs inside db.withTenant(), so row-level security
// applies on top of the explicit `tenant_id = $1` filters.
//
// opts.client (insertBatch only): run inside the caller's transaction instead of opening one.
// The caller must already have set app.current_tenant_id (db.withTenant does). The HTTP ingest
// lane uses this so events, collector bookkeeping and the audit row commit together.
//
// Timestamps: the table uses `timestamp` (no zone) and ASIX treats it as UTC, as it does
// everywhere else (localtimestamp, received_at defaults). Keep PostgreSQL's timezone on UTC.

const { EventStore } = require('./event-store');
const { ENVELOPE_VERSION } = require('./envelope');
const { toSql, matchToSql } = require('../search/xql-postgres');

const COLUMNS = `id, tenant_id, source_type, collector_id, received_at::text AS received_at_txt,
                 event_time::text AS event_time_txt, raw, parsed`;

// "2026-10-14 10:00:00.123456" (a timestamp read as text) -> "2026-10-14T10:00:00.123Z"
const toIso = (txt) => (txt ? new Date(String(txt).replace(' ', 'T') + 'Z').toISOString() : null);

function rowToEnvelope(r) {
  return {
    v: ENVELOPE_VERSION,
    id: r.id,
    tenant_id: r.tenant_id,
    source_type: r.source_type,
    collector_id: r.collector_id,
    received_at: toIso(r.received_at_txt),
    event_time: toIso(r.event_time_txt),
    raw: r.raw,
    parsed: r.parsed || {},
  };
}

class PostgresEventStore extends EventStore {
  // `db` is injectable for tests; by default the platform's pool is loaded on first use.
  constructor({ db } = {}) { super(); this._db = db || null; }
  get db() { return this._db || (this._db = require('../db')); }
  get name() { return 'postgres'; }

  _run(tenant, opts, fn) {
    return opts && opts.client ? fn(opts.client) : this.db.withTenant(tenant, fn);
  }

  async _insert(tenant, envelopes, opts) {
    return this._run(tenant, opts, async (client) => {
      const r = await client.query(
        `INSERT INTO events (id, tenant_id, source_type, collector_id, received_at, event_time, raw, parsed)
         SELECT x.id, $1::uuid, x.s, x.c, COALESCE(x.rcv, localtimestamp), x.t, x.r, x.p::jsonb
         FROM unnest($2::uuid[], $3::text[], $4::text[], $5::timestamp[], $6::timestamp[], $7::text[], $8::text[])
              AS x(id, s, c, rcv, t, r, p)
         ON CONFLICT DO NOTHING`,
        [tenant,
          envelopes.map((e) => e.id), envelopes.map((e) => e.source_type), envelopes.map((e) => e.collector_id),
          envelopes.map((e) => e.received_at), envelopes.map((e) => e.event_time),
          envelopes.map((e) => e.raw), envelopes.map((e) => JSON.stringify(e.parsed))]);
      return { inserted: r.rowCount };
    });
  }

  async _getByIds(tenant, ids) {
    return this._run(tenant, null, async (client) => {
      const r = await client.query(`SELECT ${COLUMNS} FROM events WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, [tenant, ids]);
      return r.rows.map(rowToEnvelope);
    });
  }

  // Shared WHERE builder for scan() and count(); params[0] is always the tenant.
  _where(tenant, f) {
    const params = [tenant];
    const where = ['tenant_id = $1'];
    const add = (sql, v) => { params.push(v); where.push(sql.replace('?', '$' + params.length)); };
    if (f.since) add('received_at >= ?::timestamp', f.since);
    if (f.until) add('received_at < ?::timestamp', f.until);
    if (f.source_type) add('source_type = ?', f.source_type);
    if (f.collector_id) add('collector_id = ?', f.collector_id);
    return { params, where };
  }

  async _scan(tenant, q) {
    const { params, where } = this._where(tenant, q);
    const dir = q.order === 'desc' ? 'DESC' : 'ASC';
    if (q.after) {
      params.push(q.after.ts, q.after.id);
      where.push(`(received_at, id) ${q.order === 'desc' ? '<' : '>'} ($${params.length - 1}::timestamp, $${params.length}::uuid)`);
    }
    params.push(q.limit);
    return this._run(tenant, null, async (client) => {
      const r = await client.query(
        `SELECT ${COLUMNS} FROM events WHERE ${where.join(' AND ')} ORDER BY received_at ${dir}, id ${dir} LIMIT $${params.length}`, params);
      return r.rows.map((row) => ({ event: rowToEnvelope(row), cursorTs: row.received_at_txt }));
    });
  }

  async _count(tenant, f) {
    const { params, where } = this._where(tenant, f);
    return this._run(tenant, null, async (client) => {
      const r = await client.query(`SELECT COUNT(*)::bigint AS n FROM events WHERE ${where.join(' AND ')}`, params);
      return Number(r.rows[0].n);
    });
  }

  async _sourceTypes(tenant, { since, limit }) {
    const params = [tenant];
    let sinceSql = '';
    if (since) { params.push(since); sinceSql = ' AND received_at >= $2::timestamp'; }
    params.push(limit);
    return this._run(tenant, null, async (client) => {
      const r = await client.query(
        `SELECT DISTINCT source_type FROM events WHERE tenant_id = $1${sinceSql} ORDER BY 1 LIMIT $${params.length}`, params);
      return r.rows.map((x) => x.source_type);
    });
  }

  // Counts per collector / source type / UTC day, in one scan. The grouping expression is chosen from a fixed list
  // (the base class already checked `by`), never built from input.
  async _groupCounts(tenant, { by, since, until, limit }) {
    const { params, where } = this._where(tenant, { since, until });
    const key = { collector_id: 'collector_id', source_type: 'source_type', day: "to_char(received_at, 'YYYY-MM-DD')" }[by];
    if (by === 'collector_id') where.push('collector_id IS NOT NULL');
    params.push(limit);
    const order = by === 'day' ? '1 ASC' : `n DESC, ${key} COLLATE "C" ASC`;       // byte order, like the other engines
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      const r = await client.query(
        `SELECT ${key} AS key, COUNT(*)::bigint AS n, MIN(received_at)::text AS first_txt, MAX(received_at)::text AS last_txt
         FROM events WHERE ${where.join(' AND ')} GROUP BY 1 ORDER BY ${order} LIMIT $${params.length}`, params);
      return r.rows.map((x) => ({ key: x.key, events: Number(x.n), first_seen: toIso(x.first_txt), last_seen: toIso(x.last_txt) }));
    });
  }

  async _timeRange(tenant) {
    return this._run(tenant, null, async (client) => {
      const r = (await client.query('SELECT MIN(received_at)::text AS lo, MAX(received_at)::text AS hi FROM events WHERE tenant_id = $1', [tenant])).rows[0];
      return { oldest: toIso(r.lo), newest: toIso(r.hi) };
    });
  }

  // Top-level keys of `parsed` over the newest events, counted in the database so the documents are not shipped.
  async _fieldKeys(tenant, { limit }) {
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      const r = await client.query(
        `SELECT k AS name, COUNT(*)::int AS events FROM (
           SELECT jsonb_object_keys(parsed) AS k FROM (
             SELECT parsed FROM events WHERE tenant_id = $1 ORDER BY received_at DESC, id DESC LIMIT $2) s
           WHERE jsonb_typeof(parsed) = 'object') t
         GROUP BY k ORDER BY events DESC, k COLLATE "C" LIMIT 200`, [tenant, limit]);
      return r.rows;
    });
  }

  async _xdmSamples(tenant, { limit }) {
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      // `parsed ? 'xdm'` first: it is what the GIN index on parsed can answer
      const r = await client.query(
        `SELECT parsed->'xdm' AS x FROM events
         WHERE tenant_id = $1 AND parsed ? 'xdm' AND jsonb_typeof(parsed->'xdm') = 'object'
         ORDER BY received_at DESC, id DESC LIMIT $2`, [tenant, limit]);
      return r.rows.map((x) => x.x);
    });
  }

  // The newest events first (event time, else received time). `q` is a literal substring: % and _ are escaped.
  async _listEvents(tenant, q) {
    const params = [tenant];
    const where = ['tenant_id = $1'];
    const add = (sql, v) => { params.push(v); where.push(sql.replace('?', '$' + params.length)); };
    if (q.source_type) add('source_type = ?', q.source_type);
    if (q.collector_id) add('collector_id = ?', q.collector_id);
    if (q.from) add('COALESCE(event_time, received_at) >= ?::timestamp', q.from);
    if (q.to) add('COALESCE(event_time, received_at) <= ?::timestamp', q.to);
    if (q.q) add('raw ILIKE ?', '%' + q.q.replace(/[\\%_]/g, '\\$&') + '%');
    params.push(q.limit, q.offset);
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      const r = await client.query(
        `SELECT ${COLUMNS} FROM events WHERE ${where.join(' AND ')}
         ORDER BY COALESCE(event_time, received_at) DESC, id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
      return r.rows.map(rowToEnvelope);
    });
  }

  async _dataSources(tenant, { recentSince, limit }) {
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      const r = await client.query(
        `SELECT source_type, collector_id, COUNT(*)::bigint AS events_total,
                COUNT(*) FILTER (WHERE COALESCE(event_time, received_at) > $2::timestamp)::bigint AS events_recent,
                MAX(received_at)::text AS last_txt
         FROM events WHERE tenant_id = $1 GROUP BY source_type, collector_id
         ORDER BY MAX(received_at) DESC, source_type COLLATE "C" ASC, collector_id COLLATE "C" ASC NULLS LAST LIMIT $3`, [tenant, recentSince, limit]);
      return r.rows.map((x) => ({ source_type: x.source_type, collector_id: x.collector_id, events_total: Number(x.events_total), events_recent: Number(x.events_recent), last_received: toIso(x.last_txt) }));
    });
  }

  async _ingestionStats(tenant, { by, groups, since, recent, hourFrom }) {
    const key = by === 'collector_id' ? "COALESCE(collector_id, '(none)')" : 'source_type';       // from a fixed list, never from input
    const ts = 'COALESCE(event_time, received_at)';
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      const t = (await client.query(
        `SELECT COUNT(*)::bigint AS events, COALESCE(SUM(octet_length(raw)), 0)::bigint AS bytes,
                COUNT(*) FILTER (WHERE received_at > $3::timestamp)::bigint AS events_1h,
                COUNT(DISTINCT source_type)::bigint AS source_types, COUNT(DISTINCT collector_id)::bigint AS collectors,
                MAX(received_at)::text AS last_txt
         FROM events WHERE tenant_id = $1 AND ${ts} > $2::timestamp`, [tenant, since, recent])).rows[0];
      const h = await client.query(
        `SELECT to_char(date_trunc('hour', ${ts}), 'YYYY-MM-DD"T"HH24:MI:SS.000"Z"') AS hour, COUNT(*)::bigint AS n
         FROM events WHERE tenant_id = $1 AND ${ts} >= $2::timestamp GROUP BY 1`, [tenant, hourFrom]);
      const g = await client.query(
        `SELECT ${key} AS key, COUNT(*)::bigint AS events, COALESCE(SUM(octet_length(raw)), 0)::bigint AS bytes
         FROM events WHERE tenant_id = $1 AND ${ts} > $2::timestamp GROUP BY 1 ORDER BY 2 DESC, ${key} COLLATE "C" ASC LIMIT $3`, [tenant, since, groups]);
      return {
        totals: { events: t.events, bytes: t.bytes, events_1h: t.events_1h, source_types: t.source_types, collectors: t.collectors, last_received: toIso(t.last_txt) },
        hours: h.rows.map((x) => ({ hour: x.hour, n: Number(x.n) })),
        groups: g.rows,
      };
    });
  }

  // A plain row delete. Dropping whole daily partitions (what src/storage/retention.js does for
  // large tables) stays in the retention job until it is moved behind this interface.
  async _deleteBefore(tenant, cutoff) {
    return this._run(tenant, null, async (client) => {
      const r = await client.query('DELETE FROM events WHERE tenant_id = $1 AND received_at < $2::timestamp', [tenant, cutoff]);
      return { deleted: r.rowCount };
    });
  }

  // An XQL plan becomes SQL here (src/search/xql-postgres.js: every value is a bound parameter, the tenant is $1).
  async _search(tenant, plan, opts) {
    const q = toSql(plan, tenant);
    return this._run(tenant, opts, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      return (await client.query(q.sql, q.values)).rows;
    });
  }

  // A rule match spec becomes SQL here (src/search/xql-postgres.js matchToSql: every value is a bound parameter).
  async _matchGroups(tenant, spec, opts) {
    const q = matchToSql(spec, tenant);
    const rows = await this._run(tenant, opts, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      return (await client.query(q.sql, q.values)).rows;
    });
    return rows.map((r) => ({ key: r.gkey, n: Number(r.n), first_at: toIso(r.first_at), last_at: toIso(r.last_at), sample_ids: r.sample_ids || [], sample_raw: r.sample_raw }));
  }

  async close() { /* the shared pool belongs to src/db */ }
}

module.exports = { PostgresEventStore, rowToEnvelope };
