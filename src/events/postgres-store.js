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

  // A plain row delete. Dropping whole daily partitions (what src/storage/retention.js does for
  // large tables) stays in the retention job until it is moved behind this interface.
  async _deleteBefore(tenant, cutoff) {
    return this._run(tenant, null, async (client) => {
      const r = await client.query('DELETE FROM events WHERE tenant_id = $1 AND received_at < $2::timestamp', [tenant, cutoff]);
      return { deleted: r.rowCount };
    });
  }

  // Executes an XQL-compiled SQL query. The SQL is safe by construction (from xql.compile) and carries
  // its own tenant_id filter; nothing is prepended here. Row-level security (db.withTenant) is a second
  // layer only when the connecting role does not own the table.
  async _querySQL(tenant, sql, params, opts) {
    return this._run(tenant, opts, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      const result = await client.query(sql, params);
      const fields = result.fields ? result.fields.map((f) => f.name) : [];
      return { rows: result.rows, fields };
    });
  }

  // Used by detection rules (rule-runner.js / rule-query.js buildMatch) and the IOC matcher.
  // group_expr is a trusted SQL fragment like "COALESCE(parsed #>> '{xdm,source,ipv4}'::text[], 'unknown')"
  // that the rule definition author controls via group_by — never raw user input.
  async _queryAggregated(tenant, { since, until, source_type, collector_id, limit, group_expr, sample_ids }) {
    return this._run(tenant, null, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      const params = [tenant];
      const add = (v) => { params.push(v); return '$' + params.length; };
      const where = ['tenant_id = $1'];

      if (since) { where.push(`received_at >= ${add(since)}::timestamp`); }
      if (until) { where.push(`received_at < ${add(until)}::timestamp`); }
      if (source_type) { where.push(`source_type = ${add(source_type)}`); }
      if (collector_id) { where.push(`collector_id = ${add(collector_id)}`); }

      // group_expr is a SQL fragment, not a parameter — it comes from the rule's group_by whitelist.
      const g = group_expr || "'all'";
      const sampleCols = sample_ids
        ? `, (array_agg(id ORDER BY received_at DESC))[1:5] AS sample_ids, (array_agg(raw ORDER BY received_at DESC))[1] AS sample_raw`
        : '';
      const text = `
        SELECT ${g} AS gkey, COUNT(*)::int AS n, MIN(received_at) AS first_at, MAX(received_at) AS last_at${sampleCols}
        FROM events WHERE ${where.join(' AND ')}
        GROUP BY 1 HAVING COUNT(*) >= 1
        ORDER BY n DESC LIMIT ${limit}`;
      const result = await client.query(text, params);
      return result.rows;
    });
  }

  async close() { /* the shared pool belongs to src/db */ }
}

module.exports = { PostgresEventStore, rowToEnvelope };
