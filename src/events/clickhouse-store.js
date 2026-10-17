'use strict';
// ClickHouse adapter for the event store (Phase 2). It must pass tests/event-store-conformance.js
// unchanged; tests/event-store-clickhouse.test.js runs it against a real server (ASIX_TEST_DB=1).
//
// It talks to ClickHouse's HTTP interface with Node's built-in fetch, so it adds no npm dependency.
//   ASIX_EVENT_STORE=clickhouse
//   ASIX_CLICKHOUSE_URL=http://user:password@host:8123/asix     (database = path, default "asix")
//   ASIX_CLICKHOUSE_TIMEOUT_MS=30000                            (optional)
//
// Table: see SCHEMA_SQL below (also applied by store.ensureSchema()). One row per event:
// ReplacingMergeTree sorted by (tenant_id, received_at, id), partitioned by day.
//
// Idempotency. ReplacingMergeTree only removes duplicates when parts merge, which can be much
// later, so the adapter does not rely on it for correctness: _insert looks up which
// (id, received_at) pairs already exist and inserts only the new ones, and every read that could
// see two copies uses FINAL. The merge is just housekeeping. Two inserts of the same pair at the
// same instant can both pass the lookup; FINAL still hides the second copy.
//
// Safety. Tenant ids, event ids and timestamps are validated by the base class (UUID / ISO) before
// they get here and are the only values written into the SQL text. Free-text filters (source_type,
// collector_id) and every cursor value go through ClickHouse query parameters, never string splicing.

const { EventStore, EventStoreError, daysFor, shortestDays, cutoffIso, MAX_GROUPS } = require('./event-store');
const { ENVELOPE_VERSION, UUID_RE } = require('./envelope');
const { toClickHouse, matchToClickHouse } = require('../search/xql-clickhouse');

// Plain column names on purpose: an alias such as `toString(id) AS id` would shadow the column inside
// WHERE and ORDER BY (comparing text with UUIDs, sorting times as text). JSONEachRow already renders
// UUID and DateTime64 as strings ("2026-10-14 10:00:00.123", UTC).
const COLUMNS = 'id, tenant_id, source_type, collector_id, received_at, event_time, raw, parsed';
const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const DEFAULT_TIMEOUT_MS = 30000;
const READ_SETTINGS = { max_execution_time: 20 }; // seconds; the counterpart of Postgres statement_timeout

const schemaSql = (table) => `CREATE TABLE IF NOT EXISTS ${table} (
  id UUID,
  tenant_id UUID,
  source_type LowCardinality(String),
  collector_id Nullable(String),
  received_at DateTime64(3, 'UTC'),
  event_time Nullable(DateTime64(3, 'UTC')),
  raw String CODEC(ZSTD(3)),
  parsed String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(received_at)
ORDER BY (tenant_id, received_at, id)`;

// "2026-10-14T10:00:00.123Z" -> "2026-10-14 10:00:00.123" (what DateTime64 literals and parameters read)
const chTime = (iso) => (iso ? String(iso).replace('T', ' ').replace(/Z$/, '') : null);
// ClickHouse text ("2026-10-14 10:00:00.123", UTC) -> "2026-10-14T10:00:00.123Z"
const isoTime = (txt) => (txt === null || txt === undefined ? null : new Date(`${String(txt).replace(' ', 'T')}Z`).toISOString());
// a cursor timestamp (any form the base class accepts) -> DateTime64 text, millisecond precision
const cursorTime = (ts) => chTime(new Date(/Z$/.test(ts) ? ts.replace(' ', 'T') : `${ts.replace(' ', 'T')}Z`).toISOString());

// Query parameters are parsed like TSV text: backslash and control characters must be escaped.
const escParam = (s) => String(s).replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n').replace(/\r/g, '\\r');

function rowToEnvelope(r) {
  let parsed = {};
  try { parsed = r.parsed ? JSON.parse(r.parsed) : {}; } catch (_) { parsed = {}; }
  return {
    v: ENVELOPE_VERSION,
    id: r.id,
    tenant_id: r.tenant_id,
    source_type: r.source_type,
    collector_id: r.collector_id === undefined ? null : r.collector_id,
    received_at: isoTime(r.received_at),
    event_time: isoTime(r.event_time),
    raw: r.raw,
    parsed,
  };
}

class ClickHouseEventStore extends EventStore {
  // `url` and `table` are injectable for tests; `fetch` too (a stub, or a different HTTP client).
  constructor({ url, table, fetch: fetchImpl, timeoutMs, initRetry } = {}) {
    super();
    this._initRetry = { attempts: 10, delayMs: 3000, ...(initRetry || {}) };
    this._url = url || null;
    this._table = table || 'events';
    if (!TABLE_RE.test(this._table)) throw new Error('ClickHouse table name must match [A-Za-z_][A-Za-z0-9_]{0,63}');
    this._fetch = fetchImpl || null;
    this._timeoutMs = Number(timeoutMs || process.env.ASIX_CLICKHOUSE_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
    this._conn = null;
  }

  get name() { return 'clickhouse'; }
  get table() { return this._table; }

  get conn() {
    if (this._conn) return this._conn;
    const raw = this._url || process.env.ASIX_CLICKHOUSE_URL;
    if (!raw) throw new Error('ASIX_CLICKHOUSE_URL is not set');
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('ASIX_CLICKHOUSE_URL must be an http(s) URL');
    const user = decodeURIComponent(u.username || 'default');
    const password = decodeURIComponent(u.password || '');
    this._conn = {
      base: `${u.protocol}//${u.host}/`,
      database: decodeURIComponent(u.pathname.replace(/^\/+/, '')) || 'asix',
      auth: `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`,
    };
    return this._conn;
  }

  // One HTTP round trip. `sql` goes in the body (no length limit); parameters and settings go in the URL.
  async _exec(sql, { params = {}, settings = {}, body = null, format = null } = {}) {
    const { base, database, auth } = this.conn;
    const qs = new URLSearchParams({ database, ...settings });
    for (const [k, v] of Object.entries(params)) qs.set(`param_${k}`, escParam(v));
    // an INSERT carries its rows in the body, so its statement moves to the URL
    if (body !== null) qs.set('query', sql);
    const doFetch = this._fetch || globalThis.fetch;
    let res;
    try {
      res = await doFetch(`${base}?${qs.toString()}`, {
        method: 'POST',
        headers: { Authorization: auth, 'Content-Type': 'text/plain; charset=utf-8' },
        body: body !== null ? body : (format ? `${sql} FORMAT ${format}` : sql),
        signal: AbortSignal.timeout(this._timeoutMs),
      });
    } catch (e) {
      throw new EventStoreError('BACKEND_UNAVAILABLE', `ClickHouse request failed: ${e.name === 'TimeoutError' ? 'timed out' : e.message}`);
    }
    const text = await res.text();
    if (!res.ok) throw new EventStoreError('BACKEND_ERROR', `ClickHouse ${res.status}: ${text.slice(0, 300).replace(/\s+/g, ' ').trim()}`);
    return text;
  }

  async _rows(sql, opts = {}) {
    const text = await this._exec(sql, { ...opts, format: 'JSONEachRow', settings: { output_format_json_quote_64bit_integers: 0, ...READ_SETTINGS, ...(opts.settings || {}) } });
    return text ? text.split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  }

  // Creates the table if it is missing. Safe to run any number of times.
  async ensureSchema() { await this._exec(schemaSql(this._table)); }
  // Drops THIS store's table. Only for scratch tables (the backup's test restore): the live `events` table cannot be dropped through it.
  async dropTable() {
    if (this._table === 'events') throw new Error('refusing to drop the live events table');
    await this._exec(`DROP TABLE IF EXISTS ${this._table}`);
  }

  // Called once when the API starts (src/server.js): creates the table if it is missing, retrying while ClickHouse is still
  // coming up (a fresh install starts the API and the database together). Throws the last error once the attempts are used.
  // The database named in ASIX_CLICKHOUSE_URL must exist (the official image makes it from CLICKHOUSE_DB).
  async init() {
    const { attempts, delayMs } = this._initRetry;
    let last;
    for (let i = 1; i <= attempts; i++) {
      try { await this.ensureSchema(); await this._warnIfNotDaily(); return; }
      catch (e) { last = e; if (i < attempts) await new Promise((r) => setTimeout(r, delayMs)); }
    }
    throw last;
  }

  // A table made by hand with another partition key still works, but whole-day retention only drops days that are
  // partitions of the form YYYYMMDD, so it would drop nothing from it. Say so once at start instead of failing silently.
  async _warnIfNotDaily() {
    try {
      const rows = await this._rows('SELECT partition_key FROM system.tables WHERE database = {d:String} AND name = {tb:String}', { params: { d: this.conn.database, tb: this._table } });
      const key = rows[0] ? String(rows[0].partition_key) : null;
      if (key !== null && key !== 'toYYYYMMDD(received_at)') {
        console.warn(`[events] ClickHouse table ${this._table} is partitioned by "${key}", not by day: whole-day partition retention will not drop anything from it (row deletes still work)`);
      }
    } catch { /* only a courtesy check */ }
  }

  async _insert(tenant, envelopes) {
    const now = new Date().toISOString();
    const keyOf = (id, receivedIso) => `${id}|${receivedIso}`;

    // 1. stamp received_at where the caller left it out, and drop repeats inside this batch
    const batch = [];
    const inBatch = new Set();
    for (const e of envelopes) {
      const received_at = e.received_at || now;
      const k = keyOf(e.id, received_at);
      if (inBatch.has(k)) continue;
      inBatch.add(k);
      batch.push({ ...e, received_at });
    }

    // 2. which of those (id, received_at) pairs are already stored?
    //    ids and times are validated (UUID / ISO), so they are safe to write into the statement
    const lo = batch.reduce((m, e) => (e.received_at < m ? e.received_at : m), batch[0].received_at);
    const hi = batch.reduce((m, e) => (e.received_at > m ? e.received_at : m), batch[0].received_at);
    const idList = [...new Set(batch.map((e) => e.id))].map((id) => {
      if (!UUID_RE.test(id)) throw new EventStoreError('INVALID_BATCH', 'event id is not a UUID');
      return `'${id}'`;
    }).join(',');
    const existing = await this._rows(
      `SELECT id, received_at FROM ${this._table} FINAL
       WHERE tenant_id = {t:UUID} AND received_at >= {lo:DateTime64(3, 'UTC')} AND received_at <= {hi:DateTime64(3, 'UTC')}
         AND id IN (${idList})`,
      { params: { t: tenant, lo: chTime(lo), hi: chTime(hi) } });
    const have = new Set(existing.map((r) => keyOf(r.id, isoTime(r.received_at))));
    const fresh = batch.filter((e) => !have.has(keyOf(e.id, e.received_at)));
    if (!fresh.length) return { inserted: 0 };

    // 3. insert only the new rows (one statement; the base class already validated every event)
    const body = fresh.map((e) => JSON.stringify({
      id: e.id,
      tenant_id: e.tenant_id,
      source_type: e.source_type,
      collector_id: e.collector_id,
      received_at: chTime(e.received_at),
      event_time: chTime(e.event_time),
      raw: e.raw,
      parsed: JSON.stringify(e.parsed || {}),
    })).join('\n');
    await this._exec(
      `INSERT INTO ${this._table} (id, tenant_id, source_type, collector_id, received_at, event_time, raw, parsed) FORMAT JSONEachRow`,
      { body, settings: { date_time_input_format: 'basic' } });
    return { inserted: fresh.length };
  }

  async _getByIds(tenant, ids) {
    const list = ids.map((id) => {
      if (!UUID_RE.test(id)) throw new EventStoreError('INVALID_QUERY', 'ids must be UUIDs');
      return `'${id}'`;
    }).join(',');
    const rows = await this._rows(
      `SELECT ${COLUMNS} FROM ${this._table} FINAL WHERE tenant_id = {t:UUID} AND id IN (${list})`,
      { params: { t: tenant } });
    return rows.map(rowToEnvelope);
  }

  // Shared WHERE builder for scan() and count(). Returns SQL fragments and the parameters they use.
  _where(tenant, f) {
    const params = { t: tenant };
    const where = ['tenant_id = {t:UUID}'];
    if (f.since) { params.since = chTime(f.since); where.push("received_at >= {since:DateTime64(3, 'UTC')}"); }
    if (f.until) { params.until = chTime(f.until); where.push("received_at < {until:DateTime64(3, 'UTC')}"); }
    if (f.source_type) { params.st = f.source_type; where.push('source_type = {st:String}'); }
    if (f.collector_id) { params.cid = f.collector_id; where.push('collector_id = {cid:String}'); }
    return { params, where };
  }

  async _scan(tenant, q) {
    const { params, where } = this._where(tenant, q);
    const dir = q.order === 'desc' ? 'DESC' : 'ASC';
    if (q.after) {
      params.after_ts = cursorTime(q.after.ts);
      params.after_id = q.after.id;
      // ties are ordered by the id as TEXT: ClickHouse's own UUID order is not the hex-string order the contract (and
      // the other adapters) use, so comparing UUIDs made paging order differ from the other engines
      where.push(`(received_at, toString(id)) ${q.order === 'desc' ? '<' : '>'} ({after_ts:DateTime64(3, 'UTC')}, {after_id:String})`);
    }
    const limit = Number(q.limit);
    if (!Number.isInteger(limit) || limit < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    const rows = await this._rows(
      `SELECT ${COLUMNS} FROM ${this._table} FINAL WHERE ${where.join(' AND ')} ORDER BY received_at ${dir}, toString(id) ${dir} LIMIT ${limit}`,
      { params });
    return rows.map((row) => ({ event: rowToEnvelope(row), cursorTs: row.received_at }));
  }

  async _count(tenant, f) {
    const { params, where } = this._where(tenant, f);
    const rows = await this._rows(`SELECT count() AS n FROM ${this._table} FINAL WHERE ${where.join(' AND ')}`, { params });
    return Number(rows[0] ? rows[0].n : 0);
  }

  async _sourceTypes(tenant, { since, limit }) {
    const { params, where } = this._where(tenant, { since });
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    const rows = await this._rows(
      `SELECT DISTINCT source_type FROM ${this._table} WHERE ${where.join(' AND ')} ORDER BY source_type LIMIT ${n}`,
      { params });
    return rows.map((r) => r.source_type);
  }

  // The newest events first (event time, else received time). `q` is a literal substring: % and _ are escaped.
  async _listEvents(tenant, q) {
    const params = { t: tenant };
    const where = ['tenant_id = {t:UUID}'];
    if (q.source_type) { params.st = q.source_type; where.push('source_type = {st:String}'); }
    if (q.collector_id) { params.cid = q.collector_id; where.push('collector_id = {cid:String}'); }
    if (q.from) { params.from = chTime(q.from); where.push("coalesce(event_time, received_at) >= {from:DateTime64(3, 'UTC')}"); }
    if (q.to) { params.to = chTime(q.to); where.push("coalesce(event_time, received_at) <= {to:DateTime64(3, 'UTC')}"); }
    if (q.q) { params.q = '%' + q.q.replace(/[\\%_]/g, '\\$&') + '%'; where.push('ifNull(ilike(raw, {q:String}), 0)'); }
    const limit = Number(q.limit); const offset = Number(q.offset);
    if (!Number.isInteger(limit) || limit < 1 || !Number.isInteger(offset) || offset < 0) throw new EventStoreError('INVALID_QUERY', 'limit and offset must be whole numbers');
    const rows = await this._rows(
      `SELECT ${COLUMNS} FROM ${this._table} FINAL WHERE ${where.join(' AND ')}
       ORDER BY coalesce(event_time, received_at) DESC, toString(id) DESC LIMIT ${limit} OFFSET ${offset}`, { params });
    return rows.map(rowToEnvelope);
  }

  async _dataSources(tenant, { recentSince, limit }) {
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    const rows = await this._rows(
      `SELECT toString(source_type) AS st, collector_id AS cid, count() AS total,
              countIf(coalesce(event_time, received_at) > {since:DateTime64(3, 'UTC')}) AS recent, max(received_at) AS hi
       FROM ${this._table} FINAL WHERE tenant_id = {t:UUID} GROUP BY st, cid
       ORDER BY hi DESC, st ASC, cid ASC NULLS LAST LIMIT ${n}`, { params: { t: tenant, since: chTime(recentSince) } });
    return rows.map((r) => ({ source_type: r.st, collector_id: r.cid === undefined ? null : r.cid, events_total: Number(r.total), events_recent: Number(r.recent), last_received: isoTime(r.hi) }));
  }

  // length(raw) on a ClickHouse String is its size in bytes (the same as PostgreSQL's octet_length); uniqExact skips NULLs.
  async _ingestionStats(tenant, { by, groups, since, recent, hourFrom }) {
    const key = by === 'collector_id' ? "ifNull(toString(collector_id), '(none)')" : 'toString(source_type)';   // fixed list, never input
    const n = Number(groups);
    if (!Number.isInteger(n) || n < 1) throw new EventStoreError('INVALID_QUERY', 'groups must be a whole number of at least 1');
    const ts = 'coalesce(event_time, received_at)';
    const params = { t: tenant, since: chTime(since), recent: chTime(recent), hf: chTime(hourFrom) };
    const [t] = await this._rows(
      `SELECT count() AS events, sum(length(raw)) AS bytes, countIf(received_at > {recent:DateTime64(3, 'UTC')}) AS events_1h,
              uniqExact(source_type) AS source_types, uniqExact(collector_id) AS collectors, maxOrNull(received_at) AS last
       FROM ${this._table} FINAL WHERE tenant_id = {t:UUID} AND ${ts} > {since:DateTime64(3, 'UTC')}`, { params });
    const hours = await this._rows(
      `SELECT toString(toStartOfHour(${ts})) AS h, count() AS n FROM ${this._table} FINAL
       WHERE tenant_id = {t:UUID} AND ${ts} >= {hf:DateTime64(3, 'UTC')} GROUP BY h`, { params });
    const g = await this._rows(
      `SELECT ${key} AS k, count() AS n, sum(length(raw)) AS b FROM ${this._table} FINAL
       WHERE tenant_id = {t:UUID} AND ${ts} > {since:DateTime64(3, 'UTC')} GROUP BY k ORDER BY n DESC, k ASC LIMIT ${n}`, { params });
    return {
      totals: { events: t.events, bytes: t.bytes, events_1h: t.events_1h, source_types: t.source_types, collectors: t.collectors, last_received: isoTime(t.last) },
      hours: hours.map((x) => ({ hour: isoTime(x.h), n: Number(x.n) })),
      groups: g.map((x) => ({ key: x.k, events: Number(x.n), bytes: Number(x.b) })),
    };
  }


  // Counts, then deletes with a lightweight DELETE that completes before it returns
  // (lightweight_deletes_sync=2), so a count taken right afterwards is already correct. Dropping
  // whole daily partitions is still the retention job's cheaper path for large tables.
  async _deleteBefore(tenant, cutoff) {
    const params = { t: tenant, c: chTime(cutoff) };
    const rows = await this._rows(
      `SELECT count() AS n FROM ${this._table} FINAL WHERE tenant_id = {t:UUID} AND received_at < {c:DateTime64(3, 'UTC')}`, { params });
    const deleted = Number(rows[0] ? rows[0].n : 0);
    if (deleted) {
      await this._exec(
        `DELETE FROM ${this._table} WHERE tenant_id = {t:UUID} AND received_at < {c:DateTime64(3, 'UTC')}`,
        { params, settings: { lightweight_deletes_sync: 2 } });
    }
    return { deleted };
  }

  // Retention. The policy differs per source type, so these work source type by source type with scalar query parameters
  // (no array parameters to escape): first the source types that have anything older than the shortest retention (and the
  // oldest event of each), then one count per source type that really has expired events against its own cut-off.
  // At most MAX_GROUPS (1,000) source types are looked at in one call; deleteExpired says `truncated` if there were more.
  async _expiredCandidates(tenant, policy, nowMs) {
    return this._rows(
      `SELECT source_type, min(received_at) AS lo FROM ${this._table} FINAL
       WHERE tenant_id = {t:UUID} AND received_at < {c:DateTime64(3, 'UTC')} GROUP BY source_type ORDER BY source_type LIMIT ${MAX_GROUPS}`,
      { params: { t: tenant, c: chTime(cutoffIso(nowMs, shortestDays(policy))) } });
  }

  // Count of one source type's events older than `cutoff` (ISO), with the oldest one.
  async _expiredOf(tenant, sourceType, cutoff) {
    const rows = await this._rows(
      `SELECT count() AS n, min(received_at) AS lo FROM ${this._table} FINAL
       WHERE tenant_id = {t:UUID} AND source_type = {s:String} AND received_at < {c:DateTime64(3, 'UTC')}`,
      { params: { t: tenant, s: sourceType, c: chTime(cutoff) } });
    return { n: Number(rows[0] ? rows[0].n : 0), oldest: rows[0] && Number(rows[0].n) ? isoTime(rows[0].lo) : null };
  }

  async _expiredCounts(tenant, policy, { now }) {
    const nowMs = Date.parse(now);
    const out = [];
    for (const c of await this._expiredCandidates(tenant, policy, nowMs)) {
      const days = daysFor(policy, c.source_type);
      if (days === null) continue;
      const cutoff = cutoffIso(nowMs, days);
      if (!(Date.parse(isoTime(c.lo)) < Date.parse(cutoff))) continue;
      const r = await this._expiredOf(tenant, c.source_type, cutoff);
      if (r.n) out.push({ source_type: c.source_type, events: r.n, oldest: r.oldest });
    }
    return out;
  }

  // One lightweight DELETE per source type that has expired events (it completes before it returns, as in _deleteBefore),
  // after counting them for the report. Whole-partition DROP / table TTL are the cheaper path for big tables and are not used yet.
  async _deleteExpired(tenant, policy, { now, deadline }) {
    const nowMs = Date.parse(now);
    const candidates = await this._expiredCandidates(tenant, policy, nowMs);
    const by_source = {}; let deleted = 0; let truncated = candidates.length >= MAX_GROUPS;
    for (const c of candidates) {
      const days = daysFor(policy, c.source_type);
      if (days === null) continue;
      const cutoff = cutoffIso(nowMs, days);
      if (!(Date.parse(isoTime(c.lo)) < Date.parse(cutoff))) continue;
      if (deadline !== null && Date.now() > deadline) { truncated = true; break; }
      const { n } = await this._expiredOf(tenant, c.source_type, cutoff);
      if (!n) continue;
      await this._exec(
        `DELETE FROM ${this._table} WHERE tenant_id = {t:UUID} AND source_type = {s:String} AND received_at < {c:DateTime64(3, 'UTC')}`,
        { params: { t: tenant, s: c.source_type, c: chTime(cutoff) }, settings: { lightweight_deletes_sync: 2 } });
      by_source[c.source_type] = n; deleted += n;
    }
    return { deleted, by_source, truncated };
  }

  // One partition per UTC day (PARTITION BY toYYYYMMDD(received_at)), read from system.parts. Row counts include rows that
  // lightweight deletes have hidden but a merge has not yet removed, so they can run a little high after a purge.
  async _storageStats() {
    const parts = await this._rows(
      `SELECT partition AS p, sum(rows) AS rows, sum(bytes_on_disk) AS bytes FROM system.parts
       WHERE database = {d:String} AND table = {tb:String} AND active GROUP BY partition ORDER BY partition DESC`,
      { params: { d: this.conn.database, tb: this._table } });
    const partitions = parts.filter((r) => /^\d{8}$/.test(String(r.p))).map((r) => {
      const day = `${String(r.p).slice(0, 4)}-${String(r.p).slice(4, 6)}-${String(r.p).slice(6, 8)}`;
      return { name: String(r.p), from: day, to: new Date(Date.parse(`${day}T00:00:00Z`) + 86400000).toISOString().slice(0, 10), rows: Number(r.rows), bytes: Number(r.bytes) };
    });
    return { partitioned: true, events_rows: partitions.reduce((n, p) => n + p.rows, 0), events_bytes: partitions.reduce((n, p) => n + p.bytes, 0), default_partition_rows: 0, partitions };
  }

  // ALTER TABLE ... DROP PARTITION ID per day, oldest first. ClickHouse refuses to drop a partition above its
  // max_partition_size_to_drop (50 GB by default, a server setting); that one lands in `failed` and the next days still go.
  async _dropPartitionsBefore(day) {
    const dropped = []; const failed = [];
    const { partitions } = await this._storageStats();
    for (const p of partitions.filter((x) => x.to <= day).sort((a, b) => (a.from < b.from ? -1 : 1))) {
      try { await this._exec(`ALTER TABLE ${this._table} DROP PARTITION ID '${p.name}'`); dropped.push(p.name); } catch (e) { failed.push({ name: p.name, error: e.message }); }
    }
    return { dropped, failed };
  }

  // Counts per collector / source type / UTC day. The key expression comes from a fixed list; the column is a
  // DateTime64 in UTC, so toDate() is the UTC day. Aliases (k, n, lo, hi) are chosen not to shadow a column.
  async _groupCounts(tenant, { by, since, until, limit }) {
    const { params, where } = this._where(tenant, { since, until });
    const key = { collector_id: 'collector_id', source_type: 'source_type', day: 'toString(toDate(received_at))' }[by];
    if (by === 'collector_id') where.push('collector_id IS NOT NULL');
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    const order = by === 'day' ? 'k ASC' : 'n DESC, k ASC';
    const rows = await this._rows(
      `SELECT ${key} AS k, count() AS n, min(received_at) AS lo, max(received_at) AS hi
       FROM ${this._table} FINAL WHERE ${where.join(' AND ')} GROUP BY k ORDER BY ${order} LIMIT ${n}`, { params });
    return rows.map((r) => ({ key: r.k, events: Number(r.n), first_seen: isoTime(r.lo), last_seen: isoTime(r.hi) }));
  }

  // minOrNull / maxOrNull: plain min() and max() of an empty set are 1970-01-01, not null.
  async _timeRange(tenant) {
    const rows = await this._rows(
      `SELECT minOrNull(received_at) AS lo, maxOrNull(received_at) AS hi FROM ${this._table} WHERE tenant_id = {t:UUID}`, { params: { t: tenant } });
    const r = rows[0] || {};
    return { oldest: isoTime(r.lo), newest: isoTime(r.hi) };
  }

  // Ties on received_at are ordered by the id as text, like scan() (see "Paging order on ClickHouse" in docs/event-store.md).
  async _fieldKeys(tenant, { limit }) {
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    const rows = await this._rows(
      `SELECT k, count() AS n FROM (
         SELECT arrayJoin(JSONExtractKeys(parsed)) AS k FROM (
           SELECT parsed FROM ${this._table} FINAL WHERE tenant_id = {t:UUID} ORDER BY received_at DESC, toString(id) DESC LIMIT ${n}))
       GROUP BY k ORDER BY n DESC, k ASC LIMIT 200`, { params: { t: tenant } });
    return rows.map((r) => ({ name: r.k, events: Number(r.n) }));
  }

  async _xdmSamples(tenant, { limit }) {
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1) throw new EventStoreError('INVALID_QUERY', 'limit must be a whole number of at least 1');
    const rows = await this._rows(
      `SELECT JSONExtractRaw(parsed, 'xdm') AS x FROM ${this._table} FINAL
       WHERE tenant_id = {t:UUID} AND JSONType(parsed, 'xdm') = 'Object'
       ORDER BY received_at DESC, toString(id) DESC LIMIT ${n}`, { params: { t: tenant } });
    const out = [];
    for (const r of rows) { try { const o = JSON.parse(r.x); if (o && typeof o === 'object' && !Array.isArray(o)) out.push(o); } catch (_) { /* skip an unreadable document */ } }
    return out;
  }

  // An XQL plan becomes ClickHouse SQL (src/search/xql-clickhouse.js); every value is a query parameter.
  async _search(tenant, plan) {
    const q = toClickHouse(plan, tenant, this._table);
    const rows = await this._rows(q.sql, { params: q.params });
    return rows.map((r) => {
      const out = Object.fromEntries(q.columns.map(({ c, name }) => [name, r[c] === undefined ? null : r[c]]));   // not out[name] =: __proto__
      if (q.mode === 'raw') {
        out._time = new Date(isoTime(out._time));
        try { out.parsed = out.parsed ? JSON.parse(out.parsed) : {}; } catch (_) { out.parsed = {}; }
      }
      return out;
    });
  }

  // A rule match spec becomes ClickHouse SQL (src/search/xql-clickhouse.js matchToClickHouse).
  async _matchGroups(tenant, spec) {
    const q = matchToClickHouse(spec, tenant, this._table);
    const rows = await this._rows(q.sql, { params: q.params });
    return rows.map((r) => ({ key: r.c0, n: Number(r.c1), first_at: isoTime(r.c2), last_at: isoTime(r.c3), sample_ids: r.c4 || [], sample_raw: r.c5 }));
  }

  async close() { this._conn = null; }
}

module.exports = { ClickHouseEventStore, schemaSql, rowToEnvelope };
