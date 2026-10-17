'use strict';
// In-memory adapter. It exists for two reasons: it lets the conformance suite run in CI with no
// database (so the contract itself is tested on every push), and it is a readable reference for
// anyone writing a new adapter. It keeps everything in process memory, so it is for tests and
// local experiments only; src/events/index.js refuses to use it when NODE_ENV=production.

const { EventStore, daysFor, cutoffIso } = require('./event-store');
const { runPlan, runMatch } = require('../search/xql-eval');

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const clone = (v) => structuredClone(v);

const nextDay = (day) => new Date(Date.parse(`${day}T00:00:00Z`) + 86400000).toISOString().slice(0, 10);

class MemoryEventStore extends EventStore {
  constructor() { super(); this.tenants = new Map(); }
  get name() { return 'memory'; }

  _rows(tenant) {
    if (!this.tenants.has(tenant)) this.tenants.set(tenant, []);
    return this.tenants.get(tenant);
  }

  async _insert(tenant, envelopes) {
    const rows = this._rows(tenant);
    const seen = new Set(rows.map((e) => `${e.id}|${e.received_at}`));
    const now = new Date().toISOString();
    let inserted = 0;
    for (const e of envelopes) {
      const row = clone({ ...e, received_at: e.received_at || now });
      const key = `${row.id}|${row.received_at}`;
      if (seen.has(key)) continue; // same (id, received_at): already stored
      seen.add(key);
      rows.push(row);
      inserted++;
    }
    return { inserted };
  }

  async _getByIds(tenant, ids) {
    const wanted = new Set(ids);
    return this._rows(tenant).filter((e) => wanted.has(e.id)).map(clone);
  }

  _filter(tenant, f) {
    return this._rows(tenant).filter((e) =>
      (!f.since || e.received_at >= f.since) && (!f.until || e.received_at < f.until)
      && (!f.source_type || e.source_type === f.source_type)
      && (!f.collector_id || e.collector_id === f.collector_id));
  }

  async _scan(tenant, q) {
    const sign = q.order === 'desc' ? -1 : 1;
    let rows = this._filter(tenant, q).sort((a, b) => sign * (cmp(a.received_at, b.received_at) || cmp(a.id, b.id)));
    if (q.after) rows = rows.filter((e) => sign * (cmp(e.received_at, q.after.ts) || cmp(e.id, q.after.id)) > 0);
    return rows.slice(0, q.limit).map((e) => ({ event: clone(e), cursorTs: e.received_at }));
  }

  async _search(tenant, plan) { return clone(runPlan(plan, this._rows(tenant))); }
  async _matchGroups(tenant, spec) { return clone(runMatch(spec, this._rows(tenant))); }

  async _count(tenant, f) { return this._filter(tenant, f).length; }

  async _sourceTypes(tenant, { since, limit }) {
    return [...new Set(this._filter(tenant, { since }).map((e) => e.source_type))].sort().slice(0, limit);
  }

  async _groupCounts(tenant, { by, since, until, limit }) {
    const keyOf = (e) => (by === 'day' ? e.received_at.slice(0, 10) : e[by]);
    const groups = new Map();
    for (const e of this._filter(tenant, { since, until })) {
      const key = keyOf(e);
      if (key === null || key === undefined) continue;                        // no collector: not a group
      const g = groups.get(key) || { key, events: 0, first_seen: e.received_at, last_seen: e.received_at };
      g.events++;
      if (e.received_at < g.first_seen) g.first_seen = e.received_at;
      if (e.received_at > g.last_seen) g.last_seen = e.received_at;
      groups.set(key, g);
    }
    const rows = [...groups.values()];
    rows.sort(by === 'day' ? (a, b) => cmp(a.key, b.key) : (a, b) => (b.events - a.events) || cmp(a.key, b.key));
    return rows.slice(0, limit);
  }

  async _timeRange(tenant) {
    let oldest = null; let newest = null;
    for (const e of this._rows(tenant)) {
      if (oldest === null || e.received_at < oldest) oldest = e.received_at;
      if (newest === null || e.received_at > newest) newest = e.received_at;
    }
    return { oldest, newest };
  }

  _newest(tenant, limit, keep = () => true) {
    return this._rows(tenant).filter(keep).sort((a, b) => cmp(b.received_at, a.received_at) || cmp(b.id, a.id)).slice(0, limit);
  }

  async _fieldKeys(tenant, { limit }) {
    const counts = new Map();
    for (const e of this._newest(tenant, limit)) for (const k of Object.keys(e.parsed || {})) counts.set(k, (counts.get(k) || 0) + 1);
    return [...counts].map(([name, events]) => ({ name, events }));
  }

  async _xdmSamples(tenant, { limit }) {
    const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
    return this._newest(tenant, limit, (e) => isObj(e.parsed && e.parsed.xdm)).map((e) => clone(e.parsed.xdm));
  }

  async _listEvents(tenant, q) {
    const t = (e) => Date.parse(e.event_time || e.received_at);
    const from = q.from ? Date.parse(q.from) : null; const to = q.to ? Date.parse(q.to) : null;
    const needle = q.q ? q.q.toLowerCase() : null;
    const rows = this._rows(tenant).filter((e) =>
      (!q.source_type || e.source_type === q.source_type) && (!q.collector_id || e.collector_id === q.collector_id)
      && (from === null || t(e) >= from) && (to === null || t(e) <= to)
      && (needle === null || e.raw.toLowerCase().includes(needle)));
    rows.sort((a, b) => (t(b) - t(a)) || cmp(b.id, a.id));
    return clone(rows.slice(q.offset, q.offset + q.limit));
  }

  async _dataSources(tenant, { recentSince, limit }) {
    const since = Date.parse(recentSince);
    const groups = new Map();
    for (const e of this._rows(tenant)) {
      const k = JSON.stringify([e.source_type, e.collector_id === undefined ? null : e.collector_id]);
      const g = groups.get(k) || { source_type: e.source_type, collector_id: e.collector_id === undefined ? null : e.collector_id, events_total: 0, events_recent: 0, last_received: e.received_at };
      g.events_total++;
      if (Date.parse(e.event_time || e.received_at) > since) g.events_recent++;
      if (e.received_at > g.last_received) g.last_received = e.received_at;
      groups.set(k, g);
    }
    const nullLast = (a, b) => (a === null ? (b === null ? 0 : 1) : b === null ? -1 : cmp(a, b));
    return [...groups.values()].sort((a, b) => cmp(b.last_received, a.last_received) || cmp(a.source_type, b.source_type) || nullLast(a.collector_id, b.collector_id)).slice(0, limit);
  }

  async _ingestionStats(tenant, { by, groups, since, recent, hourFrom }) {
    const t = (e) => Date.parse(e.event_time || e.received_at);
    const inWindow = this._rows(tenant).filter((e) => t(e) > Date.parse(since));
    const hours = new Map();
    for (const e of this._rows(tenant)) {
      if (t(e) < Date.parse(hourFrom)) continue;
      const h = new Date(Math.floor(t(e) / 3600000) * 3600000).toISOString();
      hours.set(h, (hours.get(h) || 0) + 1);
    }
    const g = new Map();
    for (const e of inWindow) {
      const k = by === 'collector_id' ? (e.collector_id === null || e.collector_id === undefined ? '(none)' : e.collector_id) : e.source_type;
      const x = g.get(k) || { key: k, events: 0, bytes: 0 };
      x.events++; x.bytes += Buffer.byteLength(e.raw, 'utf8'); g.set(k, x);
    }
    const lastReceived = inWindow.reduce((m, e) => (m === null || e.received_at > m ? e.received_at : m), null);
    return {
      totals: {
        events: inWindow.length, bytes: inWindow.reduce((n, e) => n + Buffer.byteLength(e.raw, 'utf8'), 0),
        events_1h: inWindow.filter((e) => e.received_at > recent).length,
        source_types: new Set(inWindow.map((e) => e.source_type)).size,
        collectors: new Set(inWindow.filter((e) => e.collector_id !== null && e.collector_id !== undefined).map((e) => e.collector_id)).size,
        last_received: lastReceived,
      },
      hours: [...hours].map(([hour, n]) => ({ hour, n })),
      groups: [...g.values()].sort((a, b) => (b.events - a.events) || cmp(a.key, b.key)).slice(0, groups),
    };
  }

  async _deleteBefore(tenant, cutoff) {
    const rows = this._rows(tenant);
    const keep = rows.filter((e) => e.received_at >= cutoff);
    const deleted = rows.length - keep.length;
    this.tenants.set(tenant, keep);
    return { deleted };
  }

  // The memory store has no partitions on disk; it reports one per UTC day so the same tests and pages work.
  async _storageStats() {
    const by = new Map();
    for (const rows of this.tenants.values()) {
      for (const e of rows) {
        const g = by.get(e.received_at.slice(0, 10)) || { rows: 0, bytes: 0 };
        g.rows += 1; g.bytes += e.raw.length + JSON.stringify(e.parsed).length;
        by.set(e.received_at.slice(0, 10), g);
      }
    }
    const partitions = [...by.entries()].sort((a, b) => (a[0] < b[0] ? 1 : -1)).map(([from, g]) => ({ name: from.replace(/-/g, ''), from, to: nextDay(from), rows: g.rows, bytes: g.bytes }));
    return { partitioned: true, events_rows: partitions.reduce((n, p) => n + p.rows, 0), events_bytes: partitions.reduce((n, p) => n + p.bytes, 0), default_partition_rows: 0, partitions };
  }

  async _dropPartitionsBefore(day) {
    const gone = new Set();
    for (const [tenant, rows] of this.tenants) {
      const keep = rows.filter((e) => { const d = e.received_at.slice(0, 10); if (d < day) { gone.add(d); return false; } return true; });
      this.tenants.set(tenant, keep);
    }
    return { dropped: [...gone].sort().map((d) => d.replace(/-/g, '')), failed: [] };
  }

  // Events whose received_at is older than now minus the days that apply to their source type.
  _isExpired(policy, nowMs, e) {
    const days = daysFor(policy, e.source_type);
    return days !== null && e.received_at < cutoffIso(nowMs, days);
  }

  async _expiredCounts(tenant, policy, { now }) {
    const nowMs = Date.parse(now);
    const by = new Map();
    for (const e of this._rows(tenant)) {
      if (!this._isExpired(policy, nowMs, e)) continue;
      const g = by.get(e.source_type) || { source_type: e.source_type, events: 0, oldest: e.received_at };
      g.events += 1;
      if (e.received_at < g.oldest) g.oldest = e.received_at;
      by.set(e.source_type, g);
    }
    return [...by.values()];
  }

  async _deleteExpired(tenant, policy, { now, deadline }) {
    const nowMs = Date.parse(now);
    const rows = this._rows(tenant);
    if (deadline !== null && Date.now() > deadline) return { deleted: 0, by_source: {}, truncated: rows.some((e) => this._isExpired(policy, nowMs, e)) };
    const keep = []; const by_source = {}; let deleted = 0;
    for (const e of rows) {
      if (this._isExpired(policy, nowMs, e)) { deleted += 1; by_source[e.source_type] = (by_source[e.source_type] || 0) + 1; } else keep.push(e);
    }
    this.tenants.set(tenant, keep);
    return { deleted, by_source, truncated: false };
  }
}

module.exports = { MemoryEventStore };
