'use strict';
// In-memory adapter. It exists for two reasons: it lets the conformance suite run in CI with no
// database (so the contract itself is tested on every push), and it is a readable reference for
// anyone writing a new adapter. It keeps everything in process memory, so it is for tests and
// local experiments only; src/events/index.js refuses to use it when NODE_ENV=production.

const { EventStore } = require('./event-store');
const { runPlan } = require('../search/xql-eval');

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const clone = (v) => structuredClone(v);

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

  async _count(tenant, f) { return this._filter(tenant, f).length; }

  async _sourceTypes(tenant, { since, limit }) {
    return [...new Set(this._filter(tenant, { since }).map((e) => e.source_type))].sort().slice(0, limit);
  }

  async _deleteBefore(tenant, cutoff) {
    const rows = this._rows(tenant);
    const keep = rows.filter((e) => e.received_at >= cutoff);
    const deleted = rows.length - keep.length;
    this.tenants.set(tenant, keep);
    return { deleted };
  }
}

module.exports = { MemoryEventStore };
