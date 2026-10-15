'use strict';
// The collectors list and /v1/search/fields read their counts through the event store. This runs the real routes on the
// in-memory store (no database), with only the sign-in chain and the `collectors` table query replaced.
// tests/read-counts-db.test.js (ASIX_TEST_DB=1) holds the same routes to the SQL they replaced, on real Postgres.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');

const TENANT = crypto.randomUUID();
let registered = [];                                           // what the `collectors` table query returns
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared,
  guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
  db: { withTenant: async (t, fn) => fn({ query: async () => ({ rows: registered }) }) },
};
const collectorRoutes = require('../src/gateway/routes/collectors');
const searchRoutes = require('../src/gateway/routes/search');
const { setEventStore, getEventStore } = require('../src/events');
const { MemoryEventStore } = require('../src/events/memory-store');

const ago = (ms) => new Date(Date.now() - ms).toISOString();
const MIN = 60000; const HOUR = 3600000; const DAY = 86400000;
const ev = (collector, source, age, parsed = {}) => ({ source_type: source, collector_id: collector, raw: 'r', parsed, received_at: ago(age) });

describe('collectors list and search fields read through the event store', () => {
  let srv; let base;
  const get = async (path) => { const r = await fetch(base + path); return { status: r.status, body: await r.json() }; };
  before(async () => {
    setEventStore(new MemoryEventStore());
    await getEventStore().insertBatch(TENANT, [
      ev('broker-1', 'syslog', 2 * MIN), ev('broker-1', 'syslog', 3 * HOUR), ev('broker-1', 'syslog', 3 * DAY),     // keyed sender
      ev('vm1-syslog', 'syslog', 10 * MIN), ev('vm1-syslog', 'syslog', 2 * DAY),                                       // key-less heartbeat row
      ev('orphan', 'cloud', 5 * MIN),                                                                                  // only appears in events
      ev('old-c', 'syslog', 8 * DAY),                                                                                  // outside the 7 day window
      ev(null, 'syslog', MIN, { host: 'h', xdm: { source: { ipv4: '1.2.3.4' } } }),                                    // no collector
    ]);
    registered = [
      { id: crypto.randomUUID(), name: 'broker-1', alias: 'Home broker', platform: 'broker', os: 'Ubuntu', version: '1.0', last_ip: '10.0.0.5', first_seen: ago(30 * DAY), last_seen: ago(MIN), events_total: '5000', installer: 'home', origin: 'registered' },
      { id: crypto.randomUUID(), name: 'vm1-syslog', alias: null, platform: 'linux', os: null, version: null, last_ip: null, first_seen: ago(40 * DAY), last_seen: ago(3 * DAY), events_total: '0', installer: null, origin: 'built-in' },
    ];
    const app = express(); app.use(express.json()); app.use(collectorRoutes); app.use(searchRoutes);
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { if (srv) srv.close(); setEventStore(null); });

  it('lists registered senders, key-less heartbeat rows and event-only senders, with counts from events', async () => {
    const { status, body } = await get('/v1/collectors');
    assert.strictEqual(status, 200);
    assert.deepStrictEqual(body.collectors.map((c) => c.name), ['broker-1', 'orphan', 'vm1-syslog']);   // old-c is outside 7 days; no-collector events are not a sender
    const by = Object.fromEntries(body.collectors.map((c) => [c.name, c]));
    // a keyed sender keeps its own row and total (the table's counter), and gets the 24 hour count from events
    assert.strictEqual(by['broker-1'].events_total, 5000); assert.strictEqual(by['broker-1'].events_24h, 2); assert.strictEqual(by['broker-1'].origin, 'registered');
    assert.strictEqual(by['broker-1'].alias, 'Home broker'); assert.strictEqual(by['broker-1'].status, 'connected');
    // a key-less row takes its counts and last_seen from the events, so an idle-but-alive source reads Connected
    assert.strictEqual(by['vm1-syslog'].events_total, 2); assert.strictEqual(by['vm1-syslog'].events_24h, 1); assert.strictEqual(by['vm1-syslog'].status, 'connected');
    assert.ok(Date.parse(by['vm1-syslog'].first_seen) <= Date.now() - 39 * DAY, 'keeps the earlier first_seen of the row');
    // an event-only sender is listed as built-in syslog
    assert.deepStrictEqual([by.orphan.origin, by.orphan.platform, by.orphan.events_total, by.orphan.events_24h, by.orphan.status, by.orphan.id], ['built-in', 'syslog', 1, 1, 'connected', null]);
    assert.strictEqual(body.total, 3); assert.strictEqual(body.overall, 3);
  });

  it('filters by status and search text', async () => {
    registered[1].last_seen = ago(3 * DAY);
    assert.deepStrictEqual((await get('/v1/collectors?q=home')).body.collectors.map((c) => c.name), ['broker-1']);
    assert.strictEqual((await get('/v1/collectors?status=disconnected')).body.total, 0);
  });

  it('search fields: top-level keys, xdm paths, and datasets of the last 7 days', async () => {
    const { status, body } = await get('/v1/search/fields');
    assert.strictEqual(status, 200); assert.strictEqual(body.sampled_events, 2000);
    assert.deepStrictEqual(body.fields, [{ name: 'host', events: 1 }, { name: 'xdm', events: 1 }, { name: 'xdm.source.ipv4', events: 1 }]);
    assert.deepStrictEqual(body.datasets.map((d) => [d.name, d.events]), [['syslog', 6], ['cloud', 1]]);
    assert.ok(body.datasets.every((d) => /^\d{4}-\d{2}-\d{2}T.*Z$/.test(d.last_seen)));
  });

  it('an unreadable store is a 500 with the old error code', async () => {
    const real = getEventStore(); const broken = new MemoryEventStore();
    broken._fieldKeys = async () => { throw new Error('boom'); };
    setEventStore(broken);
    const { status, body } = await get('/v1/search/fields');
    setEventStore(real);
    assert.strictEqual(status, 500); assert.strictEqual(body.error.code, 'FIELDS_ERROR');
  });
});
