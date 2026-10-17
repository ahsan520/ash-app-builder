'use strict';
// Needs a real Postgres with the platform schema (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node --test tests/parser-status-db.test.js
// Skips itself otherwise. The unparsed-event count on a real events table, through the real route.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const db = require('../src/db');

let TENANT;
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const { getEventStore } = require('../src/events');
const poolMod = require('../src/ingestion/parser-pool');

const MIN = 60000, HOUR = 3600000;
const ev = (age, parsed) => ({ source_type: 'syslog', collector_id: null, raw: 'line', parsed, received_at: new Date(Date.now() - age).toISOString() });

describe('parser status on PostgreSQL', () => {
  let srv, base, other;
  const get = async (q = '') => { const r = await fetch(base + '/v1/parser/status' + q); return { status: r.status, body: await r.json() }; };
  before(async () => {
    poolMod.setParserPool(null);
    TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['parser-status-' + Date.now()])).rows[0].id;
    other = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['parser-status-o-' + Date.now()])).rows[0].id;
    await getEventStore().insertBatch(TENANT, [
      ev(5 * MIN, { _parse_error: 'PARSE_TIMEOUT' }), ev(6 * MIN, { _parse_error: 'PARSE_TIMEOUT' }), ev(7 * MIN, { _parse_error: 'PARSE_WORKER_CRASH' }),
      ev(8 * MIN, { host: 'fine' }), ev(9 * MIN, {}), ev(30 * HOUR, { _parse_error: 'PARSE_FAILED' }),
    ]);
    await getEventStore().insertBatch(other, [ev(5 * MIN, { _parse_error: 'PARSE_QUARANTINED' })]);
    const app = express(); app.use(require('../src/gateway/routes/parser-status'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(async () => {
    srv.close();
    for (const t of [TENANT, other]) await db.query('DELETE FROM events WHERE tenant_id = $1', [t]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, other]]).catch(() => {});
    await db.pool.end().catch(() => {});
  });

  it('counts the unparsed events of this tenant by reason, inside the window', async () => {
    const r = await get();
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.unparsed.total, 3);
    assert.deepStrictEqual(r.body.unparsed.by_reason, { PARSE_TIMEOUT: 2, PARSE_WORKER_CRASH: 1, PARSE_FAILED: 0, PARSE_QUARANTINED: 0 });
    assert.strictEqual(r.body.settings.mode, 'inline');
  });
  it('a wider window includes older ones, and another tenant\'s events never show', async () => {
    const r = await get('?hours=72');
    assert.strictEqual(r.body.unparsed.total, 4); assert.strictEqual(r.body.unparsed.by_reason.PARSE_FAILED, 1); assert.strictEqual(r.body.unparsed.by_reason.PARSE_QUARANTINED, 0);
  });
});
