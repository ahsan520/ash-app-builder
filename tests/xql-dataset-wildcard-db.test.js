'use strict';
// Wildcard dataset names against the real PostgreSQL event store (the same checks as the in-memory ones in tests/xql-dataset-wildcard.test.js):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/xql-dataset-wildcard-db.test.js
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
const assert = require('assert');
const db = require('../src/db');
const xql = require('../src/search/xql');
const { PostgresEventStore } = require('../src/events/postgres-store');

async function main() {
  const stamp = Date.now();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['xql-glob-a-' + stamp])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['xql-glob-b-' + stamp])).rows[0].id;
  const store = new PostgresEventStore({ db });
  const TYPES = ['syslog', 'endpoint-alert', 'endpoint_other', 'endpointx', 'windows-event', 'wineventlog', 'cloud', 'My_Type%', 'a.b'];
  const now = Date.now(); const opts = { from: new Date(now - 3600000).toISOString(), to: new Date(now + 60000).toISOString() };
  try {
    await store.insertBatch(A, TYPES.map((t, i) => ({ source_type: t, collector_id: 'c', raw: t, parsed: { host: 'h' }, received_at: new Date(now - i * 1000).toISOString() })));
    await store.insertBatch(B, [{ source_type: 'endpoint-alert', collector_id: 'c', raw: 'other tenant', parsed: {}, received_at: new Date(now).toISOString() }]);
    const run = async (q) => (await store.search(A, xql.parse(q, opts))).rows.map((r) => r.source_type).sort();
    assert.deepStrictEqual(await run('dataset = *'), [...TYPES].sort(), 'dataset = * : every event of this tenant only');
    assert.deepStrictEqual(await run('dataset = endpoint*'), ['endpoint-alert', 'endpoint_other', 'endpointx']);
    assert.deepStrictEqual(await run('dataset = *event*'), ['windows-event', 'wineventlog']);
    assert.deepStrictEqual(await run('dataset = win*-event'), ['windows-event']);
    assert.deepStrictEqual(await run('dataset in (cloud, endpoint-*)'), ['cloud', 'endpoint-alert']);
    assert.deepStrictEqual(await run('dataset = "My_Type%"'), ['My_Type%'], 'LIKE characters in a name are literal');
    assert.deepStrictEqual(await run('dataset = "My_*"'), ['My_Type%']);
    assert.deepStrictEqual(await run('dataset = "a.*"'), ['a.b']);
    assert.deepStrictEqual(await run('dataset = "My%"'), [], '% is not a wildcard');
    assert.deepStrictEqual(await run('dataset = "My_Typ_*"'), [], '_ is not a wildcard');
    assert.deepStrictEqual(await run('dataset = syslog'), ['syslog']);
    assert.deepStrictEqual(await run('dataset = nothing*'), []);
    assert.deepStrictEqual(await run('dataset = endpoint* | filter host = "h"'), ['endpoint-alert', 'endpoint_other', 'endpointx'], 'with a filter stage after it');
    const comp = await store.search(A, xql.parse('dataset = endpoint* | comp count() as n by source_type', opts));
    assert.strictEqual(comp.rows.length, 3, 'with comp');
    console.log('xql-dataset-wildcard-db: all checks passed');
  } finally {
    for (const t of [A, B]) await store.deleteBefore(t, '2999-01-01T00:00:00Z');
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[A, B]]);
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
