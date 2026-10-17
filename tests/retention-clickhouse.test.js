'use strict';
// The retention job with events in ClickHouse and the control-plane data (tenants, retention policy, run log) in PostgreSQL.
// Needs both, plus the platform schema in Postgres (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... ASIX_CLICKHOUSE_URL=http://default@127.0.0.1:8123/asix node --test tests/retention-clickhouse.test.js
// Skips itself otherwise. It proves that preview, manual purge and the scheduled run work on the other engine, and that the
// PostgreSQL-only housekeeping (daily partitions, partition drop) is skipped instead of touching the wrong table.
// The events go to a throwaway table (events_test_<random>), dropped at the end.
if (!process.env.ASIX_TEST_DB || !process.env.ASIX_CLICKHOUSE_URL) { console.log('skipped (set ASIX_TEST_DB=1 and ASIX_CLICKHOUSE_URL to run against Postgres and ClickHouse)'); process.exit(0); }
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const db = require('../src/db');
const storage = require('../src/storage/retention');
const { setEventStore } = require('../src/events');
const { ClickHouseEventStore } = require('../src/events/clickhouse-store');

const DAY = 86400000;
const ev = (source, daysAgo) => ({ source_type: source, collector_id: 'ret-ch', raw: `${source} ${daysAgo}d`, parsed: {}, received_at: new Date(Date.now() - daysAgo * DAY).toISOString() });

describe('retention job on ClickHouse', () => {
  let T; let store; let table;
  const left = (source) => store.count(T, { source_type: source });

  before(async () => {
    table = `events_test_${crypto.randomBytes(6).toString('hex')}`;
    store = new ClickHouseEventStore({ table });
    await store.ensureSchema();
    setEventStore(store);
    T = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['retention-ch-' + Date.now()])).rows[0].id;
    await db.query('INSERT INTO retention_settings (tenant_id, auto_purge, default_days) VALUES ($1, false, 30)', [T]);
    await db.query('INSERT INTO retention_policies (tenant_id, source_type, retention_days) VALUES ($1, $2, 7), ($1, $3, NULL)', [T, 'c-short', 'c-forever']);
    await store.insertBatch(T, [
      ev('c-default', 40), ev('c-default', 31), ev('c-default', 29), ev('c-default', 1),
      ev('c-short', 8), ev('c-short', 6), ev('c-forever', 3000),
    ]);
  });
  after(async () => {
    for (const tbl of ['retention_runs', 'retention_policies', 'retention_settings']) await db.query(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [T]);
    await db.query('DELETE FROM tenants WHERE id = $1', [T]);
    await store._exec(`DROP TABLE IF EXISTS ${table}`);
    await store.close();
    await db.close();
  });

  it('the preview counts what is past its retention per source and deletes nothing', async () => {
    const r = await storage.runManual(T, { dryRun: true });
    assert.strictEqual(r.dry_run, true);
    assert.strictEqual(r.total, 3);
    assert.deepStrictEqual(r.by_source.map((x) => [x.source_type, x.events]), [['c-default', 2], ['c-short', 1]]);
    assert.strictEqual(await left('c-default'), 4);
  });

  it('a manual purge deletes exactly that, keeps "forever", and logs the run', async () => {
    const r = await storage.runManual(T, { dryRun: false });
    assert.strictEqual(r.rows_deleted, 3);
    assert.deepStrictEqual(r.by_source, { 'c-default': 2, 'c-short': 1 });
    assert.strictEqual(r.truncated, false);
    assert.strictEqual(r.partitions_scanned, undefined, 'a Postgres detail that does not exist here');
    assert.strictEqual(await left('c-default'), 2);
    assert.strictEqual(await left('c-short'), 1);
    assert.strictEqual(await left('c-forever'), 1);
    const run = (await db.query('SELECT status, rows_deleted::int AS n FROM retention_runs WHERE id = $1', [r.run_id])).rows[0];
    assert.deepStrictEqual([run.status, run.n], ['completed', 3]);
  });

  it('the scheduled run purges, and skips the PostgreSQL partition work', async () => {
    await db.query('UPDATE retention_settings SET auto_purge = true WHERE tenant_id = $1', [T]);
    await store.insertBatch(T, [ev('c-default', 60), ev('c-short', 20)]);
    const out = await storage.runScheduled();
    assert.ok(!out.busy);
    assert.strictEqual(out.errors, 0);
    assert.deepStrictEqual(out.partitions, { partitioned: false, created: [] });
    assert.deepStrictEqual(out.dropped, []);
    assert.strictEqual(await left('c-default'), 2);
    assert.strictEqual(await left('c-short'), 1);
  });
});
