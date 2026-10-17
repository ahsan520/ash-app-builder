'use strict';
// Needs a real Postgres with the platform schema (k8s/12-schema-init.yaml's schema.sql), ideally a throwaway database:
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node --test tests/retention-db.test.js
// Skips itself otherwise. It runs the retention job end to end on the partitioned `events` table, now that the preview
// and the row purge go through the event store: the preview must equal the SQL it replaced (written out below as the
// oracle), a real purge must delete exactly what the preview counted (from daily partitions and from events_default),
// the scheduled run must purge only tenants that switched automatic purge on, and whole expired partitions are still dropped.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const db = require('../src/db');
const storage = require('../src/storage/retention');
const { getEventStore } = require('../src/events');

const DAY = 86400000;
const agoDays = (d, extraMs = 0) => new Date(Date.now() - d * DAY + extraMs).toISOString();
const dayOf = (iso) => iso.slice(0, 10);
const ev = (source, daysAgo) => ({ source_type: source, collector_id: 'ret-db', raw: `${source} ${daysAgo}d`, parsed: {}, received_at: agoDays(daysAgo) });

// the preview query as it was before the move behind the event store (retention.js, "preview")
async function oldPreview(tenantId, pol) {
  const minDays = Math.min(pol.default_days, ...pol.overrides.filter((o) => o.retention_days !== null).map((o) => o.retention_days));
  const r = await db.query(
    `SELECT e.source_type, COUNT(*)::bigint AS events, MIN(e.received_at) AS oldest
     FROM events e
     LEFT JOIN unnest($2::text[], $3::int[]) AS pol(source_type, days) ON pol.source_type = e.source_type
     WHERE e.tenant_id = $1
       AND e.received_at < localtimestamp - ($5::int * interval '1 day')
       AND (CASE WHEN pol.source_type IS NULL THEN $4::int ELSE pol.days END) IS NOT NULL
       AND e.received_at < localtimestamp - ((CASE WHEN pol.source_type IS NULL THEN $4::int ELSE pol.days END) * interval '1 day')
     GROUP BY e.source_type ORDER BY events DESC, e.source_type ASC`,
    [tenantId, pol.overrides.map((o) => o.source_type), pol.overrides.map((o) => o.retention_days), pol.default_days, minDays]);
  return r.rows.map((x) => ({ source_type: x.source_type, events: Number(x.events) }));
}

describe('retention job on PostgreSQL, through the event store', () => {
  let T; let T2; const made = [];
  const store = () => getEventStore();
  const left = (source, tenant = T) => store().count(tenant, { source_type: source });
  const setPolicy = async (tenant, { auto, days, overrides }) => {
    await db.query('INSERT INTO retention_settings (tenant_id, auto_purge, default_days) VALUES ($1, $2, $3) ON CONFLICT (tenant_id) DO UPDATE SET auto_purge = $2, default_days = $3', [tenant, auto, days]);
    await db.query('DELETE FROM retention_policies WHERE tenant_id = $1', [tenant]);
    for (const o of overrides) await db.query('INSERT INTO retention_policies (tenant_id, source_type, retention_days) VALUES ($1, $2, $3)', [tenant, o.source_type, o.retention_days]);
  };
  const partitionFor = async (daysAgo) => { const d = dayOf(agoDays(daysAgo)); await storage.ensurePartition(d); made.push('events_p' + d.replace(/-/g, '')); };

  before(async () => {
    const stamp = Date.now();
    T = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['retention-db-a-' + stamp])).rows[0].id;
    T2 = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['retention-db-b-' + stamp])).rows[0].id;
  });
  after(async () => {
    for (const t of [T, T2]) {
      await store().deleteBefore(t, '2999-01-01T00:00:00Z');
      for (const tbl of ['retention_runs', 'retention_policies', 'retention_settings']) await db.query(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t]);
      await db.query('DELETE FROM tenants WHERE id = $1', [t]);
    }
    for (const name of made) if (/^events_p\d{8}$/.test(name)) await db.query(`DROP TABLE IF EXISTS ${name}`);     // only the empty partitions this test made
    await db.close();
  });

  it('the preview equals the SQL it replaced, with expired rows in daily partitions and in events_default', async () => {
    await partitionFor(40); await partitionFor(10); await partitionFor(500);          // daily partitions for some of the days; the other days stay in events_default
    await setPolicy(T, { auto: false, days: 30, overrides: [{ source_type: 'r-short', retention_days: 7 }, { source_type: 'r-long', retention_days: 365 }, { source_type: 'r-forever', retention_days: null }] });
    const events = [];
    for (const d of [40, 40, 35, 31, 29, 2]) events.push(ev('r-default', d));
    for (const d of [10, 10, 8, 6]) events.push(ev('r-short', d));
    for (const d of [500, 400, 366, 100]) events.push(ev('r-long', d));
    for (const d of [3000, 500]) events.push(ev('r-forever', d));
    await store().insertBatch(T, events);
    await store().insertBatch(T2, [ev('r-other-tenant', 900), ev('r-other-tenant', 1)]);
    const inDefault = Number((await db.query('SELECT COUNT(*)::int AS n FROM events_default WHERE tenant_id = $1', [T])).rows[0].n);
    assert.ok(inDefault > 0, 'some of the data sits in events_default, so that target is exercised');
    const pol = await storage.loadPolicy(db, T);
    const mine = await storage.preview(T, pol);
    assert.deepStrictEqual(mine.by_source.map((r) => ({ source_type: r.source_type, events: r.events })), await oldPreview(T, pol));
    assert.deepStrictEqual(mine.by_source.map((r) => [r.source_type, r.events]), [['r-default', 4], ['r-long', 3], ['r-short', 3]]);
    assert.strictEqual(mine.total, 10);
    assert.ok(mine.by_source.every((r) => typeof r.oldest === 'string' && !Number.isNaN(Date.parse(r.oldest))), 'oldest is an ISO time');
    const dry = await storage.runManual(T, { dryRun: true });
    assert.strictEqual(dry.dry_run, true);
    assert.strictEqual(dry.total, 10);
    assert.strictEqual(await left('r-default'), 6, 'a preview deletes nothing');
  });

  it('a manual purge deletes exactly what the preview counted, per source, and logs it', async () => {
    const r = await storage.runManual(T, { dryRun: false });
    assert.strictEqual(r.dry_run, false);
    assert.strictEqual(r.rows_deleted, 10);
    assert.deepStrictEqual(r.by_source, { 'r-default': 4, 'r-long': 3, 'r-short': 3 });
    assert.strictEqual(r.truncated, false);
    assert.ok(r.partitions_scanned >= 1);
    assert.strictEqual(await left('r-default'), 2);
    assert.strictEqual(await left('r-short'), 1);
    assert.strictEqual(await left('r-long'), 1);
    assert.strictEqual(await left('r-forever'), 2, 'keep forever is never deleted');
    assert.strictEqual(await left('r-other-tenant', T2), 2, 'another tenant is untouched');
    const run = (await db.query('SELECT status, rows_deleted::int AS n, detail FROM retention_runs WHERE id = $1', [r.run_id])).rows[0];
    assert.deepStrictEqual([run.status, run.n], ['completed', 10]);
    assert.deepStrictEqual(run.detail.by_source, r.by_source);
    assert.deepStrictEqual((await storage.preview(T, await storage.loadPolicy(db, T))).by_source, []);
  });

  it('the scheduled run purges only tenants that switched automatic purge on', async () => {
    await setPolicy(T, { auto: true, days: 30, overrides: [{ source_type: 'r-short', retention_days: 7 }, { source_type: 'r-forever', retention_days: null }] });
    await setPolicy(T2, { auto: false, days: 30, overrides: [] });
    await store().insertBatch(T, [ev('r-short', 9), ev('r-default', 45)]);
    const out = await storage.runScheduled();
    assert.ok(!out.busy);
    assert.strictEqual(out.errors, 0);
    assert.ok(out.rows_deleted >= 2);
    assert.strictEqual(await left('r-short'), 1, 'the 9 day old r-short event is gone, the 6 day old one stays');
    assert.strictEqual(await left('r-other-tenant', T2), 2, 'automatic purge is off for the other tenant');
    const runs = (await db.query("SELECT status FROM retention_runs WHERE tenant_id = $1 AND trigger = 'scheduled'", [T])).rows;
    assert.deepStrictEqual(runs.map((x) => x.status), ['completed']);
  });

  it('whole partitions older than every tenant\'s longest retention are still dropped (when this is the only data)', async (t) => {
    const others = Number((await db.query('SELECT COUNT(*)::int AS n FROM tenants WHERE id NOT IN ($1, $2)', [T, T2])).rows[0].n);
    if (others) return t.skip('other tenants exist in this database, so their policies decide what may be dropped');
    await setPolicy(T, { auto: true, days: 30, overrides: [{ source_type: 'r-short', retention_days: 7 }] });
    await setPolicy(T2, { auto: true, days: 60, overrides: [] });
    await storage.runManual(T2, { dryRun: false });
    const name = 'events_p' + dayOf(agoDays(500)).replace(/-/g, '');
    await store().insertBatch(T2, [ev('r-drop', 500)]);                                            // sits in the day-500 partition
    const before = (await storage.listPartitions(db)).map((p) => p.name);
    assert.ok(before.includes(name));
    const out = await storage.runScheduled();
    assert.ok(out.dropped.includes(name), 'the old partition is dropped');
    assert.ok(!(await storage.listPartitions(db)).map((p) => p.name).includes(name));
    assert.strictEqual(await left('r-drop', T2), 0);
  });
});
