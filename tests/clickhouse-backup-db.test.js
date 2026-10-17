'use strict';
// The ClickHouse event backup on real servers: ClickHouse (events, scratch tables) and PostgreSQL (backup_runs, the Data safety report).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... ASIX_CLICKHOUSE_URL=http://user:pass@127.0.0.1:8123/asix node --test tests/clickhouse-backup-db.test.js
// Skips itself otherwise. It uses its own throwaway ClickHouse tables (never the live `events` table) and removes everything it made.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 and ASIX_CLICKHOUSE_URL to run against ClickHouse and Postgres)'); process.exit(0); }
if (!process.env.ASIX_CLICKHOUSE_URL) { console.error('ASIX_TEST_DB=1 needs ASIX_CLICKHOUSE_URL'); process.exit(1); }

const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const db = require('../src/db');
const { ClickHouseEventStore } = require('../src/events/clickhouse-store');
const cb = require('../src/backup/clickhouse-backup');

const rnd = () => crypto.randomBytes(5).toString('hex');
const src = new ClickHouseEventStore({ table: 'events_bksrc_' + rnd() });
const T1 = crypto.randomUUID(), T2 = crypto.randomUUID();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chbk-db-')), tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'chbk-dbtmp-'));
const env = { BACKUP_DIR: dir, BACKUP_TMP: tmp, BACKUP_PASSPHRASE: 'a passphrase', BACKUP_KEEP: '14', BACKUP_CLICKHOUSE: '1' };
const cfg = cb.config(env);
const extra = [];                                                 // other throwaway tables to drop at the end
const tables = async (like) => (await src._exec(`SELECT name FROM system.tables WHERE database = currentDatabase() AND name LIKE '${like}' ORDER BY name FORMAT TSV`)).split('\n').filter(Boolean);
const deps = {
  store: src, tenants: async () => [T1, T2],
  openScratch: async () => { const s = new ClickHouseEventStore({ table: 'events_verify_' + rnd() }); await s.ensureSchema(); return { store: s, drop: () => s.dropTable() }; },
};
const all = async (store, tenant) => { const out = []; let after = null; for (;;) { const p = await store.scan(tenant, { limit: 1000, after }); out.push(...p.events); if (!p.next) break; after = p.next; } return out; };
const iso = (daysAgo, h, m, s, ms) => new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate() - daysAgo, h, m, s, ms)).toISOString();

test.before(async () => {
  await src.ensureSchema();
  const mk = (tenant, daysAgo, n) => src.insertBatch(tenant, Array.from({ length: n }, (_, i) => ({
    id: crypto.randomUUID(), source_type: i % 3 ? 'syslog' : 'json', collector_id: i % 4 ? 'c-' + (i % 4) : null, received_at: iso(daysAgo, 1 + (i % 20), i % 60, i % 60, (i * 37) % 1000),
    event_time: i % 2 ? iso(daysAgo, 0, 30, 0, 250) : null, raw: `real clickhouse "quoted" ünïcode ✓ ${daysAgo}/${i}`,
    parsed: { n: i, host: 'h' + (i % 5), nested: { list: [1, 2.5, 'x', null], flag: i % 2 === 0 }, text: 'café' } })));
  for (const d of [4, 3, 2, 1]) await mk(T1, d, 300);
  await mk(T2, 2, 120); await mk(T2, 1, 80);
});
test.after(async () => {
  await db.query("DELETE FROM backup_runs WHERE set_name LIKE 'asix-ch-%' AND error IS DISTINCT FROM 'keep'").catch(() => {});
  for (const t of [...(await tables('events_verify_%')), ...(await tables('events_bkrestore_%')), src.table, ...extra]) await src._exec(`DROP TABLE IF EXISTS ${t}`).catch(() => {});
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true });
  await db.close();
});

test('backup, test restore and an exact restore of real ClickHouse data; the scratch table is gone afterwards', async () => {
  const r = await cb.backupEvents(cfg, deps);
  assert.strictEqual(r.days, 4); assert.strictEqual(r.rows, 4 * 300 + 120 + 80);
  const m = cb.readManifest(cfg);
  assert.strictEqual(m.days[Object.keys(m.days).sort()[2]].tenants.length, 2);       // day 2 ago: the first day both tenants have events
  const v = await cb.verifyBackup(cfg, deps);
  assert.deepStrictEqual(v, { days: 4, rows: 1400 });
  assert.deepStrictEqual(await tables('events_verify_%'), [], 'scratch table dropped');
  // restore into a new table: identical to the source, field by field (microsecond-free, as ClickHouse stores them)
  const fresh = new ClickHouseEventStore({ table: 'events_bkrestore_' + rnd() }); await fresh.ensureSchema();
  const res = await cb.restoreEvents(cfg, { store: fresh, exact: true });
  assert.deepStrictEqual(res, { days: 4, restored: 1400, already_there: 0 });
  assert.deepStrictEqual(await all(fresh, T1), await all(src, T1)); assert.deepStrictEqual(await all(fresh, T2), await all(src, T2));
  // restoring again into the same table adds nothing (the stores' own idempotency)
  const again = await cb.restoreEvents(cfg, { store: fresh, exact: true });
  assert.deepStrictEqual(again, { days: 4, restored: 0, already_there: 1400 });
  assert.strictEqual(await fresh.count(T1), 1200);
});

test('a damaged backup file fails the test restore on the real server, and the scratch table is still dropped', async () => {
  const m = cb.readManifest(cfg), file = path.join(cfg.dir, Object.values(m.days)[1].file);
  const good = fs.readFileSync(file), bad = Buffer.from(good); bad[bad.length - 40] ^= 0x55; fs.writeFileSync(file, bad);
  await assert.rejects(cb.verifyBackup(cfg, deps), /checksum mismatch/);
  fs.writeFileSync(file, good);
  assert.deepStrictEqual(await tables('events_verify_%'), []);
  assert.deepStrictEqual(await cb.verifyBackup(cfg, deps), { days: 4, rows: 1400 });
});

test('incremental on the real server: a second run reads nothing for closed days; a late event re-exports only its day', async () => {
  let r = await cb.backupEvents(cfg, deps);
  assert.ok(r.exported <= 2, 'only the last two days are refreshed: ' + JSON.stringify(r.exported_days));
  await src.insertBatch(T1, [{ source_type: 'syslog', raw: 'late arrival', received_at: iso(4, 23, 59, 59, 5), parsed: { late: true } }]);
  r = await cb.backupEvents(cfg, deps);
  assert.ok(r.exported_days.some((d) => d === iso(4, 0, 0, 0, 0).slice(0, 10)));
  assert.strictEqual(r.rows, 1401);
  assert.deepStrictEqual(await cb.verifyBackup(cfg, deps), { days: 4, rows: 1401 });
  assert.strictEqual(fs.readdirSync(cfg.dir).filter((f) => f.endsWith('.enc')).length, 4, 'replaced files removed');
});

test('the live events table cannot be dropped through the store', async () => {
  await assert.rejects(new ClickHouseEventStore().dropTable(), /refusing to drop the live events table/);
  assert.ok(src.table.startsWith('events_bksrc_'));
});

test('nightly entry point on real servers: recorded in backup_runs as kind clickhouse, verified, and the Data safety report reads it', async () => {
  const { report } = require('../src/storage/safety');
  await db.query("DELETE FROM backup_runs WHERE kind = 'clickhouse'");
  process.env.ASIX_EVENT_STORE = 'clickhouse';
  try {
    // never backed up while ClickHouse is the store: critical
    let rep = await report();
    assert.ok(rep.warnings.some((w) => w.id === 'ch_no_backup' && w.severity === 'critical'), JSON.stringify(rep.warnings.map((w) => w.id)));
    assert.strictEqual(rep.clickhouse.active, true);
    const out = await cb.runClickHouseBackup({ env, db, deps });
    assert.strictEqual(out.verified, true); assert.ok(out.bytes > 0); assert.match(out.set, /^asix-ch-/);
    const row = (await db.query("SELECT kind, status, verified, bytes::bigint AS bytes, databases FROM backup_runs WHERE set_name = $1", [out.set])).rows[0];
    assert.strictEqual(row.kind, 'clickhouse'); assert.strictEqual(row.status, 'completed'); assert.strictEqual(row.verified, true); assert.deepStrictEqual(row.databases, ['clickhouse:events']);
    rep = await report();
    assert.ok(!rep.warnings.some((w) => w.id.startsWith('ch_')), 'no ClickHouse warnings after a verified backup: ' + JSON.stringify(rep.warnings.map((w) => w.id)));
    assert.strictEqual(rep.clickhouse.last_success.set_name, out.set); assert.strictEqual(rep.clickhouse.last_verified.set_name, out.set);
    // ClickHouse runs never hide a PostgreSQL problem: the PostgreSQL view does not include them
    assert.ok(rep.runs.every((r) => !String(r.set_name).startsWith('asix-ch-')));
    // a failure is recorded, thrown, and shown as critical
    const broken = { ...deps, store: Object.assign(Object.create(src), { init: async () => { throw new Error('ClickHouse refused the connection'); } }) };
    await assert.rejects(cb.runClickHouseBackup({ env, db, deps: broken }), /refused the connection/);
    rep = await report();
    assert.ok(rep.warnings.some((w) => w.id === 'ch_last_failed' && w.severity === 'critical' && /refused the connection/.test(w.detail)));
    // when ClickHouse is not the store the same failure is only a warning
    process.env.ASIX_EVENT_STORE = 'postgres';
    rep = await report();
    assert.ok(rep.warnings.some((w) => w.id === 'ch_last_failed' && w.severity === 'warning'));
  } finally { delete process.env.ASIX_EVENT_STORE; }
});
