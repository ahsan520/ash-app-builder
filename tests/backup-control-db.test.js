'use strict';
// The backup control on a real PostgreSQL with the platform schema applied (k8s/12-schema-init.yaml's schema.sql) and the PostgreSQL client tools (pg_dump, pg_restore, psql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node --test tests/backup-control-db.test.js
// Skips itself otherwise. Real: the settings row and its SQL, the portal routes, the Data safety report and a real backup job with the retention (pg_dump, encryption, the
// manifest). Replaced: the sign-in chain and the cluster. It puts the settings row back as it found it and removes the backup_runs rows it made.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const db = require('../src/db');
const kube = require('../src/capacity/kube');
kube.snapshot = async () => ({ available: false, error: 'no cluster in this test' });
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = 'x'; req.user_id = 'user-1'; next(); }] };
const routes = require('../src/gateway/routes/storage');
const control = require('../src/backup/control');
const safety = require('../src/storage/safety');
const backup = require('../src/backup/backup');

const started = Date.now() - 1000;
let saved, srv, base, dir, tmp;
const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, body: await r.json() }; };
const row = async () => (await db.query('SELECT * FROM backup_settings WHERE id = 1')).rows[0];
const reset = () => db.query("UPDATE backup_settings SET enabled = true, time_utc = '02:17', days = '[0,1,2,3,4,5,6]', retain_days = 2, last_scheduled_at = NULL, run_requested_at = NULL, run_requested_by = NULL");
const dbEnv = () => ({ PATH: process.env.PATH, PGHOST: process.env.DB_HOST || '127.0.0.1', PGPORT: process.env.DB_PORT || '5432', PGUSER: process.env.DB_USER || 'asix_admin', PGPASSWORD: process.env.DB_PASSWORD });

before(async () => {
  saved = await row(); assert.ok(saved, 'the schema creates the backup_settings row');
  const app = express(); app.use(express.json()); app.use(routes); srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bkctl-')); tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bkctl-tmp-'));
});
after(async () => {
  await db.query('UPDATE backup_settings SET enabled=$1, time_utc=$2, days=$3, retain_days=$4, last_scheduled_at=$5, run_requested_at=$6, run_requested_by=$7, updated_at=$8, updated_by=$9 WHERE id = 1',
    [saved.enabled, saved.time_utc, JSON.stringify(saved.days), saved.retain_days, saved.last_scheduled_at, saved.run_requested_at, saved.run_requested_by, saved.updated_at, saved.updated_by]);
  await db.query("DELETE FROM backup_runs WHERE started_at >= to_timestamp($1) AT TIME ZONE 'UTC' - interval '1 day' AND (set_name LIKE 'asix-2026%' OR trigger IN ('test-manual','test-running'))", [started / 1000]).catch(() => {});
  if (srv) srv.close(); fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); await db.close();
});

describe('settings row (src/backup/control.js)', () => {
  it('the schema row gives the defaults: on, 02:17 UTC, every day, 2 days kept, never scheduled', async () => {
    await reset(); const s = await control.load(db);
    assert.deepStrictEqual([s.configured, s.enabled, s.time_utc, s.days, s.retain_days, s.last_scheduled_at, s.run_requested_at], [true, true, '02:17', [0, 1, 2, 3, 4, 5, 6], 2, null, null]);
  });
  it('save changes only what is sent, and a schedule change moves "last scheduled" to now (a time earlier today must not fire)', async () => {
    await control.save(db, { retain_days: 5 }, 'u1'); let s = await control.load(db);
    assert.strictEqual(s.retain_days, 5); assert.strictEqual(s.time_utc, '02:17'); assert.strictEqual(s.last_scheduled_at, null, 'retention alone is not a schedule change'); assert.strictEqual(s.updated_by, 'u1');
    const at = Date.parse('2026-10-30T12:00:00Z'); await control.save(db, { time_utc: '04:30', days: [1, 3], enabled: false }, 'u2', at); s = await control.load(db);
    assert.deepStrictEqual([s.time_utc, s.days, s.enabled, s.retain_days, s.last_scheduled_at, s.updated_by], ['04:30', [1, 3], false, 5, new Date(at).toISOString(), 'u2']);
  });
  it('the table refuses values the API would never send (a bad time, retention 0, a second row)', async () => {
    await reset();
    await assert.rejects(db.query("UPDATE backup_settings SET time_utc = '25:00'"), /check/i);
    await assert.rejects(db.query('UPDATE backup_settings SET retain_days = 0'), /check/i);
    await assert.rejects(db.query('INSERT INTO backup_settings (id) VALUES (2)'), /check/i);
  });
  it('request: one waits at a time; claiming takes it once, even when two claim together', async () => {
    await reset(); const a = await control.request(db, 'u1'); assert.ok(a.requested_at);
    assert.deepStrictEqual(await control.request(db, 'u2'), { busy: 'requested' }); assert.strictEqual((await row()).run_requested_by, 'u1');
    const [c1, c2] = await Promise.all([control.claimRequest(db), control.claimRequest(db)]); assert.strictEqual([c1, c2].filter(Boolean).length, 1); assert.deepStrictEqual([c1, c2].find(Boolean), { by: 'u1' });
    assert.strictEqual(await control.claimRequest(db), null); assert.ok((await control.request(db, 'u3')).requested_at);
  });
  it('a request is refused while a backup is running; a "running" row older than the job limit is a dead run and does not block', async () => {
    await reset(); const r = (await db.query("INSERT INTO backup_runs (trigger, kind, status) VALUES ('test-running', 'postgres', 'running') RETURNING id")).rows[0].id;
    assert.strictEqual((await control.request(db, 'u1')).busy, 'running'); assert.strictEqual((await control.running(db)).trigger, 'test-running');
    await db.query("UPDATE backup_runs SET started_at = localtimestamp - interval '3 hours' WHERE id = $1", [r]); assert.strictEqual(await control.running(db), null); assert.ok((await control.request(db, 'u1')).requested_at);
    await db.query('DELETE FROM backup_runs WHERE id = $1', [r]);
  });
  it('markScheduled is an upsert: with the row gone it creates it (an update would leave the slot owed forever)', async () => {
    await db.query('DELETE FROM backup_settings'); const slot = Date.parse('2026-10-30T02:17:00Z'); await control.markScheduled(db, slot);
    const s = await control.load(db); assert.strictEqual(s.last_scheduled_at, new Date(slot).toISOString()); assert.strictEqual(s.retain_days, 2); assert.strictEqual(s.time_utc, '02:17');
    await db.query('DELETE FROM backup_settings'); assert.strictEqual((await control.load(db)).configured, false, 'no row: the defaults, not an error'); assert.strictEqual(await control.retainDays(db), 2);
    await db.query('INSERT INTO backup_settings (id) VALUES (1)');
  });
  it('retainDays reads the setting', async () => { await reset(); await control.save(db, { retain_days: 9 }); assert.strictEqual(await control.retainDays(db), 9); });
});

describe('portal routes', () => {
  it('PUT /v1/storage/backup/settings: saves, returns the settings; refusals write nothing', async () => {
    await reset(); let r = await call('PUT', '/v1/storage/backup/settings', { enabled: true, time_utc: '03:05', days: [1, 2, 3, 4, 5], retain_days: 3 });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.body.settings.time_utc, r.body.settings.days, r.body.settings.retain_days], ['03:05', [1, 2, 3, 4, 5], 3]); assert.strictEqual((await row()).updated_by, 'user-1');
    for (const bad of [{ time_utc: '3:5' }, { days: [] }, { days: [8] }, { retain_days: 0 }, { retain_days: 'x' }, { enabled: 'on' }, {}]) {
      r = await call('PUT', '/v1/storage/backup/settings', bad); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(r.body.error.code, 'INVALID_BODY');
    }
    const s = await control.load(db); assert.deepStrictEqual([s.time_utc, s.days, s.retain_days], ['03:05', [1, 2, 3, 4, 5], 3]);
  });
  it('POST /v1/storage/backup/run: 202 and the request is recorded with who asked; asking again is 409', async () => {
    await reset(); let r = await call('POST', '/v1/storage/backup/run'); assert.strictEqual(r.status, 202); assert.ok(r.body.requested_at); assert.strictEqual((await row()).run_requested_by, 'user-1');
    r = await call('POST', '/v1/storage/backup/run'); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'BACKUP_ALREADY_REQUESTED');
    await reset(); const id = (await db.query("INSERT INTO backup_runs (trigger, kind, status) VALUES ('test-running', 'clickhouse', 'running') RETURNING id")).rows[0].id;
    r = await call('POST', '/v1/storage/backup/run'); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'BACKUP_RUNNING'); assert.strictEqual((await row()).run_requested_at, null);
    await db.query('DELETE FROM backup_runs WHERE id = $1', [id]);
  });
});

describe('Data safety report', () => {
  const ids = (r) => r.warnings.map((w) => w.id);
  const insertRun = (hoursAgo, extra = {}) => db.query("INSERT INTO backup_runs (trigger, kind, status, started_at, finished_at, bytes, databases, verified, verified_at) VALUES ('scheduled', 'postgres', 'completed', localtimestamp - $1 * interval '1 hour', localtimestamp - $1 * interval '1 hour', 100, '[\"asix_platform\"]', true, localtimestamp - $1 * interval '1 hour') RETURNING id", [hoursAgo]).then((x) => x.rows[0].id);
  it('carries the control section: schedule text, retention, next run, a waiting request, a running backup', async () => {
    await reset(); await control.save(db, { time_utc: '03:30', days: [1, 4], retain_days: 2 }, 'u1');
    let r = await safety.report(); assert.strictEqual(r.schedule, 'Mon, Thu at 03:30 UTC'); assert.strictEqual(r.retain_days, 2); assert.strictEqual(r.control.enabled, true); assert.ok(Date.parse(r.control.next_run) > Date.now()); assert.strictEqual(r.control.running, null);
    await control.request(db, 'u9'); r = await safety.report(); assert.ok(r.control.run_requested_at); assert.strictEqual(r.control.run_requested_by, 'u9');
    await control.save(db, { days: [0, 1, 2, 3, 4, 5, 6] }); assert.strictEqual((await safety.report()).schedule, 'daily at 03:30 UTC');
  });
  it('switched off: a warning, and no next run', async () => { await reset(); await control.save(db, { enabled: false }); const r = await safety.report(); assert.ok(ids(r).includes('schedule_off')); assert.strictEqual(r.control.next_run, null); assert.strictEqual(r.schedule, 'switched off'); });
  it('a request nothing picks up for over two minutes is critical (the runner is probably down); a fresh one is not', async () => {
    await reset(); await control.request(db, 'u1'); assert.ok(!ids(await safety.report()).includes('runner_stalled'));
    await db.query("UPDATE backup_settings SET run_requested_at = now() - interval '5 minutes'"); const r = await safety.report(); const w = r.warnings.find((x) => x.id === 'runner_stalled');
    assert.ok(w && w.severity === 'critical'); assert.match(w.fix, /asix-backup-runner/); assert.strictEqual(r.verdict, 'critical');
  });
  it('an overdue scheduled time nothing started is critical; one already handed to a job is not', async () => {
    await reset(); await control.save(db, { time_utc: '00:00', days: [0, 1, 2, 3, 4, 5, 6] }, 'u1', Date.now() - 3 * 86400000);   // last scheduled 3 days ago: today's 00:00 is owed
    await db.query('UPDATE backup_settings SET last_scheduled_at = now() - interval \'3 days\''); const slotAge = Date.now() - Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate());
    assert.strictEqual(ids(await safety.report()).includes('runner_stalled'), slotAge > 10 * 60000);
    await db.query('UPDATE backup_settings SET last_scheduled_at = now()'); assert.ok(!ids(await safety.report()).includes('runner_stalled'));
  });
  it('"the last backup is old" follows the schedule: 50 hours is a warning on a daily schedule and fine on a Mon+Thu one', async () => {
    await reset(); await db.query("DELETE FROM backup_runs WHERE kind = 'postgres'"); const id = await insertRun(50);
    assert.ok(ids(await safety.report()).includes('stale')); await control.save(db, { days: [1, 4] }); assert.ok(!ids(await safety.report()).includes('stale'));
    await db.query("UPDATE backup_runs SET finished_at = localtimestamp - interval '250 hours' WHERE id = $1", [id]); assert.strictEqual((await safety.report()).warnings.find((w) => w.id === 'stale').severity, 'critical');
    await db.query('DELETE FROM backup_runs WHERE id = $1', [id]);
  });
});

describe('the backup job with retention (real pg_dump)', () => {
  const env = (extra = {}) => ({ ...dbEnv(), BACKUP_DIR: dir, BACKUP_TMP: tmp, BACKUP_PASSPHRASE: 'a passphrase', BACKUP_DATABASES: process.env.DB_NAME || 'asix_platform', BACKUP_VERIFY_EVERY_DAYS: '0', BACKUP_KEEP: '14', ...extra });
  const fake = (daysAgo, hh = '02', manifest = true) => {
    const d = new Date(Date.now() - daysAgo * 86400000), p = (n) => String(n).padStart(2, '0'), name = `asix-${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${hh}1700Z`;
    for (const f of ['asix_platform.dump.enc', 'globals.sql.enc']) fs.writeFileSync(path.join(dir, `${name}.${f}`), 'x'); if (manifest) fs.writeFileSync(path.join(dir, `${name}.manifest.json`), '{}'); return name;
  };
  const sets = () => fs.readdirSync(dir).filter((f) => f.endsWith('.manifest.json')).map((f) => f.replace('.manifest.json', '')).sort();
  it('deletes sets older than the retention before the run, keeps newer ones, and the new set is complete and readable', async () => {
    await reset(); await control.save(db, { retain_days: 2 }); fs.readdirSync(dir).forEach((f) => fs.rmSync(path.join(dir, f)));
    const old = fake(6), mid = fake(3), recent = fake(1);
    const r = await backup.runBackup({ trigger: 'manual', env: env(), db });
    assert.strictEqual(r.retain_days, 2); assert.deepStrictEqual(r.pruned.sort(), [old, mid].sort());
    assert.deepStrictEqual(sets(), [recent, r.set].sort()); assert.ok(fs.existsSync(path.join(dir, r.set + '.manifest.json')));
    const rows = (await db.query("SELECT status, trigger FROM backup_runs WHERE set_name = $1", [r.set])).rows; assert.deepStrictEqual(rows, [{ status: 'completed', trigger: 'manual' }]);
  });
  it('the user\'s case: the only backup is 5 days old - it survives until the new one is good, then goes', async () => {
    fs.readdirSync(dir).forEach((f) => fs.rmSync(path.join(dir, f))); const stale = fake(5);
    await assert.rejects(backup.runBackup({ trigger: 'manual', env: env({ BACKUP_DATABASES: 'no_such_database' }), db }));            // a failing run: nothing is left of it, and the old backup is untouched
    assert.deepStrictEqual(sets(), [stale]); assert.strictEqual(fs.readdirSync(dir).filter((f) => f.startsWith(stale)).length, 3);
    assert.strictEqual((await db.query("SELECT count(*)::int AS n FROM backup_runs WHERE status = 'failed' AND started_at >= localtimestamp - interval '1 minute' AND kind = 'postgres'")).rows[0].n >= 1, true);
    const r = await backup.runBackup({ trigger: 'scheduled', env: env(), db }); assert.deepStrictEqual(r.pruned, [stale]); assert.deepStrictEqual(sets(), [r.set]);
  });
  it('BACKUP_RETAIN_DAYS in the environment wins over the portal setting', async () => {
    fs.readdirSync(dir).forEach((f) => fs.rmSync(path.join(dir, f))); await control.save(db, { retain_days: 1 }); const keepMe = fake(3);
    const r = await backup.runBackup({ trigger: 'manual', env: env({ BACKUP_RETAIN_DAYS: '10' }), db }); assert.strictEqual(r.retain_days, 10); assert.deepStrictEqual(r.pruned, []); assert.ok(sets().includes(keepMe));
  });
});
