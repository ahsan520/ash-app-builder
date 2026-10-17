'use strict';
// ClickHouse event backup, test restore and restore (src/backup/clickhouse-backup.js) on in-memory stores. No database, no ClickHouse.
const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { MemoryEventStore } = require('../src/events/memory-store');
const cb = require('../src/backup/clickhouse-backup');

const NOW = Date.parse('2026-10-17T12:00:00Z');
const T1 = crypto.randomUUID(), T2 = crypto.randomUUID();
const day = (n) => new Date(NOW - n * 86400000).toISOString().slice(0, 10);      // day(0) = today
const at = (n, h, m = 0) => `${day(n)}T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00.000Z`;

function setup(over = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chbk-')), tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'chbk-tmp-'));
  const cfg = cb.config({ BACKUP_DIR: dir, BACKUP_TMP: tmp, BACKUP_PASSPHRASE: 'correct horse', BACKUP_KEEP: '14', ...over });
  const store = new MemoryEventStore(), scratches = [];
  const deps = { store, tenants: async () => [T1, T2], openScratch: async () => { const s = new MemoryEventStore(); scratches.push(s); return { store: s, drop: async () => { s.dropped = true; } }; } };
  return { cfg, store, deps, dir, tmp, scratches, files: () => fs.readdirSync(cfg.dir).filter((f) => f.endsWith('.enc')).sort(), cleanup: () => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); } };
}
async function fill(store, tenant, days, perDay, tag = 'x') {
  for (const d of days) await store.insertBatch(tenant, Array.from({ length: perDay }, (_, i) => ({ id: crypto.randomUUID(), source_type: 'syslog', collector_id: i % 2 ? 'c1' : null, received_at: at(d, 1 + (i % 10), i),
    event_time: i % 3 ? at(d, 1, 0) : null, raw: `${tag} secret-marker line ${d}/${i} "q" ünï ✓`, parsed: { n: i, nested: { a: [1, { b: 2 }] }, day: d } })));
}
const all = async (store, tenant) => { const out = []; let after = null; for (;;) { const p = await store.scan(tenant, { limit: 1000, after }); out.push(...p.events); if (!p.next) break; after = p.next; } return out; };
const failure = (p) => p.then(() => null, (e) => e.message);

test('first backup: one encrypted file per day for all tenants, manifest with rows and digests, nothing readable in the files', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [0, 1, 2, 3, 4], 30); await fill(s.store, T2, [1, 2], 10);
    const r = await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    assert.strictEqual(r.days, 5); assert.strictEqual(r.exported, 5); assert.strictEqual(r.rows, 5 * 30 + 2 * 10);
    const m = cb.readManifest(s.cfg);
    assert.deepStrictEqual(Object.keys(m.days).sort(), [4, 3, 2, 1, 0].map(day));
    assert.strictEqual(m.days[day(1)].rows, 40); assert.deepStrictEqual(m.days[day(1)].tenants.sort(), [T1, T2].sort()); assert.strictEqual(m.days[day(3)].tenants.length, 1);
    assert.strictEqual(s.files().length, 5);
    for (const f of s.files()) { const raw = fs.readFileSync(path.join(s.cfg.dir, f)); assert.ok(!raw.includes('secret-marker') && !raw.includes('syslog')); assert.strictEqual(raw.subarray(0, 8).toString(), 'ASIXBK01'); }
    assert.ok(!fs.existsSync(path.join(s.cfg.dir, '.lock')), 'lock released'); assert.deepStrictEqual(fs.readdirSync(s.tmp), [], 'no plaintext left in the scratch folder');
  } finally { s.cleanup(); }
});

test('later runs are incremental: unchanged closed days are not read again, the last two days are refreshed, a changed old day is re-exported', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [0, 1, 2, 3, 4, 5], 20);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    const before = cb.readManifest(s.cfg), filesBefore = s.files();
    let r = await cb.backupEvents(s.cfg, s.deps, { now: NOW + 3600000 });
    assert.deepStrictEqual(r.exported_days.sort(), [day(0), day(1)].sort());                    // only the recent two
    const after = cb.readManifest(s.cfg);
    for (const d of [2, 3, 4, 5]) assert.strictEqual(after.days[day(d)].file, before.days[day(d)].file, 'closed day untouched');
    assert.strictEqual(s.files().length, 6, 'replaced files were removed');
    assert.ok(filesBefore.includes(after.days[day(3)].file));
    // an old day gets a late event (for example from the event copy tool): its count changes, so it is exported again
    await s.store.insertBatch(T1, [{ source_type: 'syslog', raw: 'late', received_at: at(4, 23, 59) }]);
    r = await cb.backupEvents(s.cfg, s.deps, { now: NOW + 7200000 });
    assert.ok(r.exported_days.includes(day(4))); assert.strictEqual(cb.readManifest(s.cfg).days[day(4)].rows, 21);
    assert.strictEqual(s.files().length, 6);
  } finally { s.cleanup(); }
});

test('events from the last seconds are left for the next run (snapshot), so a day is never exported half-written', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [1], 5);
    await s.store.insertBatch(T1, [{ source_type: 'syslog', raw: 'too fresh', received_at: new Date(NOW - 1000).toISOString() }]);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    assert.strictEqual(cb.readManifest(s.cfg).days[day(0)], undefined, 'today has only the too-fresh event: nothing counted yet');
    await cb.backupEvents(s.cfg, s.deps, { now: NOW + 60000 });
    assert.strictEqual(cb.readManifest(s.cfg).days[day(0)].rows, 1);
  } finally { s.cleanup(); }
});

test('test restore: all days load into a scratch table that matches the manifest, and the scratch table is dropped', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [0, 1, 2], 25); await fill(s.store, T2, [1], 7);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    const v = await cb.verifyBackup(s.cfg, s.deps);
    assert.deepStrictEqual(v, { days: 3, rows: 82 });
    assert.strictEqual(s.scratches.length, 1); assert.strictEqual(s.scratches[0].dropped, true);
  } finally { s.cleanup(); }
});

test('test restore catches a damaged file, a missing file, a wrong passphrase, and a manifest that does not match the content', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [1, 2, 3], 15);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    const m = cb.readManifest(s.cfg), file = path.join(s.cfg.dir, m.days[day(2)].file);
    // wrong passphrase
    assert.match(await failure(cb.verifyBackup({ ...s.cfg, pass: 'wrong' }, s.deps)), /wrong passphrase|damaged/);
    // content tampered with, manifest digest kept: same rows, different content
    const m2 = JSON.parse(JSON.stringify(m)); m2.days[day(2)].digest = '0'.repeat(64); fs.writeFileSync(path.join(s.cfg.dir, 'manifest.json'), JSON.stringify(m2));
    assert.match(await failure(cb.verifyBackup(s.cfg, s.deps)), /differ from what was backed up/);
    fs.writeFileSync(path.join(s.cfg.dir, 'manifest.json'), JSON.stringify(m));
    // one flipped byte in a file
    const good = fs.readFileSync(file), bad = Buffer.from(good); bad[bad.length - 40] ^= 0xff; fs.writeFileSync(file, bad);
    assert.match(await failure(cb.verifyBackup(s.cfg, s.deps)), /checksum mismatch/);
    // missing file
    fs.rmSync(file);
    assert.match(await failure(cb.verifyBackup(s.cfg, s.deps)), /file is missing/);
    assert.ok(s.scratches.every((x) => x.dropped), 'scratch dropped even when the test failed');
  } finally { s.cleanup(); }
});

test('restore into a new table is identical to the backup; into a live table it only adds; from/to select days', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [0, 1, 2, 3], 12); await fill(s.store, T2, [2], 4);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    const original = { t1: await all(s.store, T1), t2: await all(s.store, T2) };
    // a fresh table
    const fresh = new MemoryEventStore();
    const r = await cb.restoreEvents(s.cfg, { store: fresh, exact: true });
    assert.deepStrictEqual(r, { days: 4, restored: 52, already_there: 0 });
    assert.deepStrictEqual(await all(fresh, T1), original.t1); assert.deepStrictEqual(await all(fresh, T2), original.t2);
    // a live table that already has most of it, and one event the backup does not know
    const live = new MemoryEventStore();
    await live.insertBatch(T1, original.t1.slice(0, 30)); await live.insertBatch(T1, [{ source_type: 'syslog', raw: 'written after the disaster', received_at: at(0, 11) }]);
    const r2 = await cb.restoreEvents(s.cfg, { store: live, exact: false });
    assert.strictEqual(r2.restored, 52 - 30); assert.strictEqual(r2.already_there, 30);
    assert.strictEqual((await all(live, T1)).length, 48 + 1, 'nothing deleted, the extra event is still there');
    // a range
    const part = new MemoryEventStore();
    const r3 = await cb.restoreEvents(s.cfg, { store: part, exact: true }, { from: day(2), to: day(1) });
    assert.strictEqual(r3.days, 2); assert.strictEqual(r3.restored, 12 + 12 + 4);
    await assert.rejects(cb.restoreEvents(s.cfg, { store: part, exact: true }, { from: 'yesterday' }), /must be a day/);
    // an exact restore into a table that already holds other events of that day is reported, not hidden
    const dirty = new MemoryEventStore(); await dirty.insertBatch(T1, [{ source_type: 'syslog', raw: 'stray', received_at: at(3, 5) }]);
    await assert.rejects(cb.restoreEvents(s.cfg, { store: dirty, exact: true }), /holds \d+ events after the restore/);
  } finally { s.cleanup(); }
});

test('days that left the store (retention) stay in the backup for BACKUP_KEEP days, then are removed', async () => {
  const s = setup({ BACKUP_KEEP: '3' });
  try {
    await fill(s.store, T1, [0, 1, 2, 3], 5);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    // retention removes the two oldest days from the store
    s.store.tenants.set(T1, s.store.tenants.get(T1).filter((e) => e.received_at.slice(0, 10) >= day(1)));
    let r = await cb.backupEvents(s.cfg, s.deps, { now: NOW + 86400000 });
    assert.strictEqual(r.pruned, 0); assert.ok(cb.readManifest(s.cfg).days[day(3)], 'kept for now');
    assert.ok(cb.listBackup(s.cfg).days.find((d) => d.day === day(3)).gone_since);
    r = await cb.backupEvents(s.cfg, s.deps, { now: NOW + 3 * 86400000 });
    assert.strictEqual(r.pruned, 0, 'not yet: 2 days since it was noticed');
    r = await cb.backupEvents(s.cfg, s.deps, { now: NOW + 5 * 86400000 });
    assert.strictEqual(r.pruned, 2); assert.strictEqual(cb.readManifest(s.cfg).days[day(3)], undefined);
    assert.ok(s.files().every((f) => !f.includes(day(3)) && !f.includes(day(2))));
  } finally { s.cleanup(); }
});

test('a failure part way leaves the previous backup exactly as it was and no stray files; a running backup blocks a second; a stale lock does not', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [1, 2, 3], 10);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    const manifestBefore = fs.readFileSync(path.join(s.cfg.dir, 'manifest.json'), 'utf8'), filesBefore = s.files();
    await s.store.insertBatch(T1, [{ source_type: 'syslog', raw: 'new', received_at: at(2, 12) }, { source_type: 'syslog', raw: 'new', received_at: at(3, 12) }]);
    const realScan = s.store.scan.bind(s.store); let n = 0;
    s.store.scan = async (...a) => { if (++n === 2) throw new Error('clickhouse went away'); return realScan(...a); };
    assert.match(await failure(cb.backupEvents(s.cfg, s.deps, { now: NOW + 1000 })), /clickhouse went away/);
    assert.strictEqual(fs.readFileSync(path.join(s.cfg.dir, 'manifest.json'), 'utf8'), manifestBefore);
    assert.deepStrictEqual(s.files(), filesBefore); assert.deepStrictEqual(fs.readdirSync(s.tmp), []);
    s.store.scan = realScan;
    fs.writeFileSync(path.join(s.cfg.dir, '.lock'), 'someone');
    assert.match(await failure(cb.backupEvents(s.cfg, s.deps, { now: NOW + 2000 })), /another ClickHouse backup is running/);
    const old = new Date(Date.now() - 7 * 3600000); fs.utimesSync(path.join(s.cfg.dir, '.lock'), old, old);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW + 3000 });
  } finally { s.cleanup(); }
});

test('two runs in the same second never share a file name: a failure in the second leaves the first backup readable', async () => {
  const s = setup();
  try {
    await fill(s.store, T1, [0, 1, 2], 10);
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });
    const filesBefore = s.files(), manifestBefore = fs.readFileSync(path.join(s.cfg.dir, 'manifest.json'), 'utf8');
    await s.store.insertBatch(T1, [{ source_type: 'syslog', raw: 'more today', received_at: at(0, 2) }, { source_type: 'syslog', raw: 'more yesterday', received_at: at(1, 2) }]);
    const realScan = s.store.scan.bind(s.store); let n = 0;
    s.store.scan = async (...a) => { if (++n === 2) throw new Error('died in the middle of the second run'); return realScan(...a); };   // after the first re-exported day was written
    assert.match(await failure(cb.backupEvents(s.cfg, s.deps, { now: NOW })), /died in the middle/);     // the SAME now = the same second
    assert.deepStrictEqual(s.files(), filesBefore, 'every file of the first backup is still there, and nothing new is left behind');
    assert.strictEqual(fs.readFileSync(path.join(s.cfg.dir, 'manifest.json'), 'utf8'), manifestBefore);
    s.store.scan = realScan;
    assert.deepStrictEqual(await cb.verifyBackup(s.cfg, s.deps), { days: 3, rows: 30 }, 'the first backup still restores');
    await cb.backupEvents(s.cfg, s.deps, { now: NOW });                                                  // and a good run in the same second works
    assert.deepStrictEqual(await cb.verifyBackup(s.cfg, s.deps), { days: 3, rows: 32 });
    assert.strictEqual(new Set(s.files()).size, s.files().length);
  } finally { s.cleanup(); }
});

test('the digest is order independent and sees every field; a missing passphrase is refused', async () => {
  const base = { id: crypto.randomUUID(), tenant_id: T1, source_type: 's', collector_id: null, received_at: '2026-10-01T00:00:00.000Z', event_time: null, raw: 'r', parsed: { a: 1, b: { c: [1, 2] } } };
  const d = (...evs) => { const x = new cb.DayDigest(); evs.forEach((e) => x.add(e)); return x.hex(); };
  const e2 = { ...base, id: crypto.randomUUID(), raw: 'other' };
  assert.strictEqual(d(base, e2), d(e2, base));
  assert.strictEqual(d(base), d({ ...base, parsed: { b: { c: [1, 2] }, a: 1 }, received_at: '2026-10-01T00:00:00.000000Z' }));
  for (const change of [{ raw: 'R' }, { source_type: 'x' }, { collector_id: 'c' }, { event_time: '2026-10-01T00:00:01.000Z' }, { parsed: { a: 2, b: { c: [1, 2] } } }, { tenant_id: T2 }, { received_at: '2026-10-01T00:00:00.001Z' }]) {
    assert.notStrictEqual(d(base), d({ ...base, ...change }), JSON.stringify(change));
  }
  const s = setup({ BACKUP_PASSPHRASE: '' });
  try { assert.match(await failure(cb.backupEvents({ ...s.cfg, pass: '' }, s.deps, { now: NOW })), /BACKUP_PASSPHRASE/); } finally { s.cleanup(); }
});

test('the nightly entry point: skipped when ClickHouse is not deployed or switched off; otherwise records the run and tests the restore when due', async () => {
  const s = setup();
  const calls = [];
  const fakeDb = (verifiedRecently) => ({ query: async (sql, params) => { calls.push({ sql, params }); if (/INSERT INTO backup_runs/.test(sql)) return { rows: [{ id: 'run-1' }] }; if (/SELECT 1 FROM backup_runs/.test(sql)) return { rows: verifiedRecently ? [{ '?column?': 1 }] : [] }; return { rows: [] }; } });
  const env = { BACKUP_DIR: s.dir, BACKUP_TMP: s.tmp, BACKUP_PASSPHRASE: 'pw' };
  try {
    assert.match((await cb.runClickHouseBackup({ env, db: fakeDb(false) })).skipped, /not deployed/);
    assert.match((await cb.runClickHouseBackup({ env: { ...env, CLICKHOUSE_PASSWORD: 'x', BACKUP_CLICKHOUSE: '0' }, db: fakeDb(false) })).skipped, /off/);
    assert.strictEqual(calls.length, 0, 'nothing recorded when skipped');
    s.deps.store.init = async () => {};
    await fill(s.store, T1, [1, 2], 6);
    let r = await cb.runClickHouseBackup({ env: { ...env, BACKUP_CLICKHOUSE: '1' }, db: fakeDb(false), deps: s.deps });
    assert.strictEqual(r.verified, true); assert.strictEqual(r.days, 2);
    const done = calls.find((c) => /status='completed'/.test(c.sql)); assert.strictEqual(done.params[3], true); assert.deepStrictEqual(JSON.parse(done.params[2]), ['clickhouse:events']); assert.ok(done.params[1] > 0);
    assert.ok(calls.some((c) => /INSERT INTO backup_runs.*'clickhouse'/.test(c.sql)), 'recorded with kind clickhouse');
    assert.strictEqual(cb.readManifest(cb.config(env)).verified, true);
    // verified recently: no test restore this time
    calls.length = 0; s.scratches.length = 0;
    r = await cb.runClickHouseBackup({ env: { ...env, BACKUP_CLICKHOUSE: '1' }, db: fakeDb(true), deps: s.deps });
    assert.strictEqual(r.verified, false); assert.strictEqual(s.scratches.length, 0);
    // failure is recorded as failed and thrown
    s.deps.store.init = async () => { throw new Error('connection refused'); };
    calls.length = 0;
    await assert.rejects(cb.runClickHouseBackup({ env: { ...env, BACKUP_CLICKHOUSE: '1' }, db: fakeDb(true), deps: s.deps }), /connection refused/);
    assert.ok(calls.some((c) => /status='failed'/.test(c.sql) && /connection refused/.test(c.params[1])));
  } finally { s.cleanup(); }
});
