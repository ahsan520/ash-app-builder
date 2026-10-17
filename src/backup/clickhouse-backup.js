'use strict';
// Backup, test restore and restore of the events held in ClickHouse (Phase 3). The nightly job (src/backup/backup.js) runs this
// after the PostgreSQL backup; restore.js exposes ch-list / ch-verify / ch-restore.
//
// Layout, in BACKUP_DIR/clickhouse/ (next to the PostgreSQL sets; the same folder is on the VM disk, see the Data safety page):
//   events-<day>.<stamp>-<id>.ndjson.gz.enc  one file per UTC day of received_at, ALL tenants: gzip of one JSON event per line,
//                                          encrypted with the backup passphrase (AES-256-GCM, src/backup/crypto.js)
//   manifest.json                          per day: file, rows, digest, bytes, sha256, tenants. Written last, atomically.
//
// Incremental: a day is exported again only when its row count changed, or when it is one of the last two UTC days (still receiving
// events). So the first run reads everything and later runs read about two days. A day that disappeared from ClickHouse (retention) stays
// in the backup for BACKUP_KEEP more days (default 14) and is then removed, like the PostgreSQL sets.
//
// The test restore (about weekly, BACKUP_VERIFY_EVERY_DAYS): decrypt every file, load all of it into a scratch table, and compare each
// day's rows and a content digest (every field of every event) with what the manifest recorded when the day was exported. It proves
// the files are readable and complete, not just present. The scratch table is dropped afterwards.
//
// Everything goes through the event store interface (scan / insertBatch / groupCounts), so tests run it on in-memory stores.
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const readline = require('readline');
const crypto = require('crypto');
const { encryptFile, decryptFile, sha256File } = require('./crypto');

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const SCAN_PAGE = 1000, INSERT_BATCH = 1000, REFRESH_DAYS = 2, LOCK_STALE_MS = 6 * 3600 * 1000;
const dayStart = (d) => `${d}T00:00:00.000Z`;
const nextDay = (d) => new Date(Date.parse(dayStart(d)) + 86400000).toISOString().slice(0, 10);
const iso = (t) => (t === null || t === undefined ? null : new Date(t).toISOString());
const stamp = (d = new Date()) => d.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');

function config(env = process.env) {
  return {
    dir: path.join(env.BACKUP_DIR || '/backups', 'clickhouse'), pass: env.BACKUP_PASSPHRASE,
    keep: Math.max(1, Number(env.BACKUP_KEEP || 14)), verifyDays: Number(env.BACKUP_VERIFY_EVERY_DAYS ?? 7),
    tmp: env.BACKUP_TMP || os.tmpdir(), mode: String(env.BACKUP_CLICKHOUSE || 'auto').toLowerCase(), env,
  };
}

// ---- content digest: order independent, over every stored field -------------------------------------------------------
const canonical = (v) => (Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}' : JSON.stringify(v ?? null));
class DayDigest {
  constructor() { this.rows = 0; this.acc = Buffer.alloc(32); }
  add(e) {
    const h = crypto.createHash('sha256').update(canonical([e.id, e.tenant_id, e.source_type, e.collector_id ?? null, iso(e.received_at), iso(e.event_time), e.raw, e.parsed ?? {}])).digest();
    for (let i = 0; i < 32; i++) this.acc[i] ^= h[i];
    this.rows++;
  }
  hex() { return this.acc.toString('hex'); }
}

// Every event of the given tenants received in [day 00:00, min(next day, until)), through scan(): calls onEvents(batch).
async function eachEvent(store, tenants, day, until, onEvents) {
  const to = until && until < dayStart(nextDay(day)) ? until : dayStart(nextDay(day));
  for (const tenant of tenants) {
    let after = null;
    for (;;) {
      const page = await store.scan(tenant, { since: dayStart(day), until: to, limit: SCAN_PAGE, after, order: 'asc' });
      if (page.events.length) await onEvents(page.events);
      if (!page.next) break;
      after = page.next;
    }
  }
}

// ---- manifest and files ------------------------------------------------------------------------------------------------
const manifestPath = (cfg) => path.join(cfg.dir, 'manifest.json');
const readManifest = (cfg) => (fs.existsSync(manifestPath(cfg)) ? JSON.parse(fs.readFileSync(manifestPath(cfg), 'utf8')) : null);
function writeManifest(cfg, m) { const f = manifestPath(cfg); fs.writeFileSync(f + '.tmp', JSON.stringify(m, null, 2), { mode: 0o600 }); fs.renameSync(f + '.tmp', f); }
const emptyManifest = () => ({ tool: 'asix-ch-backup/1', created_at: new Date().toISOString(), updated_at: null, snapshot: null, days: {}, gone: {}, verified: false, verified_at: null });

function takeLock(cfg) {
  const f = path.join(cfg.dir, '.lock');
  try { fs.writeFileSync(f, String(process.pid) + ' ' + new Date().toISOString(), { flag: 'wx', mode: 0o600 }); }
  catch (e) {
    if (e.code !== 'EEXIST') throw e;
    if (Date.now() - fs.statSync(f).mtimeMs < LOCK_STALE_MS) throw new Error('another ClickHouse backup is running (or died recently): ' + f);
    fs.rmSync(f, { force: true }); return takeLock(cfg);
  }
  return () => fs.rmSync(f, { force: true });
}

// One day -> a gzip file of NDJSON in tmp. Returns { rows, digest, plain }.
async function exportDay(store, tenants, day, until, tmpFile) {
  const gz = zlib.createGzip(), out = fs.createWriteStream(tmpFile, { mode: 0o600 });
  gz.pipe(out);
  const dg = new DayDigest();
  const write = (s) => new Promise((res, rej) => gz.write(s, (e) => (e ? rej(e) : res())));
  const done = new Promise((res, rej) => { out.on('finish', res); out.on('error', rej); gz.on('error', rej); });
  try {
    await eachEvent(store, tenants, day, until, async (events) => { let s = ''; for (const e of events) { dg.add(e); s += JSON.stringify(e) + '\n'; } await write(s); });
  } finally { gz.end(); }
  await done;
  return { rows: dg.rows, digest: dg.hex() };
}

// Reads one encrypted day file, checking its checksum first; calls onBatch(tenantId, events[]) in batches of at most INSERT_BATCH.
async function readDayFile(cfg, entry, onBatch) {
  const enc = path.join(cfg.dir, entry.file);
  if (!fs.existsSync(enc)) throw new Error(`${entry.file}: the file is missing`);
  if ((await sha256File(enc)) !== entry.sha256) throw new Error(`${entry.file}: checksum mismatch (the file is damaged)`);
  const plain = path.join(cfg.tmp, `chrestore.${entry.file}.gz`);
  await decryptFile(enc, plain, cfg.pass);
  try {
    const rl = readline.createInterface({ input: fs.createReadStream(plain).pipe(zlib.createGunzip()), crlfDelay: Infinity });
    let batch = [], tenant = null, n = 0;
    const flush = async () => { if (batch.length) { await onBatch(tenant, batch); batch = []; } };
    for await (const line of rl) {
      if (!line) continue;
      const e = JSON.parse(line); n++;
      if ((tenant !== null && e.tenant_id !== tenant) || batch.length >= INSERT_BATCH) await flush();
      tenant = e.tenant_id; batch.push(e);
    }
    await flush();
    return n;
  } finally { fs.rmSync(plain, { force: true }); }
}

// ---- backup --------------------------------------------------------------------------------------------------------------
// deps: { store, tenants: async () => [tenantId], openScratch: async () => ({ store, drop }) } ; now injectable for tests
async function backupEvents(cfg, deps, { now = Date.now() } = {}) {
  if (!cfg.pass) throw new Error('BACKUP_PASSPHRASE is not set');
  fs.mkdirSync(cfg.dir, { recursive: true });
  const unlock = takeLock(cfg), tmpFiles = [], madeFiles = [];
  try {
    const manifest = readManifest(cfg) || emptyManifest();
    const snapshot = new Date(now - 5000).toISOString();            // events received in the last seconds may still be arriving: next run
    const tenants = await deps.tenants();
    // events per UTC day, over all tenants, up to the snapshot
    const perDay = new Map();                                       // day -> { rows, tenants: [] }
    for (const t of tenants) {
      const g = await deps.store.groupCounts(t, { by: 'day', until: snapshot });
      if (g.length >= 1000) throw new Error(`tenant ${t} has events on 1000 or more days: the backup cannot list them all`);
      for (const { key, events } of g) { const d = perDay.get(key) || { rows: 0, tenants: [] }; d.rows += events; d.tenants.push(t); perDay.set(key, d); }
    }
    const today = new Date(now).toISOString().slice(0, 10), recent = new Set(Array.from({ length: REFRESH_DAYS }, (_, i) => new Date(now - i * 86400000).toISOString().slice(0, 10)));
    const exported = [], superseded = [];
    for (const day of [...perDay.keys()].sort()) {
      const cur = perDay.get(day), old = manifest.days[day];
      if (old && old.rows === cur.rows && !recent.has(day)) { delete manifest.gone[day]; continue; }
      // unique per run AND per file: two runs in the same second must never write the same name (the earlier manifest still points at its files)
      const file = `events-${day}.${stamp(new Date(now))}-${crypto.randomBytes(3).toString('hex')}.ndjson.gz.enc`;
      const plain = path.join(cfg.tmp, `chbackup.${file}.gz`); tmpFiles.push(plain);
      const r = await exportDay(deps.store, cur.tenants, day, snapshot, plain);
      const enc = path.join(cfg.dir, file); madeFiles.push(enc);
      const e = await encryptFile(plain, enc, cfg.pass); fs.rmSync(plain, { force: true });
      if (old) superseded.push(old.file);
      manifest.days[day] = { file, rows: r.rows, digest: r.digest, bytes: e.bytes, sha256: e.sha256, tenants: cur.tenants, exported_at: new Date().toISOString() };
      delete manifest.gone[day];
      exported.push(day);
    }
    // days that left ClickHouse (retention): keep for `keep` days, then drop from the backup
    const pruned = [];
    for (const day of Object.keys(manifest.days)) {
      if (perDay.has(day)) continue;
      const since = manifest.gone[day] || (manifest.gone[day] = new Date(now).toISOString());
      if (now - Date.parse(since) > cfg.keep * 86400000) { superseded.push(manifest.days[day].file); delete manifest.days[day]; delete manifest.gone[day]; pruned.push(day); }
    }
    manifest.snapshot = snapshot; manifest.updated_at = new Date().toISOString(); manifest.tenants = tenants;
    writeManifest(cfg, manifest);
    // files no longer in the manifest (replaced days, pruned days, leftovers of an interrupted run)
    const live = new Set(Object.values(manifest.days).map((d) => d.file));
    for (const f of fs.readdirSync(cfg.dir)) if (/^events-.*\.enc$/.test(f) && !live.has(f)) fs.rmSync(path.join(cfg.dir, f), { force: true });
    const bytes = Object.values(manifest.days).reduce((a, d) => a + d.bytes, 0), rows = Object.values(manifest.days).reduce((a, d) => a + d.rows, 0);
    return { days: Object.keys(manifest.days).length, exported: exported.length, exported_days: exported, pruned: pruned.length, rows, bytes, today };
  } catch (e) {
    madeFiles.forEach((f) => fs.rmSync(f, { force: true }));       // the manifest was not (re)written, so nothing it names is touched
    throw e;
  } finally { tmpFiles.forEach((f) => fs.rmSync(f, { force: true })); unlock(); }
}

// ---- test restore: everything into a scratch table, then compare with the manifest -----------------------------------------
async function verifyBackup(cfg, deps) {
  if (!cfg.pass) throw new Error('BACKUP_PASSPHRASE is not set');
  const manifest = readManifest(cfg);
  if (!manifest) throw new Error('there is no ClickHouse backup yet (no manifest)');
  const days = Object.keys(manifest.days).sort();
  const scratch = await deps.openScratch();
  try {
    let rows = 0;
    for (const day of days) {
      const entry = manifest.days[day];
      await readDayFile(cfg, entry, async (tenant, events) => { await scratch.store.insertBatch(tenant, events); });
      const dg = new DayDigest();
      await eachEvent(scratch.store, entry.tenants, day, null, async (events) => { for (const e of events) dg.add(e); });
      if (dg.rows !== entry.rows) throw new Error(`${day}: restored ${dg.rows} events, the backup recorded ${entry.rows}`);
      if (dg.hex() !== entry.digest) throw new Error(`${day}: the restored events differ from what was backed up (same count, different content)`);
      rows += dg.rows;
    }
    return { days: days.length, rows };
  } finally { await scratch.drop().catch(() => {}); }
}

// ---- restore into a table (additive: it never deletes) -------------------------------------------------------------------
// target = { store, exact }: exact = the table is new and must end up identical to the backup. Optional from / to (inclusive days).
async function restoreEvents(cfg, target, { from, to } = {}) {
  if (!cfg.pass) throw new Error('BACKUP_PASSPHRASE is not set');
  const manifest = readManifest(cfg);
  if (!manifest) throw new Error('there is no ClickHouse backup yet (no manifest)');
  for (const [flag, v] of [['from', from], ['to', to]]) if (v && !DAY_RE.test(v)) throw new Error(`${flag} must be a day like 2026-10-17`);
  const days = Object.keys(manifest.days).sort().filter((d) => (!from || d >= from) && (!to || d <= to));
  let restored = 0, already = 0;
  for (const day of days) {
    const entry = manifest.days[day];
    await readDayFile(cfg, entry, async (tenant, events) => { const r = await target.store.insertBatch(tenant, events); restored += r.inserted; already += r.skipped; });
    let have = 0;
    for (const t of entry.tenants) have += (await target.store.groupCounts(t, { by: 'day', since: dayStart(day), until: dayStart(nextDay(day)) })).reduce((a, g) => a + g.events, 0);
    if (target.exact ? have !== entry.rows : have < entry.rows) throw new Error(`${day}: the table holds ${have} events after the restore, the backup has ${entry.rows}`);
  }
  return { days: days.length, restored, already_there: already };
}

function listBackup(cfg) {
  const m = readManifest(cfg);
  if (!m) return { exists: false, days: [] };
  return { exists: true, updated_at: m.updated_at, snapshot: m.snapshot, verified: m.verified, verified_at: m.verified_at,
    days: Object.keys(m.days).sort().map((d) => ({ day: d, rows: m.days[d].rows, bytes: m.days[d].bytes, tenants: m.days[d].tenants.length, exported_at: m.days[d].exported_at, gone_since: m.gone[d] || null })) };
}

// ---- production wiring: the real ClickHouse store, scratch tables ----------------------------------------------------------
function realDeps(env = process.env, db = require('../db')) {
  const { ClickHouseEventStore } = require('../events/clickhouse-store');
  const store = new ClickHouseEventStore();
  const openTable = async (table) => { const s = new ClickHouseEventStore({ table }); await s.ensureSchema(); return s; };
  return {
    store, openTable,
    tenants: async () => (await db.query('SELECT id FROM tenants ORDER BY created_at, id')).rows.map((r) => r.id),
    openScratch: async () => { const table = 'events_verify_' + crypto.randomBytes(5).toString('hex'); const s = await openTable(table); return { store: s, drop: () => s.dropTable() }; },
  };
}

// The nightly entry point: back up, record in backup_runs (kind 'clickhouse'), and test-restore when it is due.
// Enabled by BACKUP_CLICKHOUSE=1, or in auto mode (default) when the ClickHouse password is in the environment (= ClickHouse was deployed).
async function runClickHouseBackup({ trigger = 'scheduled', env = process.env, db = require('../db'), deps = null } = {}) {
  const cfg = config(env);
  if (cfg.mode === '0' || cfg.mode === 'off') return { skipped: 'BACKUP_CLICKHOUSE is off' };
  if (cfg.mode !== '1' && !deps && !env.CLICKHOUSE_PASSWORD) return { skipped: 'ClickHouse is not deployed (no CLICKHOUSE_PASSWORD); set BACKUP_CLICKHOUSE=1 to force' };
  deps = deps || realDeps(env, db);
  const t0 = new Date(), setName = 'asix-ch-' + stamp(t0).replace(/Z$/, '') + String(t0.getUTCMilliseconds()).padStart(3, '0') + 'Z';   // to the millisecond: two runs in one second stay distinguishable
  const runId = (await db.query("INSERT INTO backup_runs (trigger, set_name, kind) VALUES ($1, $2, 'clickhouse') RETURNING id", [trigger, setName])).rows[0].id;
  try {
    await deps.store.init();
    const res = await backupEvents(cfg, deps);
    const due = cfg.verifyDays > 0 && !(await db.query("SELECT 1 FROM backup_runs WHERE kind = 'clickhouse' AND verified AND finished_at > localtimestamp - ($1::int * interval '1 day') LIMIT 1", [cfg.verifyDays])).rows.length;
    let verification = null;
    if (due && res.days > 0) {
      verification = await verifyBackup(cfg, deps);
      const m = readManifest(cfg); m.verified = true; m.verified_at = new Date().toISOString(); writeManifest(cfg, m);
    }
    await db.query("UPDATE backup_runs SET status='completed', finished_at=localtimestamp, bytes=$2, databases=$3::jsonb, verified=$4, verified_at=CASE WHEN $4 THEN localtimestamp END WHERE id=$1",
      [runId, res.bytes, JSON.stringify(['clickhouse:events']), !!verification]);
    return { set: setName, ...res, verified: !!verification, verification };
  } catch (e) {
    await db.query("UPDATE backup_runs SET status='failed', finished_at=localtimestamp, error=$2 WHERE id=$1", [runId, String(e.message).slice(0, 500)]).catch(() => {});
    throw e;
  }
}

module.exports = { config, DayDigest, canonical, backupEvents, verifyBackup, restoreEvents, listBackup, readManifest, runClickHouseBackup, realDeps, TABLE_RE, DAY_RE };
