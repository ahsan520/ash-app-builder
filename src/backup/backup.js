'use strict';
// Encrypted, verified PostgreSQL backups (ASIX database + Keycloak database + roles).
//
//   node src/backup/backup.js            run one backup (the nightly CronJob does this)
//
// For each database: pg_dump -Fc -> AES-256-GCM encrypted file in BACKUP_DIR. A small manifest
// (sizes + SHA-256 of each file) is written last, so a set without a manifest is incomplete.
// Every BACKUP_VERIFY_EVERY_DAYS days the set is also restored into a scratch database and
// compared with the source ("a backup you have not restored is a hope, not a backup").
// Retention (Data safety > Backup control): before each run, sets older than the retention days (default 2, set in the portal, kept in backup_settings) are
// deleted, always keeping the newest complete set so a string of failed runs can never leave nothing; after a good run the same rule is applied again.
// Results go to the backup_runs table, which the portal's Data safety card reads. When ClickHouse is deployed, the same job then
// backs up the events held there (src/backup/clickhouse-backup.js).

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { encryptFile, decryptFile, sha256File } = require('./crypto');
const { run, ident, psql } = require('./pg');

const stamp = (d = new Date()) => d.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
const config = (env = process.env) => ({
  dir: env.BACKUP_DIR || '/backups', pass: env.BACKUP_PASSPHRASE, dbs: (env.BACKUP_DATABASES || 'asix_platform,keycloak').split(',').map((s) => s.trim()).filter(Boolean),
  keep: Math.max(1, Number(env.BACKUP_KEEP || 14)), verifyDays: Number(env.BACKUP_VERIFY_EVERY_DAYS ?? 7), tmp: env.BACKUP_TMP || os.tmpdir(), env,
  retainDays: Number.isInteger(Number(env.BACKUP_RETAIN_DAYS)) && Number(env.BACKUP_RETAIN_DAYS) >= 1 ? Number(env.BACKUP_RETAIN_DAYS) : null,   // overrides the portal setting; unset = use the portal setting
});

const SET_FILE_RE = /^(asix-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z)\.(.+)$/;
// Age-based retention. Deletes every set (all its files) made more than `retainDays` days before `now`, EXCEPT the newest complete set (the one with a manifest),
// which stays however old it is. A set with no manifest that old is left-over from a run that died, and goes too. Only asix-<stamp>.* files directly in the folder are
// looked at (the ClickHouse day files live in a sub-folder and are not touched). Returns { removed: [set names], kept: [set names] }.
function pruneSets(cfg, retainDays, now = Date.now()) {
  const sets = new Map();                                                                        // base -> { at, files, complete }
  for (const f of fs.readdirSync(cfg.dir)) {
    const m = SET_FILE_RE.exec(f); if (!m) continue;
    const s = sets.get(m[1]) || { at: Date.UTC(+m[2], +m[3] - 1, +m[4], +m[5], +m[6], +m[7]), files: [], complete: false };
    s.files.push(f); if (m[8] === 'manifest.json') s.complete = true; sets.set(m[1], s);
  }
  const newestComplete = [...sets.entries()].filter(([, s]) => s.complete).sort((a, b) => b[1].at - a[1].at)[0];
  const removed = [], kept = [];
  for (const [base, s] of sets) {
    const old = now - s.at > retainDays * 86400000;
    if (old && !(newestComplete && newestComplete[0] === base)) { s.files.forEach((f) => fs.rmSync(path.join(cfg.dir, f), { force: true })); removed.push(base); }
    else if (s.complete) kept.push(base);
  }
  return { removed: removed.sort(), kept: kept.sort() };
}

const tableCount = async (env, db) => Number(await psql(env, db, "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')"));

// Restore a decrypted dump into a throw-away database and check it looks like the source.
async function verifyDump(cfg, dumpFile, sourceDb) {
  const scratch = 'asix_verify_' + crypto.randomBytes(4).toString('hex');
  await psql(cfg.env, 'postgres', `CREATE DATABASE ${ident(scratch)}`);
  try {
    await run('pg_restore', ['--no-owner', '--no-privileges', '--exit-on-error', '-d', scratch, dumpFile], { env: cfg.env });
    const [a, b] = [await tableCount(cfg.env, scratch), await tableCount(cfg.env, sourceDb)];
    if (a !== b) throw new Error(`verification failed: restored ${a} tables, source has ${b}`);
    return { tables: a };
  } finally { await psql(cfg.env, 'postgres', `DROP DATABASE IF EXISTS ${ident(scratch)} WITH (FORCE)`).catch(() => {}); }
}

async function verifySet(cfg, setName, manifest) {
  const results = {};
  for (const f of manifest.files.filter((x) => x.kind === 'dump')) {
    const file = path.join(cfg.dir, f.name);
    if ((await sha256File(file)) !== f.sha256) throw new Error(`${f.name}: checksum mismatch (file is damaged)`);
    const plain = path.join(cfg.tmp, `${setName}.${f.db}.verify.dump`);
    try { await decryptFile(file, plain, cfg.pass); results[f.db] = await verifyDump(cfg, plain, f.db); }
    finally { fs.rmSync(plain, { force: true }); }
  }
  return results;
}

async function runBackup({ trigger = 'scheduled', env = process.env, db = require('../db') } = {}) {
  const cfg = config(env);
  if (!cfg.pass) throw new Error('BACKUP_PASSPHRASE is not set');
  fs.mkdirSync(cfg.dir, { recursive: true });
  // How many days to keep: BACKUP_RETAIN_DAYS if set, else the portal setting (backup_settings), else null = the older count-only rule below.
  let retainDays = cfg.retainDays;
  if (retainDays === null) { const v = await require('./control').retainDays(db).catch(() => null); retainDays = Number.isInteger(v) && v >= 1 ? v : null; }
  let pruned = [];
  if (retainDays !== null) {                                                                      // before the run: free the space first, but never let a prune problem stop the backup
    try { pruned = pruneSets(cfg, retainDays).removed; if (pruned.length) console.log('[backup] removed ' + pruned.length + ' set(s) older than ' + retainDays + ' day(s): ' + pruned.join(', ')); }
    catch (e) { console.error('[backup] could not remove old sets (continuing):', e.message); }
  }
  let setName, bump = 0;                                                    // two backups in the same second must not share a name
  do { setName = 'asix-' + stamp(new Date(Date.now() + bump * 1000)); bump += 1; } while (fs.readdirSync(cfg.dir).some((f) => f.startsWith(setName + '.')));
  const runId = (await db.query("INSERT INTO backup_runs (trigger, set_name) VALUES ($1, $2) RETURNING id", [trigger, setName])).rows[0].id;
  const made = [], tmpFiles = [];
  try {
    const manifest = { set: setName, created_at: new Date().toISOString(), trigger, tool: 'asix-backup/1', files: [], verified: false };
    const add = async (plain, outName, meta) => { const enc = path.join(cfg.dir, outName); made.push(enc); const r = await encryptFile(plain, enc, cfg.pass); manifest.files.push({ name: outName, ...meta, bytes: r.bytes, sha256: r.sha256 }); };
    for (const name of cfg.dbs) {
      const plain = path.join(cfg.tmp, `${setName}.${name}.dump`); tmpFiles.push(plain);
      await run('pg_dump', ['-Fc', '--no-password', '-d', name, '-f', plain], { env: cfg.env });
      await add(plain, `${setName}.${name}.dump.enc`, { db: name, kind: 'dump' });
      fs.rmSync(plain, { force: true });
    }
    const globals = path.join(cfg.tmp, `${setName}.globals.sql`); tmpFiles.push(globals);
    fs.writeFileSync(globals, (await run('pg_dumpall', ['--globals-only', '--no-password'], { env: cfg.env })).out, { mode: 0o600 });
    await add(globals, `${setName}.globals.sql.enc`, { kind: 'globals' });
    fs.rmSync(globals, { force: true });

    const due = cfg.verifyDays > 0 && !(await db.query("SELECT 1 FROM backup_runs WHERE verified AND finished_at > localtimestamp - ($1::int * interval '1 day') LIMIT 1", [cfg.verifyDays])).rows.length;
    let verification = null;
    if (due) { verification = await verifySet(cfg, setName, manifest); manifest.verified = true; manifest.verified_at = new Date().toISOString(); }
    const mf = path.join(cfg.dir, setName + '.manifest.json'); fs.writeFileSync(mf + '.tmp', JSON.stringify(manifest, null, 2), { mode: 0o600 }); fs.renameSync(mf + '.tmp', mf);

    if (retainDays !== null) { try { pruned = pruned.concat(pruneSets(cfg, retainDays).removed); } catch (e) { console.error('[backup] could not remove old sets (continuing):', e.message); } }   // the new set is now the newest complete one, so an older survivor can go
    // keep the newest N sets
    const sets = fs.readdirSync(cfg.dir).filter((f) => /^asix-\d{8}T\d{6}Z\.manifest\.json$/.test(f)).sort().reverse();
    for (const old of sets.slice(cfg.keep)) { const base = old.replace('.manifest.json', ''); fs.readdirSync(cfg.dir).filter((f) => f.startsWith(base + '.')).forEach((f) => fs.rmSync(path.join(cfg.dir, f), { force: true })); }

    const bytes = manifest.files.reduce((a, f) => a + f.bytes, 0);
    await db.query("UPDATE backup_runs SET status='completed', finished_at=localtimestamp, bytes=$2, databases=$3::jsonb, verified=$4, verified_at=CASE WHEN $4 THEN localtimestamp END WHERE id=$1", [runId, bytes, JSON.stringify(cfg.dbs), manifest.verified]);
    return { set: setName, bytes, verified: manifest.verified, verification, kept: Math.min(fs.readdirSync(cfg.dir).filter((f) => /^asix-\d{8}T\d{6}Z\.manifest\.json$/.test(f)).length, cfg.keep), pruned, retain_days: retainDays };
  } catch (e) {
    made.forEach((f) => fs.rmSync(f, { force: true })); tmpFiles.forEach((f) => fs.rmSync(f, { force: true }));
    await db.query("UPDATE backup_runs SET status='failed', finished_at=localtimestamp, error=$2 WHERE id=$1", [runId, String(e.message).slice(0, 500)]).catch(() => {});
    throw e;
  }
}

module.exports = { runBackup, verifySet, config, stamp, pruneSets };

if (require.main === module) {
  // PostgreSQL first, then ClickHouse (if it is deployed): one failing does not stop the other, and the job exits 1 if either failed.
  (async () => {
    const trigger = process.env.BACKUP_TRIGGER || 'scheduled';
    let failed = false;
    try { console.log('[backup] done', JSON.stringify(await runBackup({ trigger }))); } catch (e) { failed = true; console.error('[backup] FAILED:', e.message); }
    try { console.log('[backup] clickhouse', JSON.stringify(await require('./clickhouse-backup').runClickHouseBackup({ trigger }))); } catch (e) { failed = true; console.error('[backup] CLICKHOUSE FAILED:', e.message); }
    process.exit(failed ? 1 : 0);
  })();
}
