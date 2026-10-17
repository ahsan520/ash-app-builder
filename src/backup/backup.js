'use strict';
// Encrypted, verified PostgreSQL backups (ASIX database + Keycloak database + roles).
//
//   node src/backup/backup.js            run one backup (the nightly CronJob does this)
//
// For each database: pg_dump -Fc -> AES-256-GCM encrypted file in BACKUP_DIR. A small manifest
// (sizes + SHA-256 of each file) is written last, so a set without a manifest is incomplete.
// Every BACKUP_VERIFY_EVERY_DAYS days the set is also restored into a scratch database and
// compared with the source ("a backup you have not restored is a hope, not a backup").
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
});

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

    // keep the newest N sets
    const sets = fs.readdirSync(cfg.dir).filter((f) => /^asix-\d{8}T\d{6}Z\.manifest\.json$/.test(f)).sort().reverse();
    for (const old of sets.slice(cfg.keep)) { const base = old.replace('.manifest.json', ''); fs.readdirSync(cfg.dir).filter((f) => f.startsWith(base + '.')).forEach((f) => fs.rmSync(path.join(cfg.dir, f), { force: true })); }

    const bytes = manifest.files.reduce((a, f) => a + f.bytes, 0);
    await db.query("UPDATE backup_runs SET status='completed', finished_at=localtimestamp, bytes=$2, databases=$3::jsonb, verified=$4, verified_at=CASE WHEN $4 THEN localtimestamp END WHERE id=$1", [runId, bytes, JSON.stringify(cfg.dbs), manifest.verified]);
    return { set: setName, bytes, verified: manifest.verified, verification, kept: Math.min(sets.length, cfg.keep) };
  } catch (e) {
    made.forEach((f) => fs.rmSync(f, { force: true })); tmpFiles.forEach((f) => fs.rmSync(f, { force: true }));
    await db.query("UPDATE backup_runs SET status='failed', finished_at=localtimestamp, error=$2 WHERE id=$1", [runId, String(e.message).slice(0, 500)]).catch(() => {});
    throw e;
  }
}

module.exports = { runBackup, verifySet, config, stamp };

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
