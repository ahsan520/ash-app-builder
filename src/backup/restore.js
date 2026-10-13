'use strict';
// Restore tool (run by scripts/restore-backup.sh through a one-off Kubernetes Job).
//
//   list                                   backup sets in BACKUP_DIR
//   verify <set>                           restore every database into scratch databases, compare, drop
//   restore <set> <db> [--as <newname>]    restore ONE database. Without --as it REPLACES <db>
//                                          (connections are terminated, database dropped and recreated
//                                          with its original owner); with --as it creates a copy.
//   globals <set>                          replay the roles file (disaster recovery on a fresh cluster)
//
// Replacing needs --yes. Nothing is ever restored from a file whose checksum or authentication fails.

const fs = require('fs');
const path = require('path');
const { decryptFile, sha256File } = require('./crypto');
const { run, ident, psql } = require('./pg');
const { config, verifySet } = require('./backup');

const manifestOf = (cfg, set) => {
  if (!/^asix-\d{8}T\d{6}Z$/.test(set)) throw new Error('invalid backup set name: ' + set);
  const f = path.join(cfg.dir, set + '.manifest.json');
  if (!fs.existsSync(f)) throw new Error(`no manifest for ${set}: the backup is missing or was never finished`);
  return JSON.parse(fs.readFileSync(f, 'utf8'));
};
function listSets(cfg) {
  return fs.readdirSync(cfg.dir).filter((f) => /^asix-\d{8}T\d{6}Z\.manifest\.json$/.test(f)).sort().reverse().map((f) => {
    const m = JSON.parse(fs.readFileSync(path.join(cfg.dir, f), 'utf8'));
    return { set: m.set, created_at: m.created_at, trigger: m.trigger, verified: m.verified, databases: m.files.filter((x) => x.kind === 'dump').map((x) => x.db), bytes: m.files.reduce((a, x) => a + x.bytes, 0) };
  });
}

async function decryptChecked(cfg, file, set) {
  const f = manifestOf(cfg, set).files.find((x) => x.name === file);
  if (!f) throw new Error(`${file} is not part of ${set}`);
  const enc = path.join(cfg.dir, f.name);
  if ((await sha256File(enc)) !== f.sha256) throw new Error(`${f.name}: checksum mismatch - the file is damaged, refusing to restore`);
  const plain = path.join(cfg.tmp, `restore.${f.name}.plain`); await decryptFile(enc, plain, cfg.pass); return plain;
}

async function restoreDb(cfg, set, dbName, { as = null, yes = false } = {}) {
  const m = manifestOf(cfg, set), f = m.files.find((x) => x.kind === 'dump' && x.db === dbName);
  if (!f) throw new Error(`${set} has no dump of "${dbName}" (it has: ${m.files.filter((x) => x.kind === 'dump').map((x) => x.db).join(', ')})`);
  if (!as && !yes) throw new Error(`restoring over "${dbName}" replaces it completely: pass --yes to confirm`);
  const plain = await decryptChecked(cfg, f.name, set);
  try {
    if (as) {                                                       // a copy under a new name, no ownership changes
      await psql(cfg.env, 'postgres', `CREATE DATABASE ${ident(as)}`);
      await run('pg_restore', ['--no-owner', '--no-privileges', '--exit-on-error', '-d', as, plain], { env: cfg.env });
      return { restored: dbName, as };
    }
    await psql(cfg.env, 'postgres', `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${dbName.replace(/'/g, '')}' AND pid <> pg_backend_pid()`);
    await run('pg_restore', ['--create', '--clean', '--if-exists', '--exit-on-error', '-d', 'postgres', plain], { env: cfg.env });
    return { restored: dbName, replaced: true };
  } finally { fs.rmSync(plain, { force: true }); }
}

async function restoreGlobals(cfg, set) {
  const f = manifestOf(cfg, set).files.find((x) => x.kind === 'globals'); if (!f) throw new Error(set + ' has no roles file');
  const plain = await decryptChecked(cfg, f.name, set);
  try { await run('psql', ['-X', '-q', '-d', 'postgres', '-f', plain], { env: cfg.env }); return { globals: true }; } finally { fs.rmSync(plain, { force: true }); }
}

module.exports = { listSets, restoreDb, restoreGlobals, manifestOf };

if (require.main === module) {
  const [cmd, set, db, ...rest] = process.argv.slice(2), cfg = config(), flag = (n) => rest.includes(n) || db === n;
  (async () => {
    if (cmd === 'list') return console.table(listSets(cfg));
    if (cmd === 'verify') return console.log(JSON.stringify(await verifySet(cfg, set, manifestOf(cfg, set))));
    if (cmd === 'restore') { const i = rest.indexOf('--as'); return console.log(JSON.stringify(await restoreDb(cfg, set, db, { as: i >= 0 ? rest[i + 1] : null, yes: flag('--yes') }))); }
    if (cmd === 'globals') return console.log(JSON.stringify(await restoreGlobals(cfg, set)));
    throw new Error('usage: restore.js list | verify <set> | restore <set> <db> [--as <name>] [--yes] | globals <set>');
  })().then(() => process.exit(0)).catch((e) => { console.error('[restore] FAILED:', e.message); process.exit(1); });
}
