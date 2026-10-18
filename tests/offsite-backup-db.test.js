'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql) and rsync:
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/offsite-backup-db.test.js
// Skips itself otherwise. The real script writes the real row, the real Data safety report reads it; only the cluster (volumes) is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const db = require('../src/db');
const kube = require('../src/capacity/kube');
kube.snapshot = async () => ({ available: false, error: 'no cluster in this test' });
const safety = require('../src/storage/safety');

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'offsite-db-'));
  const src = path.join(tmp, 'src'), dest = path.join(tmp, 'dest'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'asix-20261017T021700Z-asix_platform.dump.enc'), Buffer.alloc(2048, 3));
  const psql = `PGPASSWORD='${process.env.DB_PASSWORD}' psql -h '${process.env.DB_HOST || '127.0.0.1'}' -U '${process.env.DB_USER || 'asix_admin'}' -d '${process.env.DB_NAME || 'asix_platform'}' -v ON_ERROR_STOP=1 -q`;
  const run = (target) => spawnSync('bash', [path.join(__dirname, '..', 'scripts', 'offsite-backup.sh'), '--target', target],
    { encoding: 'utf8', stdin: 'ignore', env: { PATH: process.env.PATH, BACKUP_DIR: src, ASIX_OFFSITE_ENV: path.join(tmp, 'none.env'), OFFSITE_PSQL: psql } });
  const had = (await db.query("SELECT count(*)::int AS n FROM backup_runs WHERE kind = 'offsite'")).rows[0].n;
  try {
    let r = await safety.report();
    if (had === 0) assert.ok(r.warnings.some((w) => w.id === 'same_disk') && r.offsite.configured === false);

    let out = run(dest); assert.strictEqual(out.status, 0, out.stderr + out.stdout);
    r = await safety.report();
    assert.strictEqual(r.offsite.configured, true); assert.strictEqual(r.offsite.fresh, true);
    assert.strictEqual(r.offsite.last_success.bytes, 2048); assert.strictEqual(r.offsite.last_success.verified, true); assert.deepStrictEqual(r.offsite.last_success.databases, [dest]);
    assert.ok(!r.warnings.some((w) => w.id === 'same_disk' || w.id.startsWith('offsite_')), 'a fresh good copy clears the VM-only finding');
    assert.ok(!r.runs.some((x) => x.databases && x.databases[0] === dest), 'the offsite row is not mixed into the PostgreSQL backup history');

    const blocked = path.join(tmp, 'blocked'); fs.writeFileSync(blocked, 'x');
    out = run(path.join(blocked, 'sub')); assert.strictEqual(out.status, 1);
    r = await safety.report();
    const failed = r.warnings.find((w) => w.id === 'offsite_failed'); assert.ok(failed, 'a failed latest copy is reported'); assert.ok(failed.detail.length > 0);
    assert.strictEqual(r.offsite.fresh, true, 'last night\'s good copy still counts');
    console.log('offsite-backup-db: all checks passed');
  } finally {
    await db.query("DELETE FROM backup_runs WHERE kind = 'offsite' AND (databases->>0 LIKE $1)", [tmp + '%']).catch(() => {});
    fs.rmSync(tmp, { recursive: true, force: true });
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
