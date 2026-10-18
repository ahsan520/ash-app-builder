'use strict';
// scripts/offsite-backup.sh with a local folder as the target (rsync only, no ssh) and the database call replaced by a file.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'offsite-backup.sh');
const haveRsync = spawnSync('rsync', ['--version']).status === 0;

describe('offsite-backup.sh', { skip: haveRsync ? false : 'rsync is not installed' }, () => {
  let tmp, src, dest, sqlFile;
  const run = (args, extra = {}) => spawnSync('bash', [SCRIPT, ...args], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: process.env.PATH, BACKUP_DIR: src, ASIX_OFFSITE_ENV: path.join(tmp, 'none.env'), OFFSITE_PSQL: `cat > '${sqlFile}'`, ...extra } });
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'offsite-')); src = path.join(tmp, 'src'); dest = path.join(tmp, 'dest'); sqlFile = path.join(tmp, 'sql.txt');
    fs.mkdirSync(src);
    fs.writeFileSync(path.join(src, 'asix-20261017T021700Z-asix_platform.dump.enc'), Buffer.alloc(1500, 7));
    fs.writeFileSync(path.join(src, 'asix-20261017T021700Z.manifest.json'), '{"files":[]}');
    fs.writeFileSync(path.join(src, 'notes.txt'), 'not a backup');
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('refuses a missing or unsafe target, and nothing is recorded', () => {
    for (const args of [[], ['--target', 'x;rm -rf /'], ['--target', 'relative/path'], ['--target', 'u@h:relative'], ['--target', 'u@h:/a b']]) {
      const r = run(args); assert.strictEqual(r.status, 2, JSON.stringify(args)); assert.ok(!fs.existsSync(sqlFile));
    }
    assert.strictEqual(run(['--target', dest, '--port', 'abc']).status, 2);
    assert.strictEqual(run(['--target', dest, '--key', '/nonexistent/key']).status, 2);
  });
  it('--check changes nothing but the (created) folder, and records nothing', () => {
    const r = run(['--check', '--target', dest]); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /reachable and writable/);
    assert.ok(!fs.existsSync(sqlFile));
  });
  it('copies only asix-* files, owner-only, checks them, and records a completed offsite row', () => {
    const r = run(['--target', dest]); assert.strictEqual(r.status, 0, r.stderr + r.stdout); assert.match(r.stdout, /2 files copied and checked/);
    assert.deepStrictEqual(fs.readdirSync(dest).sort(), ['asix-20261017T021700Z-asix_platform.dump.enc', 'asix-20261017T021700Z.manifest.json']);
    assert.strictEqual(fs.statSync(path.join(dest, 'asix-20261017T021700Z.manifest.json')).mode & 0o077, 0, 'no group or other access');
    const sql = fs.readFileSync(sqlFile, 'utf8');
    assert.match(sql, /INSERT INTO backup_runs/); assert.match(sql, /'completed'/); assert.match(sql, /'offsite'/); assert.match(sql, /1512/); assert.match(sql, new RegExp(dest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  });
  it('repairs a changed copy on the next run and never deletes extra files on the other side', () => {
    const f = path.join(dest, 'asix-20261017T021700Z-asix_platform.dump.enc'); fs.appendFileSync(f, 'junk');
    fs.writeFileSync(path.join(dest, 'asix-OLD-pruned-here.enc'), 'kept');
    const r = run(['--target', dest]); assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(fs.readFileSync(f).equals(fs.readFileSync(path.join(src, 'asix-20261017T021700Z-asix_platform.dump.enc'))));
    assert.ok(fs.existsSync(path.join(dest, 'asix-OLD-pruned-here.enc')));
  });
  it('fails with exit 1 and records a failed row when the copy cannot be made', () => {
    fs.rmSync(sqlFile, { force: true });
    const blocked = path.join(tmp, 'file-not-folder'); fs.writeFileSync(blocked, 'x');
    const r = run(['--target', path.join(blocked, 'sub')]); assert.strictEqual(r.status, 1);
    const sql = fs.readFileSync(sqlFile, 'utf8'); assert.match(sql, /'failed'/); assert.match(sql, /'offsite'/); assert.match(sql, /false/);
  });
  it('refuses to run with nothing to copy, and records nothing', () => {
    fs.rmSync(sqlFile, { force: true });
    const empty = path.join(tmp, 'empty'); fs.mkdirSync(empty);
    const r = run(['--target', dest], { BACKUP_DIR: empty }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /nothing to copy/); assert.ok(!fs.existsSync(sqlFile));
  });
  it('still copies (exit 0) when recording fails, and says so', () => {
    const r = run(['--target', dest], { OFFSITE_PSQL: 'false' }); assert.strictEqual(r.status, 0); assert.match(r.stderr, /could not record/);
  });
});
