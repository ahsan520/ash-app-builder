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

describe('offsite-backup.sh pruning the other machine (--keep-days)', { skip: haveRsync ? false : 'rsync is not installed' }, () => {
  let tmp, src, dest, sqlFile;
  const DAY = 86400e3;
  const run = (args, extra = {}) => spawnSync('bash', [SCRIPT, ...args], { encoding: 'utf8', stdin: 'ignore',
    env: { PATH: process.env.PATH, BACKUP_DIR: src, ASIX_OFFSITE_ENV: path.join(tmp, 'none.env'), OFFSITE_PSQL: `cat > '${sqlFile}'`, ...extra } });
  const age = (f, days) => { const t = new Date(Date.now() - days * DAY); fs.utimesSync(f, t, t); };
  const put = (name, days, dir = dest) => { const f = path.join(dir, name); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, 'x'); age(f, days); return f; };
  const names = () => fs.readdirSync(dest).sort();
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'offsite-prune-')); src = path.join(tmp, 'src'); dest = path.join(tmp, 'dest'); sqlFile = path.join(tmp, 'sql.txt');
    fs.mkdirSync(src); fs.mkdirSync(dest);
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const reset = () => {
    for (const d of [src, dest]) { fs.rmSync(d, { recursive: true, force: true }); fs.mkdirSync(d); }
    fs.rmSync(sqlFile, { force: true });
    put('asix-NEW.enc', 1, src);
    put('asix-STILL-HERE-OLD.enc', 200, src);        // old but this VM still has it: must never be deleted on the other side
  };

  it('refuses a bad --keep-days, and --prune-preview without one', () => {
    reset();
    for (const v of ['6', '0', 'abc', '-3', '10000', '7.5']) assert.strictEqual(run(['--target', dest, '--keep-days', v]).status, 2, v);
    assert.strictEqual(run(['--target', dest, '--keep-days']).status, 2);
    assert.strictEqual(run(['--target', dest, '--prune-preview']).status, 2);
    assert.ok(!fs.existsSync(sqlFile));
  });
  it('does not prune at all without --keep-days', () => {
    reset(); put('asix-ANCIENT.enc', 400);
    const r = run(['--target', dest]); assert.strictEqual(r.status, 0, r.stderr); assert.doesNotMatch(r.stdout, /Prun/);
    assert.ok(names().includes('asix-ANCIENT.enc'));
  });
  it('--prune-preview lists the files and deletes nothing, copies nothing, records nothing', () => {
    reset(); put('asix-ANCIENT.enc', 400); put('asix-RECENT-GONE.enc', 30);
    const r = run(['--target', dest, '--keep-days', '60', '--prune-preview']); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /holds 2 asix-\* files; 1 are older than 60 days/); assert.match(r.stdout, /asix-ANCIENT\.enc/); assert.doesNotMatch(r.stdout, /RECENT-GONE|STILL-HERE/);
    assert.match(r.stdout, /Nothing was deleted/);
    assert.deepStrictEqual(names(), ['asix-ANCIENT.enc', 'asix-RECENT-GONE.enc']);
    assert.ok(!fs.existsSync(sqlFile), 'a preview records nothing');
    assert.ok(!fs.existsSync(path.join(dest, 'asix-NEW.enc')), 'a preview copies nothing');
  });
  it('after a good copy deletes only asix-* files that are older than N days AND gone from this VM', () => {
    reset(); put('asix-ANCIENT.enc', 400); put('asix-RECENT-GONE.enc', 30); put('sub/asix-ANCIENT2.enc', 90); put('notes-old.txt', 500);
    put('asix-STILL-HERE-OLD.enc', 200);              // same name as a file here
    const keep = (n) => assert.ok(fs.existsSync(path.join(dest, n)), `${n} must stay`);
    const r = run(['--target', dest, '--keep-days', '60']); assert.strictEqual(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Pruned 2 of 2 old file/);
    assert.ok(!fs.existsSync(path.join(dest, 'asix-ANCIENT.enc'))); assert.ok(!fs.existsSync(path.join(dest, 'sub', 'asix-ANCIENT2.enc')));
    ['asix-RECENT-GONE.enc', 'asix-STILL-HERE-OLD.enc', 'asix-NEW.enc', 'notes-old.txt'].forEach(keep);
    assert.match(fs.readFileSync(sqlFile, 'utf8'), /'completed'/);
  });
  it('refuses to delete more than half of the files unless --allow-large-prune, and says so', () => {
    reset(); for (let i = 0; i < 5; i++) put(`asix-OLD${i}.enc`, 100 + i);
    let r = run(['--target', dest, '--keep-days', '60']); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /more than half/); assert.strictEqual(names().filter((n) => n.startsWith('asix-OLD')).length, 5);
    assert.match(run(['--target', dest, '--keep-days', '60', '--prune-preview']).stdout, /more than half/);
    r = run(['--target', dest, '--keep-days', '60', '--allow-large-prune']); assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /Pruned 5 of 5/); assert.strictEqual(names().filter((n) => n.startsWith('asix-OLD')).length, 0);
  });
  it('never prunes after a failed copy, and refuses when this VM has no asix-* files', () => {
    reset(); const blocked = path.join(tmp, 'file-not-folder'); fs.writeFileSync(blocked, 'x');
    const r = run(['--target', path.join(blocked, 'sub'), '--keep-days', '60']); assert.strictEqual(r.status, 1); assert.doesNotMatch(r.stdout, /Prun/);
    reset(); put('asix-ANCIENT.enc', 400);
    const empty = path.join(tmp, 'empty'); fs.mkdirSync(empty, { recursive: true });
    const p = run(['--target', dest, '--keep-days', '60', '--prune-preview'], { BACKUP_DIR: empty }); assert.strictEqual(p.status, 2); assert.match(p.stderr, /no asix-\* files/);
    assert.ok(fs.existsSync(path.join(dest, 'asix-ANCIENT.enc')));
  });
  it('reads OFFSITE_KEEP_DAYS from the saved settings, and --keep-days off turns it off', () => {
    reset(); put('asix-ANCIENT.enc', 400);
    const env = path.join(tmp, 'saved.env'); fs.writeFileSync(env, `OFFSITE_TARGET='${dest}'\nOFFSITE_KEEP_DAYS='60'\n`);
    let r = run([], { ASIX_OFFSITE_ENV: env }); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /Pruned 1 of 1/);
    put('asix-ANCIENT.enc', 400);
    r = run(['--keep-days', 'off'], { ASIX_OFFSITE_ENV: env }); assert.strictEqual(r.status, 0, r.stderr); assert.doesNotMatch(r.stdout, /Prun/);
    assert.ok(fs.existsSync(path.join(dest, 'asix-ANCIENT.enc')));
  });
  it('leaves odd file names alone', () => {
    reset(); put('asix-ANCIENT.enc', 400); put('asix-odd name.enc', 400); put("asix-it's.enc", 400);
    const r = run(['--target', dest, '--keep-days', '60', '--allow-large-prune']); assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(path.join(dest, 'asix-odd name.enc'))); assert.ok(fs.existsSync(path.join(dest, "asix-it's.enc"))); assert.ok(!fs.existsSync(path.join(dest, 'asix-ANCIENT.enc')));
  });
});
