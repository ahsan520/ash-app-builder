'use strict';
// Age-based retention of the PostgreSQL backup sets (pruneSets in src/backup/backup.js), on a real temporary folder.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pruneSets, config, stamp } = require('../src/backup/backup');

const NOW = Date.parse('2026-10-30T02:17:00Z');
let dir, cfg;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prune-')); cfg = config({ BACKUP_DIR: dir, BACKUP_PASSPHRASE: 'x' }); });
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
// A complete set made `hoursAgo` hours before NOW: two dumps, the roles file and the manifest, like the real job writes.
const makeSet = (hoursAgo, { manifest = true } = {}) => {
  const name = 'asix-' + stamp(new Date(NOW - hoursAgo * 3600000));
  for (const f of ['asix_platform.dump.enc', 'keycloak.dump.enc', 'globals.sql.enc']) fs.writeFileSync(path.join(dir, `${name}.${f}`), 'x');
  if (manifest) fs.writeFileSync(path.join(dir, `${name}.manifest.json`), '{}');
  return name;
};
const left = () => fs.readdirSync(dir).sort();

describe('pruneSets', () => {
  it('deletes whole sets older than the retention and keeps the newer ones, every file of each', () => {
    const old = makeSet(72), edge = makeSet(49), day = makeSet(25), fresh = makeSet(1);
    const r = pruneSets(cfg, 2, NOW);
    assert.deepStrictEqual(r.removed, [old, edge].sort()); assert.deepStrictEqual(r.kept, [day, fresh].sort());
    assert.ok(left().every((f) => f.startsWith(day + '.') || f.startsWith(fresh + '.')), left().join(' ')); assert.strictEqual(left().length, 8);
  });
  it('"older than 2 days" means more than 48 hours: a set exactly 48 hours old stays', () => {
    const exact = makeSet(48); makeSet(1); assert.deepStrictEqual(pruneSets(cfg, 2, NOW).removed, []); assert.ok(left().some((f) => f.startsWith(exact)));
  });
  it('the newest complete set is never deleted, however old: a string of failed runs cannot leave nothing', () => {
    const a = makeSet(24 * 5), b = makeSet(24 * 9);
    const r = pruneSets(cfg, 2, NOW); assert.deepStrictEqual(r.removed, [b]); assert.deepStrictEqual(r.kept, [a]); assert.strictEqual(left().filter((f) => f.startsWith(a)).length, 4);
  });
  it('left-overs of a run that died (no manifest) go once they are past the retention, but a young one (a run that may be writing it) stays', () => {
    const dead = makeSet(60, { manifest: false }), writing = makeSet(0.1, { manifest: false }), good = makeSet(20);
    const r = pruneSets(cfg, 2, NOW); assert.deepStrictEqual(r.removed, [dead]); assert.ok(left().some((f) => f.startsWith(writing)) && left().some((f) => f.startsWith(good)));
  });
  it('an incomplete newer set does not stand in for the newest complete one', () => {
    const good = makeSet(24 * 4); makeSet(24 * 3, { manifest: false }); const r = pruneSets(cfg, 2, NOW);
    assert.deepStrictEqual(r.kept, [good]); assert.strictEqual(r.removed.length, 1);
  });
  it('touches nothing else: other files, other folders (ClickHouse day files) and odd names stay', () => {
    makeSet(100); makeSet(1); fs.mkdirSync(path.join(dir, 'clickhouse')); fs.writeFileSync(path.join(dir, 'clickhouse', 'events-2026-10-01.x.ndjson.gz.enc'), 'x'); fs.writeFileSync(path.join(dir, 'clickhouse', 'manifest.json'), '{}');
    fs.writeFileSync(path.join(dir, 'notes.txt'), 'x'); fs.writeFileSync(path.join(dir, 'asix-20200101.txt'), 'x'); fs.writeFileSync(path.join(dir, 'asix-20200101T000000Z'), 'x');
    pruneSets(cfg, 2, NOW); assert.ok(left().includes('notes.txt') && left().includes('asix-20200101.txt') && left().includes('asix-20200101T000000Z') && left().includes('clickhouse'));
    assert.deepStrictEqual(fs.readdirSync(path.join(dir, 'clickhouse')).sort(), ['events-2026-10-01.x.ndjson.gz.enc', 'manifest.json']);
  });
  it('an empty folder is fine; a longer retention keeps more', () => {
    assert.deepStrictEqual(pruneSets(cfg, 2, NOW), { removed: [], kept: [] }); makeSet(24 * 5); makeSet(1);
    assert.deepStrictEqual(pruneSets(cfg, 7, NOW).removed, []); assert.strictEqual(pruneSets(cfg, 4, NOW).removed.length, 1);
  });
});

describe('config: BACKUP_RETAIN_DAYS', () => {
  it('a whole number of 1 or more is used; anything else means "use the portal setting"', () => {
    assert.strictEqual(config({ BACKUP_RETAIN_DAYS: '2' }).retainDays, 2); assert.strictEqual(config({ BACKUP_RETAIN_DAYS: '30' }).retainDays, 30);
    for (const v of [undefined, '', '0', '-1', '1.5', 'x']) assert.strictEqual(config({ BACKUP_RETAIN_DAYS: v }).retainDays, null, String(v));
  });
});
