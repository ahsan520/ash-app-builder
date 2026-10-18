'use strict';
// Data safety report: the off-VM copy findings (src/storage/safety.js) with the database and the cluster replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const db = require('../src/db');
const kube = require('../src/capacity/kube');
const safety = require('../src/storage/safety');

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
const utc = (hoursAgo) => new Date(NOW - hoursAgo * 3600000).toISOString().replace('Z', '');
const run = (o) => ({ id: 'r', trigger: 'scheduled', set_name: null, status: 'completed', started_at: utc(1), finished_at: utc(1), bytes: '5000', databases: ['u@h:/p'], verified: true, verified_at: utc(1), error: null, ...o });

describe('Data safety: off-VM copy', () => {
  const savedQuery = db.query, savedSnap = kube.snapshot;
  let rows;
  before(() => {
    kube.snapshot = async () => ({ available: false, error: 'x' });
    db.query = async (sql) => ({ rows: /kind = 'offsite'/.test(sql) ? rows.offsite : /kind = 'clickhouse'/.test(sql) ? [] : rows.postgres });
  });
  after(() => { db.query = savedQuery; kube.snapshot = savedSnap; });
  const good = [run({ trigger: 'scheduled', finished_at: utc(8), started_at: utc(8), verified_at: utc(8) })];
  const ids = async (offsite) => { rows = { postgres: good, offsite }; const r = await safety.report(NOW); return { r, ids: r.warnings.map((w) => w.id) }; };

  it('with no copy ever made: the info finding says to set one up, and the report says not configured', async () => {
    const { r, ids: i } = await ids([]);
    assert.ok(i.includes('same_disk')); assert.strictEqual(r.offsite.configured, false); assert.strictEqual(r.offsite.fresh, false);
    const f = r.warnings.find((w) => w.id === 'same_disk'); assert.match(f.fix, /offsite-backup\.sh --install-timer/); assert.strictEqual(f.severity, 'info');
  });
  it('with a recent good copy: no off-VM finding at all, and the report shows it', async () => {
    const { r, ids: i } = await ids([run({ finished_at: utc(9) })]);
    assert.ok(!i.includes('same_disk')); assert.ok(!i.some((x) => x.startsWith('offsite_')));
    assert.strictEqual(r.offsite.fresh, true); assert.strictEqual(r.offsite.last_success.bytes, 5000);
  });
  it('a failed latest copy is a warning with the error, and the VM-only finding returns when no good copy is recent', async () => {
    const { r, ids: i } = await ids([run({ status: 'failed', error: 'rsync failed: Permission denied', verified: false, finished_at: utc(2) }), run({ finished_at: utc(60) })]);
    assert.ok(i.includes('offsite_failed')); assert.strictEqual(r.warnings.find((w) => w.id === 'offsite_failed').severity, 'warning');
    assert.match(r.warnings.find((w) => w.id === 'offsite_failed').detail, /Permission denied/); assert.ok(i.includes('same_disk'));
  });
  it('a failed latest copy with a good one from last night: still a warning, but the data is on another machine', async () => {
    const { ids: i } = await ids([run({ status: 'failed', error: 'e', finished_at: utc(1) }), run({ finished_at: utc(20) })]);
    assert.ok(i.includes('offsite_failed')); assert.ok(!i.includes('same_disk'));
  });
  it('stale: warning after 36 hours, critical after 72, and the verdict follows', async () => {
    let x = await ids([run({ finished_at: utc(40) })]);
    assert.strictEqual(x.r.warnings.find((w) => w.id === 'offsite_stale').severity, 'warning'); assert.notStrictEqual(x.r.verdict, 'critical');
    x = await ids([run({ finished_at: utc(100) })]);
    assert.strictEqual(x.r.warnings.find((w) => w.id === 'offsite_stale').severity, 'critical'); assert.strictEqual(x.r.verdict, 'critical');
    assert.ok(x.ids.includes('same_disk'));
  });
  it('a copy exactly at the limit counts as fresh', async () => {
    const { ids: i } = await ids([run({ finished_at: utc(36) })]); assert.ok(!i.includes('same_disk')); assert.ok(!i.includes('offsite_stale'));
  });
});
