'use strict';
// The backup runner's decisions (src/backup/runner.js) with the settings store and the job replaced: what starts a job, with which trigger, and what never does.
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const control = require('../src/backup/control');
const { createRunner } = require('../src/backup/runner');

const NOW = Date.parse('2026-10-30T03:00:00Z'), SLOT = Date.parse('2026-10-30T02:17:00Z');
const saved = { ...control };
let state, calls;
beforeEach(() => {
  state = { settings: { enabled: true, time_utc: '02:17', days: [0, 1, 2, 3, 4, 5, 6], retain_days: 2, last_scheduled_at: new Date(SLOT).toISOString() }, request: null, loadError: null };
  calls = { marked: [], spawned: [] };
  control.load = async () => { if (state.loadError) throw new Error(state.loadError); return state.settings; };
  control.claimRequest = async () => { const r = state.request; state.request = null; return r; };
  control.markScheduled = async (_db, ms) => { calls.marked.push(ms); state.settings.last_scheduled_at = new Date(ms).toISOString(); };
});
afterEach(() => Object.assign(control, saved));
const make = (spawnJob, extra = {}) => createRunner({ db: {}, now: () => NOW, log: () => {}, spawnJob: spawnJob || (async (t) => { calls.spawned.push(t); return 0; }), ...extra });

describe('runner.tick', () => {
  it('nothing owed, nothing asked: idle, no job', async () => { const r = await make().tick(); assert.deepStrictEqual(r, { did: 'idle' }); assert.deepStrictEqual(calls.spawned, []); });
  it('"Back up now": one manual job, the request is taken (a second look finds nothing)', async () => {
    state.request = { by: 'u1' }; const run = make();
    assert.strictEqual((await run.tick()).did, 'manual'); assert.deepStrictEqual(calls.spawned, ['manual']);
    assert.strictEqual((await run.tick()).did, 'idle'); assert.deepStrictEqual(calls.spawned, ['manual']);
  });
  it('a scheduled time that is owed: one scheduled job and the slot is marked, so the next look does nothing', async () => {
    state.settings.last_scheduled_at = new Date(SLOT - 86400000).toISOString(); const run = make();
    assert.strictEqual((await run.tick()).did, 'scheduled'); assert.deepStrictEqual(calls.marked, [SLOT]); assert.deepStrictEqual(calls.spawned, ['scheduled']);
    assert.strictEqual((await run.tick()).did, 'idle'); assert.deepStrictEqual(calls.spawned, ['scheduled']);
  });
  it('never run before (null): the owed slot runs once', async () => { state.settings.last_scheduled_at = null; const run = make(); assert.strictEqual((await run.tick()).did, 'scheduled'); assert.strictEqual((await run.tick()).did, 'idle'); });
  it('a manual request while a scheduled time is also owed: one manual job, and the slot counts as done (no second backup right after)', async () => {
    state.settings.last_scheduled_at = null; state.request = { by: 'u1' }; const run = make();
    assert.strictEqual((await run.tick()).did, 'manual'); assert.deepStrictEqual(calls.marked, [SLOT]);
    assert.strictEqual((await run.tick()).did, 'idle'); assert.deepStrictEqual(calls.spawned, ['manual']);
  });
  it('schedule switched off: no scheduled job, but "Back up now" still works', async () => {
    state.settings.enabled = false; state.settings.last_scheduled_at = null; const run = make();
    assert.strictEqual((await run.tick()).did, 'idle'); state.request = { by: null };
    assert.strictEqual((await run.tick()).did, 'manual'); assert.deepStrictEqual(calls.marked, []);
  });
  it('one job at a time: a look while a job runs starts nothing and takes no request', async () => {
    let release; const gate = new Promise((r) => { release = r; });
    const run = make(async (t) => { calls.spawned.push(t); await gate; return 0; });
    state.request = { by: 'u1' }; const first = run.tick(); await new Promise((r) => setImmediate(r));
    assert.strictEqual(run.isBusy(), true); state.request = { by: 'u2' };
    assert.deepStrictEqual(await run.tick(), { did: 'busy' }); assert.deepStrictEqual(state.request, { by: 'u2' });
    release(); await first; assert.strictEqual(run.isBusy(), false); assert.strictEqual((await run.tick()).did, 'manual'); assert.deepStrictEqual(calls.spawned, ['manual', 'manual']);
  });
  it('a failing job (non-zero exit) is reported and does not stop later looks', async () => {
    state.request = { by: null }; const run = make(async () => 1); assert.deepStrictEqual(await run.tick(), { did: 'manual', code: 1 }); assert.strictEqual(run.isBusy(), false);
  });
  it('a job that cannot start is reported, not thrown, and the runner is free again', async () => {
    state.request = { by: null }; const run = make(async () => { throw new Error('spawn node ENOENT'); });
    const r = await run.tick(); assert.strictEqual(r.did, 'manual'); assert.match(r.error, /ENOENT/); assert.strictEqual(run.isBusy(), false);
  });
  it('the database being unreachable is reported, not thrown, and starts nothing', async () => {
    state.loadError = 'connection refused'; const r = await make().tick(); assert.strictEqual(r.did, 'error'); assert.match(r.error, /refused/); assert.deepStrictEqual(calls.spawned, []);
  });
});
