'use strict';
// The backup schedule rules (src/backup/schedule.js): what a settings change may contain, when a run is owed, when the next one is, how slow a schedule may be.
const { describe, it } = require('node:test');
const assert = require('assert');
const sch = require('../src/backup/schedule');

const T = (s) => Date.parse(s);
const base = { enabled: true, time_utc: '02:17', days: [0, 1, 2, 3, 4, 5, 6] };

describe('check: a settings change', () => {
  it('accepts each field alone and cleans the days (sorted, once each)', () => {
    assert.deepStrictEqual(sch.check({ enabled: false }), { value: { enabled: false } });
    assert.deepStrictEqual(sch.check({ time_utc: '23:59' }), { value: { time_utc: '23:59' } });
    assert.deepStrictEqual(sch.check({ days: [5, 1, 1, 3] }), { value: { days: [1, 3, 5] } });
    assert.deepStrictEqual(sch.check({ retain_days: 2 }), { value: { retain_days: 2 } });
    assert.deepStrictEqual(sch.check({}), { value: {} });
  });
  it('refuses what is not valid, naming the field', () => {
    for (const [b, re] of [[{ enabled: 'yes' }, /enabled/], [{ time_utc: '2:17' }, /time_utc/], [{ time_utc: '24:00' }, /time_utc/], [{ time_utc: '02:60' }, /time_utc/], [{ time_utc: 217 }, /time_utc/],
      [{ days: [] }, /days/], [{ days: [7] }, /days/], [{ days: [-1] }, /days/], [{ days: ['1'] }, /days/], [{ days: 'all' }, /days/], [{ days: [0, 1, 2, 3, 4, 5, 6, 0] }, /days/],
      [{ retain_days: 0 }, /retain_days/], [{ retain_days: 366 }, /retain_days/], [{ retain_days: 1.5 }, /retain_days/], [{ retain_days: '2' }, /retain_days/]]) {
      const r = sch.check(b); assert.ok(r.error && re.test(r.error), JSON.stringify(b));
    }
  });
});

describe('lastSlot and nextSlot', () => {
  it('daily: before today\'s time the last slot is yesterday\'s, after it today\'s; the next slot is the other way round', () => {
    assert.strictEqual(sch.lastSlot(base, T('2026-10-30T01:00:00Z')), T('2026-10-29T02:17:00Z'));
    assert.strictEqual(sch.lastSlot(base, T('2026-10-30T02:17:00Z')), T('2026-10-30T02:17:00Z'));
    assert.strictEqual(sch.lastSlot(base, T('2026-10-30T23:00:00Z')), T('2026-10-30T02:17:00Z'));
    assert.strictEqual(sch.nextSlot(base, T('2026-10-30T01:00:00Z')), T('2026-10-30T02:17:00Z'));
    assert.strictEqual(sch.nextSlot(base, T('2026-10-30T02:17:00Z')), T('2026-10-31T02:17:00Z'));
  });
  it('only the chosen weekdays count (2026-10-30 is a Friday)', () => {
    const monThu = { ...base, days: [1, 4] };
    assert.strictEqual(sch.lastSlot(monThu, T('2026-10-30T12:00:00Z')), T('2026-10-29T02:17:00Z'));   // Thursday
    assert.strictEqual(sch.nextSlot(monThu, T('2026-10-30T12:00:00Z')), T('2026-11-02T02:17:00Z'));   // Monday
    assert.strictEqual(sch.lastSlot({ ...base, days: [0] }, T('2026-10-30T12:00:00Z')), T('2026-10-25T02:17:00Z'));
  });
  it('crosses month and year ends in UTC', () => {
    assert.strictEqual(sch.lastSlot(base, T('2027-01-01T00:30:00Z')), T('2026-12-31T02:17:00Z'));
    assert.strictEqual(sch.nextSlot(base, T('2026-12-31T23:00:00Z')), T('2027-01-01T02:17:00Z'));
  });
  it('no days: null', () => { assert.strictEqual(sch.lastSlot({ ...base, days: [] }, Date.now()), null); assert.strictEqual(sch.nextSlot({ ...base, days: [] }, Date.now()), null); });
});

describe('due: is a scheduled run owed?', () => {
  const now = T('2026-10-30T03:00:00Z'), slot = T('2026-10-30T02:17:00Z');
  it('the latest slot has not run: owed; it has: not owed', () => {
    assert.strictEqual(sch.due(base, T('2026-10-29T02:17:05Z'), now), true);
    assert.strictEqual(sch.due(base, slot, now), false);
    assert.strictEqual(sch.due(base, slot + 5000, now), false);
  });
  it('never run (null): owed, so the first look after a deploy catches up', () => assert.strictEqual(sch.due(base, null, now), true));
  it('a slot missed while the VM was off still runs once when it is back, however late', () => {
    assert.strictEqual(sch.due(base, T('2026-10-25T02:17:00Z'), T('2026-10-30T20:00:00Z')), true);
    assert.strictEqual(sch.due(base, T('2026-10-30T20:00:30Z'), T('2026-10-30T20:01:00Z')), false);          // and only once
  });
  it('switched off: never owed; saving settings (last = now) means a time earlier today does not fire', () => {
    assert.strictEqual(sch.due({ ...base, enabled: false }, null, now), false);
    assert.strictEqual(sch.due(base, now, now), false);
    assert.strictEqual(sch.due(base, now, T('2026-10-31T02:17:00Z')), true);                                  // tomorrow's time does
  });
  it('a weekday that is not chosen is not owed', () => assert.strictEqual(sch.due({ ...base, days: [1] }, T('2026-10-26T02:17:00Z'), T('2026-10-30T12:00:00Z')), false));
});

describe('longestGapDays', () => {
  it('daily 1, Sun/Tue/Thu/Sat 2, Mon+Fri 4, one day a week 7, none null', () => {
    assert.strictEqual(sch.longestGapDays([0, 1, 2, 3, 4, 5, 6]), 1);
    assert.strictEqual(sch.longestGapDays([0, 2, 4, 6]), 2);        // Sun, Tue, Thu, Sat: gaps of 2, 2, 2 and (Sat -> Sun) 1
    assert.strictEqual(sch.longestGapDays([1, 5]), 4);
    assert.strictEqual(sch.longestGapDays([3]), 7);
    assert.strictEqual(sch.longestGapDays([]), null);
  });
});
