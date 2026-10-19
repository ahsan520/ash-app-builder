'use strict';
// Per-channel switch for "Resolved" messages: validation, the public view and the rule. No database.
const test = require('node:test');
const assert = require('assert');
const ch = require('../src/notifications/channels');
const rec = require('../src/notifications/recovered');

const base = { name: 'soc-slack' };

test('validateCommon: notify_recovered is null, true or false and nothing else', () => {
  assert.strictEqual(ch.validateCommon(base).notify_recovered, null, 'not given on a new channel: follow the server');
  assert.strictEqual(ch.validateCommon({ ...base, notify_recovered: true }).notify_recovered, true);
  assert.strictEqual(ch.validateCommon({ ...base, notify_recovered: false }).notify_recovered, false);
  assert.strictEqual(ch.validateCommon({ ...base, notify_recovered: null }).notify_recovered, null);
  for (const bad of ['true', 'on', 1, 0, {}, []]) {
    assert.throws(() => ch.validateCommon({ ...base, notify_recovered: bad }), (e) => e.code === 'INVALID_CONFIG' && /notify_recovered/.test(e.message), String(bad));
  }
});

test('validateCommon: an update that does not mention it keeps the stored value; null clears it', () => {
  const prev = { name: 'a', min_severity: 'high', enabled: true, notify_recovered: false };
  assert.strictEqual(ch.validateCommon({ enabled: false }, prev).notify_recovered, false, 'the Disable button must not reset it');
  assert.strictEqual(ch.validateCommon({ name: 'b' }, { ...prev, notify_recovered: true }).notify_recovered, true);
  assert.strictEqual(ch.validateCommon({ notify_recovered: null }, prev).notify_recovered, null);
  assert.strictEqual(ch.validateCommon({ notify_recovered: true }, { ...prev, notify_recovered: null }).notify_recovered, true);
  assert.strictEqual(ch.validateCommon({}, { name: 'a' }).notify_recovered, null, 'a row from before the column existed');
});

test('toPublic: shows the setting and whether the channel sends Resolved messages now', () => {
  const row = (v) => ({ id: 'x', name: 'a', type: 'slack', enabled: true, min_severity: 'high', notify_recovered: v });
  const cfg = { webhook_url: 'https://hooks.slack.com/services/T/B/x' };
  let p = ch.toPublic(row(null), cfg, false);
  assert.strictEqual(p.notify_recovered, null); assert.strictEqual(p.recovered_sending, false);
  p = ch.toPublic(row(null), cfg, true);
  assert.strictEqual(p.notify_recovered, null); assert.strictEqual(p.recovered_sending, true, 'follows the server variable');
  p = ch.toPublic(row(true), cfg, false);
  assert.strictEqual(p.notify_recovered, true); assert.strictEqual(p.recovered_sending, true, 'its own setting wins over the variable');
  p = ch.toPublic(row(false), cfg, true);
  assert.strictEqual(p.notify_recovered, false); assert.strictEqual(p.recovered_sending, false);
  p = ch.toPublic({ ...row(null), notify_recovered: undefined }, cfg);
  assert.strictEqual(p.notify_recovered, null); assert.strictEqual(p.recovered_sending, false, 'no column yet, no variable: off');
  assert.ok(!JSON.stringify(p).includes('hooks.slack.com/services'), 'still no secret in the answer');
});

test('channelWants: the channel decides, else the variable', () => {
  const on = { ASIX_NOTIFY_RECOVERED: 'true' }, off = { ASIX_NOTIFY_RECOVERED: 'false' }, none = {};
  assert.strictEqual(rec.channelWants(null, on), true);
  assert.strictEqual(rec.channelWants(null, off), false);
  assert.strictEqual(rec.channelWants(undefined, none), false);
  assert.strictEqual(rec.channelWants(true, off), true);
  assert.strictEqual(rec.channelWants(true, none), true);
  assert.strictEqual(rec.channelWants(false, on), false);
  assert.strictEqual(rec.channelWants(false, none), false);
});
