'use strict';
// Overdue pauses (src/brokers/paused.js, src/collectors/pause-watch.js, the Paused column): a pause or resume asked from the Brokers page that is still not applied
// ASIX_PAUSE_OVERDUE_MIN minutes after the ask last changed. Pure rules; the database side is tests/broker-pause-overdue-db.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const paused = require('../src/brokers/paused');
const pw = require('../src/collectors/pause-watch');
const view = require('../src/brokers/broker-view');

const NOW = Date.parse('2026-10-23T12:00:00Z');
const ago = (min) => new Date(NOW - min * 60000).toISOString();
const row = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', inputs_paused: null, inputs_paused_at: null, config_paused_inputs: null, config_rejected_paused: null, config_reported_at: ago(1), ...o });
const st = (o, min) => paused.pausedState(row(o), NOW, min);
const KEY = 'brokerpause:b1';

describe('overdueMinutes: ASIX_PAUSE_OVERDUE_MIN', () => {
  it('defaults to 30 when unset, empty or unusable; 0 turns it off; 5 to 1440 is taken', () => {
    const m = (v) => paused.overdueMinutes(v === undefined ? {} : { ASIX_PAUSE_OVERDUE_MIN: v });
    for (const v of [undefined, '', '  ', 'abc', '4', '1441', '-5', '12.5', 'NaN']) assert.strictEqual(m(v), 30, String(v));
    assert.strictEqual(m('0'), 0); assert.strictEqual(m('5'), 5); assert.strictEqual(m('45'), 45); assert.strictEqual(m('1440'), 1440);
  });
});

describe('pausedState: overdue', () => {
  it('pending longer than the limit is overdue; the state itself does not change', () => {
    const a = st({ inputs_paused: 'file', inputs_paused_at: ago(40), config_paused_inputs: '' }, 30);
    assert.strictEqual(a.state, 'pending'); assert.strictEqual(a.overdue, true); assert.strictEqual(a.asked_at, ago(40));
    assert.strictEqual(st({ inputs_paused: 'file', inputs_paused_at: ago(29), config_paused_inputs: '' }, 30).overdue, false);
    assert.strictEqual(st({ inputs_paused: 'file', inputs_paused_at: ago(31), config_paused_inputs: '' }, 30).overdue, true);
  });
  it('a broker that never reported is overdue too (unknown)', () => {
    const a = st({ inputs_paused: 'http', inputs_paused_at: ago(60) }, 30);
    assert.strictEqual(a.state, 'unknown'); assert.strictEqual(a.overdue, true);
  });
  it('a resume that is not applied is overdue', () => {
    const a = st({ inputs_paused: null, inputs_paused_at: ago(60), config_paused_inputs: 'file' }, 30);
    assert.strictEqual(a.state, 'pending'); assert.deepStrictEqual(a.asked, []); assert.strictEqual(a.overdue, true);
  });
  it('never overdue: applied, rejected (own alert), stale (the disconnect alert covers it), nothing asked', () => {
    assert.strictEqual(st({ inputs_paused: 'file', inputs_paused_at: ago(600), config_paused_inputs: 'file' }, 30).overdue, false);
    const rej = st({ inputs_paused: 'file', inputs_paused_at: ago(600), config_paused_inputs: '', config_rejected_paused: 'file' }, 30);
    assert.strictEqual(rej.state, 'rejected'); assert.strictEqual(rej.overdue, false);
    const stale = st({ inputs_paused: 'file', inputs_paused_at: ago(600), config_paused_inputs: '', config_reported_at: ago(120) }, 30);
    assert.strictEqual(stale.state, 'stale'); assert.strictEqual(stale.overdue, false);
    assert.strictEqual(st({ inputs_paused_at: ago(600) }, 30).overdue, false);
  });
  it('an ask with no time (made before the column existed) is never overdue', () => {
    const a = st({ inputs_paused: 'file', inputs_paused_at: null, config_paused_inputs: '' }, 30);
    assert.strictEqual(a.state, 'pending'); assert.strictEqual(a.overdue, false); assert.strictEqual(a.asked_at, null);
  });
  it('0 turns it off; another limit moves the line; the limit comes from the environment by default', () => {
    const r = { inputs_paused: 'file', inputs_paused_at: ago(40), config_paused_inputs: '' };
    assert.strictEqual(st(r, 0).overdue, false); assert.strictEqual(st(r, 45).overdue, false); assert.strictEqual(st(r, 35).overdue, true);
    const saved = process.env.ASIX_PAUSE_OVERDUE_MIN;
    try {
      process.env.ASIX_PAUSE_OVERDUE_MIN = '0'; assert.strictEqual(paused.pausedState(row(r), NOW).overdue, false);
      process.env.ASIX_PAUSE_OVERDUE_MIN = '10'; assert.strictEqual(paused.pausedState(row(r), NOW).overdue, true);
    } finally { if (saved === undefined) delete process.env.ASIX_PAUSE_OVERDUE_MIN; else process.env.ASIX_PAUSE_OVERDUE_MIN = saved; }
  });
  it('the Brokers page data carries asked_at and overdue, and the summary counts overdue brokers', () => {
    const b = view.shape({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: ago(1), key_id: 'k1', installer_name: 'k', key_status: 'active', config_reported_at: ago(1),
      inputs_paused: 'file', inputs_paused_at: ago(90), config_paused_inputs: '' }, { now: NOW });
    assert.strictEqual(b.inputs_paused.overdue, true); assert.strictEqual(b.inputs_paused.asked_at, ago(90));
    assert.strictEqual(view.summarize([b]).paused_overdue, 1); assert.strictEqual(view.summarize([{ ...b, inputs_paused: { ...b.inputs_paused, overdue: false } }]).paused_overdue, 0);
    assert.deepStrictEqual(b.problems.filter((p) => /pause/i.test(JSON.stringify(p))), []);   // information only: not a "needs attention" problem
  });
});

const P = (o, opts) => pw.plan({ brokers: [row()], active: [], latest: [], ...o }, { now: NOW, overdueMin: 30, ...opts });
const late = (o = {}) => row({ inputs_paused: 'file', inputs_paused_at: ago(40), config_paused_inputs: '', ...o });

describe('plan: overdue', () => {
  it('raises one alert for a watched broker whose ask is overdue, with the time it was asked in the reference', () => {
    const p = P({ brokers: [late()] });
    assert.strictEqual(p.raise.length, 1);
    const r = p.raise[0];
    assert.strictEqual(r.group_key, KEY); assert.strictEqual(r.kind, 'overdue'); assert.strictEqual(r.state, 'pending'); assert.strictEqual(r.since_min, 40);
    assert.strictEqual(r.pause_ref, 'overdue:file@' + Date.parse(ago(40))); assert.deepStrictEqual(r.asked, ['file']);
  });
  it('raises nothing before the limit, with the limit off, for applied, stale and rejected-elsewhere brokers or non-brokers', () => {
    assert.deepStrictEqual(P({ brokers: [late({ inputs_paused_at: ago(20) })] }), { raise: [], close: [] });
    assert.deepStrictEqual(P({ brokers: [late()] }, { overdueMin: 0 }), { raise: [], close: [] });
    assert.deepStrictEqual(P({ brokers: [late({ config_paused_inputs: 'file' })] }), { raise: [], close: [] });
    assert.deepStrictEqual(P({ brokers: [late({ config_reported_at: ago(120) })] }), { raise: [], close: [] });
    assert.deepStrictEqual(P({ brokers: [late({ version: '1.2.3' })] }), { raise: [], close: [] });
    assert.deepStrictEqual(P({ brokers: [late({ inputs_paused_at: null })] }), { raise: [], close: [] });
  });
  it('a rejection wins over an overdue ask', () => {
    const p = P({ brokers: [late({ config_rejected_paused: 'file' })] });
    assert.strictEqual(p.raise.length, 1); assert.strictEqual(p.raise[0].kind, 'rejected'); assert.strictEqual(p.raise[0].pause_ref, 'rejected:file');
  });
  it('does not raise while an alert is open or acknowledged, nor again for the same ask after an analyst closed it', () => {
    const ref = 'overdue:file@' + Date.parse(ago(40));
    for (const status of ['open', 'acknowledged']) assert.deepStrictEqual(P({ brokers: [late()], active: [{ id: 'a1', group_key: KEY }], latest: [{ group_key: KEY, status, pause_ref: ref }] }), { raise: [], close: [] }, status);
    assert.deepStrictEqual(P({ brokers: [late()], latest: [{ group_key: KEY, status: 'closed', pause_ref: ref }] }), { raise: [], close: [] });
  });
  it('the same list asked again later is a new problem (a different ask time), and so is another list', () => {
    const old = 'overdue:file@' + Date.parse(ago(500));
    assert.strictEqual(P({ brokers: [late()], latest: [{ group_key: KEY, status: 'closed', pause_ref: old }] }).raise.length, 1);
    assert.strictEqual(P({ brokers: [late({ inputs_paused: 'http' })], latest: [{ group_key: KEY, status: 'closed', pause_ref: 'overdue:file@' + Date.parse(ago(40)) }] }).raise.length, 1);
  });
  it('closes when the broker applies it, when the ask is cleared, and when the broker is no longer watched', () => {
    const ref = 'overdue:file@' + Date.parse(ago(40)); const active = [{ id: 'a1', group_key: KEY }], latest = [{ group_key: KEY, status: 'open', pause_ref: ref }];
    assert.strictEqual(P({ brokers: [late({ config_paused_inputs: 'file' })], active, latest }).close.length, 1);
    assert.strictEqual(P({ brokers: [late({ inputs_paused: null, config_paused_inputs: null })], active, latest }).close.length, 1);
    assert.match(P({ brokers: [], active, latest }).close[0].reason, /no longer watched or was removed/);
  });
  it('an open overdue alert is closed when the broker then rejects the list, and the rejection is raised on the next cycle', () => {
    const active = [{ id: 'a1', group_key: KEY }], latest = [{ group_key: KEY, status: 'open', pause_ref: 'overdue:file@' + Date.parse(ago(40)) }];
    const p = P({ brokers: [late({ config_rejected_paused: 'file' })], active, latest });
    assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a1']); assert.match(p.close[0].reason, /different list/); assert.strictEqual(p.raise.length, 0);
  });
  it('raises nothing during the start-up grace', () => assert.deepStrictEqual(P({ brokers: [late()] }, { raiseAllowed: false }), { raise: [], close: [] }));
  it('the limit defaults to ASIX_PAUSE_OVERDUE_MIN when plan() is not told one', () => {
    const saved = process.env.ASIX_PAUSE_OVERDUE_MIN;
    try {
      process.env.ASIX_PAUSE_OVERDUE_MIN = '0';
      assert.strictEqual(pw.plan({ brokers: [late()], active: [], latest: [] }, { now: NOW }).raise.length, 0);
      delete process.env.ASIX_PAUSE_OVERDUE_MIN;
      assert.strictEqual(pw.plan({ brokers: [late()], active: [], latest: [] }, { now: NOW }).raise.length, 1);
    } finally { if (saved === undefined) delete process.env.ASIX_PAUSE_OVERDUE_MIN; else process.env.ASIX_PAUSE_OVERDUE_MIN = saved; }
  });
});

describe('raiseText: overdue', () => {
  const t = (r) => pw.raiseText({ name: 'broker-1', kind: 'overdue', asked: ['file', 'journald'], names: 'file, journald', since_min: 42, state: 'pending', ...r });
  it('says what was asked, how long ago, that it is still the old way, and where to look', () => {
    const x = t({});
    assert.strictEqual(x.title, 'Broker input pause not applied: broker-1');
    assert.match(x.summary, /asked to pause file, journald about 42 minutes ago and has not applied it, so those inputs are still running/);
    assert.match(x.summary, /reports a different list and has not rejected/); assert.match(x.summary, /asix-broker-config\.timer/); assert.match(x.summary, /--accept-config/);
  });
  it('a broker that never reported is said to have never reported; a resume says they are still paused', () => {
    assert.match(t({ state: 'unknown' }).summary, /never reported on this setting/);
    const r = t({ asked: [], names: 'none' }).summary; assert.match(r, /asked to resume its paused inputs/); assert.match(r, /they are still paused/);
  });
  it('the rejection text is unchanged', () => assert.match(pw.raiseText({ name: 'broker-1', kind: 'rejected', asked: ['file'], names: 'file' }).summary, /asked to pause file and rejected it: it put its old settings back/));
});

describe('Brokers page: Paused column, overdue', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
  const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n}\n', i) + 3); };
  const el = (tag, attrs, ...kids) => Object.assign({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) }, attrs || {});
  const pill = (text, cls) => ({ pill: text, cls });
  const LABEL = { file: 'Log files', http: 'HTTP/JSON', journald: 'Journal' };
  const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);
  const { brokerPausedCell } = new Function('el', 'pill', 'BROKER_INPUT_LABEL', line('const BROKER_PAUSABLE') + '\n' + line('const BROKER_PAUSE_STATE') + '\n' + cut('function brokerPausedCell(') + '\nreturn { brokerPausedCell };')(el, pill, LABEL);
  const shape = (o) => view.shape({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: ago(1), key_id: 'k1', installer_name: 'k', key_status: 'active', config_reported_at: ago(1), ...o }, { now: NOW });
  it('an overdue ask reads "Not applied" in the bad colour, with the time and the fix in the tooltip; a recent one still reads Pausing...', () => {
    const cell = brokerPausedCell(shape({ inputs_paused: 'file', inputs_paused_at: ago(90), config_paused_inputs: '' }));
    assert.deepStrictEqual(pills(cell), [{ text: 'Log files', cls: 'off' }, { text: 'Not applied', cls: 'bad' }]);
    assert.match(cell.title, /still not applied/); assert.match(cell.title, /asix-broker-config\.timer/);
    assert.deepStrictEqual(pills(brokerPausedCell(shape({ inputs_paused: 'file', inputs_paused_at: ago(5), config_paused_inputs: '' }))).map((p) => p.text), ['Log files', 'Pausing...']);
  });
  it('an overdue resume and a broker that never reported read the same; an applied pause is unchanged', () => {
    assert.deepStrictEqual(pills(brokerPausedCell(shape({ inputs_paused: null, inputs_paused_at: ago(90), config_paused_inputs: 'file' }))).map((p) => p.text), ['Not applied']);
    assert.deepStrictEqual(pills(brokerPausedCell(shape({ inputs_paused: 'http', inputs_paused_at: ago(90) }))).map((p) => p.text), ['HTTP/JSON', 'Not applied']);
    assert.deepStrictEqual(pills(brokerPausedCell(shape({ inputs_paused: 'file', inputs_paused_at: ago(90), config_paused_inputs: 'file' }))).map((p) => p.text), ['Log files', 'Paused']);
  });
});
