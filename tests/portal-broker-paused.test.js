'use strict';
// The Paused column and the Inputs button on the Brokers page (src/portal/index.html): the functions are cut out of the page and run with small stand-ins
// for el(), pill(), api(), prompt(), alert() and route(), as in portal-broker-tls-own.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const view = require('../src/brokers/broker-view');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
const el = (tag, attrs, ...kids) => ({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const INPUT_LABEL = { syslog: 'Syslog', 'syslog-tls': 'Syslog TLS', file: 'Log files', http: 'HTTP/JSON', https: 'HTTPS/JSON', journald: 'Journal' };
const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);

const make = (io = {}) => new Function('el', 'pill', 'BROKER_INPUT_LABEL', 'api', 'prompt', 'alert', 'route',
  line('const BROKER_PAUSABLE') + '\n' + line('const BROKER_PAUSE_STATE') + '\n' + cut('function brokerPausedCell(') + '\n' + cut('async function brokerPauseEdit(') + '\nreturn { brokerPausedCell, brokerPauseEdit };')(
  el, pill, INPUT_LABEL, io.api || (async () => ({})), io.prompt || (() => null), io.alert || (() => {}), io.route || (() => {}));

const NOW = Date.parse('2026-10-22T12:00:00Z'), fresh = new Date(NOW - 60000), old = new Date(NOW - 3600000);
const shape = (o) => view.shape({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: fresh, key_id: 'k1', installer_name: 'k', key_status: 'active', config_reported_at: fresh, ...o }, { now: NOW });

describe('Brokers page: paused inputs', () => {
  const { brokerPausedCell } = make();
  it('nothing paused or asked: a dash', () => { assert.deepStrictEqual(pills(brokerPausedCell(shape({}))), []); assert.deepStrictEqual(pills(brokerPausedCell(shape({ config_paused_inputs: '' }))), []); });
  it('asked and applied: the names and Paused', () => assert.deepStrictEqual(pills(brokerPausedCell(shape({ inputs_paused: 'file,journald', config_paused_inputs: 'file,journald' }))).map((p) => p.text), ['Log files, Journal', 'Paused']));
  it('asked, not yet applied / stale / rejected / never reported', () => {
    const t = (o) => pills(brokerPausedCell(shape(o))).map((p) => p.text)[1];
    assert.strictEqual(t({ inputs_paused: 'http', config_paused_inputs: '' }), 'Pausing...');
    assert.strictEqual(t({ inputs_paused: 'http', config_paused_inputs: '', config_reported_at: old }), 'Not reporting');
    assert.strictEqual(t({ inputs_paused: 'http', config_paused_inputs: '', config_rejected_paused: 'http' }), 'Rejected');
    assert.strictEqual(t({ inputs_paused: 'http' }), 'Not reporting');
  });
  it('resume asked while the broker still has something paused: Resuming', () => assert.deepStrictEqual(pills(brokerPausedCell(shape({ inputs_paused: null, config_paused_inputs: 'file' }))).map((p) => p.text), ['Resuming...']));
});

describe('Brokers page: the Inputs button', () => {
  const run = async (answer, b = shape({ inputs_paused: 'file' })) => {
    const calls = [], alerts = [], routes = []; let asked;
    const { brokerPauseEdit } = make({ prompt: (m, d) => { asked = { m, d }; return answer; }, api: async (p, o) => { calls.push({ p, o }); if (answer === 'FAIL') throw new Error('nope'); return {}; }, alert: (m) => alerts.push(m), route: () => routes.push(1) });
    await brokerPauseEdit(b); return { calls, alerts, routes, asked };
  };
  it('offers what is paused now, sends the list, and reloads', async () => {
    const r = await run('Journald, FILE'); assert.strictEqual(r.asked.d, 'file'); assert.match(r.asked.m, /Syslog cannot be paused/);
    assert.deepStrictEqual(r.calls, [{ p: '/v1/brokers/b1/inputs-paused', o: { method: 'PUT', body: { paused: ['journald', 'file'] } } }]); assert.strictEqual(r.routes.length, 1);
  });
  it('an empty answer resumes everything; Cancel does nothing', async () => {
    assert.deepStrictEqual((await run('')).calls[0].o.body, { paused: [] });
    const c = await run(null); assert.deepStrictEqual(c.calls, []); assert.strictEqual(c.routes.length, 0);
  });
  it('a refusal from ASIX is shown, and the page is not reloaded', async () => { const r = await run('FAIL'); assert.deepStrictEqual(r.alerts, ['nope']); assert.strictEqual(r.routes.length, 0); });
});
