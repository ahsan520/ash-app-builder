'use strict';
// The Paused column and the Inputs button on the Brokers page (src/portal/index.html): the functions are cut out of the page and run with small stand-ins
// for el(), pill(), openModal(), api() and route(), as in portal-broker-tls-own.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const view = require('../src/brokers/broker-view');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
// Like the page's el(): the attributes also become properties of the node (a checkbox's checked, a button's onclick and disabled), which the dialog reads and writes.
const el = (tag, attrs, ...kids) => Object.assign({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) }, attrs || {});
const pill = (text, cls) => ({ pill: text, cls });
const INPUT_LABEL = { syslog: 'Syslog', 'syslog-tls': 'Syslog TLS', file: 'Log files', http: 'HTTP/JSON', https: 'HTTPS/JSON', journald: 'Journal', wazuh: 'Windows events' };
const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);

const make = (io = {}) => new Function('el', 'pill', 'BROKER_INPUT_LABEL', 'api', 'openModal', 'route',
  line('const BROKER_PAUSABLE') + '\n' + line('const BROKER_PAUSE_STATE') + '\n' + line('const BROKER_PAUSE_HELP') + '\n' + cut('function brokerPausedCell(') + '\n' + cut('function brokerPauseNote(') + '\n' + cut('function brokerPauseEdit(') + '\nreturn { brokerPausedCell, brokerPauseNote, brokerPauseEdit };')(
  el, pill, INPUT_LABEL, io.api || (async () => ({})), io.openModal || (() => ({ box: { append() {} }, close() {} })), io.route || (() => {}));

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

// Every node of a stand-in tree, depth first.
const walk = (n) => (n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const text = (n) => walk(n).map((x) => x.attrs && x.attrs.textContent).filter(Boolean).join(' | ');

describe('Brokers page: the Inputs dialog', () => {
  // Opens the dialog the way the page does; `tick` is the list of inputs the operator ticks (null = leave as shown). Returns what happened.
  const open = (b, { fail } = {}) => {
    const calls = [], routes = []; let closed = 0, appended = null, tree = null;
    const { brokerPauseEdit } = make({
      openModal: (...kids) => { tree = kids; return { box: { append: (x) => { appended = x; } }, close: () => { closed++; } }; },
      api: async (p, o) => { calls.push({ p, o }); if (fail) throw new Error(fail); return {}; }, route: () => routes.push(1) });
    brokerPauseEdit(b);
    const all = [...tree, appended].flatMap(walk);
    const boxes = Object.fromEntries(all.filter((n) => n.tag === 'input' && n.type === 'checkbox').map((n, i) => [['file', 'http', 'journald', 'wazuh', 'wazuhalerts'][i], n]));
    const btn = (label) => all.find((n) => n.tag === 'button' && n.attrs.textContent === label);
    const err = all.find((n) => n.className === 'err');
    return { calls, routes, boxes, btn, err, tree, appended, closed: () => closed };
  };
  const inputs = [{ kind: 'syslog', port: 514 }, { kind: 'file' }];

  it('one checkbox per pausable input, in the fixed order, ticked for what is asked; syslog has none', () => {
    const d = open(shape({ inputs_paused: 'http,file', config_paused_inputs: 'http,file', inputs: undefined }));
    assert.deepStrictEqual(Object.keys(d.boxes), ['file', 'http', 'journald', 'wazuh', 'wazuhalerts']);
    assert.deepStrictEqual(Object.values(d.boxes).map((b) => b.checked), [true, true, false, false, false]);
    assert.match(text(d.tree), /Log files/); assert.match(text(d.tree), /Syslog and syslog over TLS cannot be paused/);
  });
  it('the note under each input says what it is doing now', () => {
    const { brokerPauseNote } = make();
    const note = (o, k) => brokerPauseNote(shape(o), k);
    assert.strictEqual(note({ inputs_paused: 'file', config_paused_inputs: 'file' }, 'file'), 'paused');
    assert.strictEqual(note({ inputs_paused: 'file', config_paused_inputs: '' }, 'file'), 'pause asked, not applied yet');
    assert.strictEqual(note({ inputs_paused: null, config_paused_inputs: 'journald' }, 'journald'), 'resume asked, not applied yet');
    assert.strictEqual(note({}, 'file'), '');                                           // the broker never said which inputs it runs
  });
  it('running and not-on-this-broker come from the heartbeat list', () => {
    const { brokerPauseNote } = make();
    const b = { name: 'broker-1', id: 'b1', inputs_paused: { state: 'none', asked: [], reported: null }, inputs };
    assert.strictEqual(brokerPauseNote(b, 'file'), 'running'); assert.strictEqual(brokerPauseNote(b, 'journald'), 'not on this broker');
  });
  it('Save sends the ticked list in the fixed order, closes the dialog and reloads', async () => {
    const d = open(shape({ inputs_paused: 'file' }));
    d.boxes.journald.checked = true; d.boxes.file.checked = true;
    await d.btn('Save').onclick();
    assert.deepStrictEqual(d.calls, [{ p: '/v1/brokers/b1/inputs-paused', o: { method: 'PUT', body: { paused: ['file', 'journald'] } } }]);
    assert.strictEqual(d.closed(), 1); assert.strictEqual(d.routes.length, 1);
  });
  it('unticking everything resumes everything', async () => {
    const d = open(shape({ inputs_paused: 'file,http' })); d.boxes.file.checked = false; d.boxes.http.checked = false;
    await d.btn('Save').onclick(); assert.deepStrictEqual(d.calls[0].o.body, { paused: [] });
  });
  it('Save with nothing changed sends nothing and just closes; Cancel does the same', async () => {
    const a = open(shape({ inputs_paused: 'file' })); await a.btn('Save').onclick();
    assert.deepStrictEqual(a.calls, []); assert.strictEqual(a.closed(), 1); assert.strictEqual(a.routes.length, 0);
    const c = open(shape({})); c.btn('Cancel').onclick(); assert.deepStrictEqual(c.calls, []); assert.strictEqual(c.closed(), 1);
  });
  it('a refusal from ASIX stays in the dialog, the page is not reloaded and Save works again', async () => {
    const d = open(shape({}), { fail: 'nope' }); d.boxes.http.checked = true; const save = d.btn('Save');
    await save.onclick();
    assert.strictEqual(d.err.textContent, 'nope'); assert.strictEqual(d.closed(), 0); assert.strictEqual(d.routes.length, 0); assert.strictEqual(save.disabled, false);
  });
});
