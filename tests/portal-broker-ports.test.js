'use strict';
// The Ports dialog on the Brokers page (src/portal/index.html): the functions are cut out of the page and run with small stand-ins for el(), openModal(), api()
// and route(), as in portal-broker-paused.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const view = require('../src/brokers/broker-view');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
const el = (tag, attrs, ...kids) => Object.assign({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) }, attrs || {});
const walk = (n) => (n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const text = (n) => walk(n).map((x) => x.attrs && x.attrs.textContent).filter(Boolean).join(' | ');

const make = (io = {}) => new Function('el', 'api', 'openModal', 'route',
  line('const BROKER_PORT_NOTE') + '\n' + cut('function brokerPortNote(') + '\n' + cut('function brokerPortsEdit(') + '\nreturn { brokerPortNote, brokerPortsEdit };')(
  el, io.api || (async () => ({})), io.openModal || (() => ({ box: { append() {} }, close() {} })), io.route || (() => {}));

const NOW = Date.parse('2026-10-22T12:00:00Z'), fresh = new Date(NOW - 60000);
const shape = (o, opts) => view.shape({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: fresh, key_id: 'k1', installer_name: 'k', key_status: 'active', config_reported_at: fresh, ...o }, { now: NOW, ...opts });

// Opens the dialog the way the page does and returns the inputs, the buttons and what the page was told.
const open = (b, { failOn } = {}) => {
  const calls = [], routes = []; let closed = 0, appended = null, tree = null;
  const { brokerPortsEdit } = make({
    openModal: (...kids) => { tree = kids; return { box: { append: (x) => { appended = x; } }, close: () => { closed++; } }; },
    api: async (p, o) => { calls.push({ p, o }); if (failOn && p.endsWith(failOn)) throw new Error('refused ' + failOn); return {}; }, route: () => routes.push(1) });
  brokerPortsEdit(b);
  const all = [...tree, appended].flatMap(walk);
  const texts = all.filter((n) => n.tag === 'input' && n.type === 'text'), box = all.find((n) => n.tag === 'input' && n.type === 'checkbox');
  const btn = (label) => all.find((n) => n.tag === 'button' && n.attrs.textContent === label);
  return { calls, routes, sys: texts[0], tls: texts[1], left: box, btn, err: all.find((n) => n.className === 'err'), tree, closed: () => closed };
};

describe('Brokers page: the Ports dialog', () => {
  it('shows the own ports and the leave-out flag as they are now', () => {
    const d = open(shape({ syslog_port_override: 2514, tls_port_override: 6515, syslog_port_exclude: true }, { syslogPort: 1514, tlsPort: 6514 }));
    assert.strictEqual(d.sys.value, '2514'); assert.strictEqual(d.tls.value, '6515'); assert.strictEqual(d.left.checked, true);
    const e = open(shape({}, { syslogPort: 1514 })); assert.strictEqual(e.sys.value, ''); assert.strictEqual(e.tls.value, ''); assert.strictEqual(e.left.checked, false);
  });
  it('a note under each port says what the broker did with it', () => {
    const { brokerPortNote } = make();
    const b = shape({ config_syslog_port: 514, config_tls_port: 0 }, { syslogPort: 1514, tlsPort: 6514 });
    assert.match(brokerPortNote(b.config), /asked, not applied yet.*port 1514/); assert.match(brokerPortNote(b.tls), /no TLS listener/);
    assert.match(brokerPortNote(shape({ config_syslog_port: 1514 }, { syslogPort: 1514 }).config), /applied on the broker \(port 1514\)/);
    assert.match(brokerPortNote(shape({ config_syslog_port: 514 }, {}).config), /listens on 514; ASIX asks for no port/);
    assert.strictEqual(brokerPortNote(null), '');
    assert.match(text(open(b).tree), /no TLS listener/);
  });
  it('Save sends only what changed, leave-out first, then syslog, then TLS, with trimmed text and null for empty', async () => {
    const d = open(shape({ syslog_port_override: 2514 }));
    d.left.checked = true; d.sys.value = ' '; d.tls.value = ' 6515 ';
    await d.btn('Save').onclick();
    assert.deepStrictEqual(d.calls, [
      { p: '/v1/brokers/b1/syslog-port-exclude', o: { method: 'PUT', body: { exclude: true } } },
      { p: '/v1/brokers/b1/syslog-port', o: { method: 'PUT', body: { syslog_port: null } } },
      { p: '/v1/brokers/b1/tls-port', o: { method: 'PUT', body: { tls_port: '6515' } } }]);
    assert.strictEqual(d.closed(), 1); assert.strictEqual(d.routes.length, 1);
  });
  it('changing one thing sends one call', async () => {
    const d = open(shape({ syslog_port_override: 2514 })); d.sys.value = '3514';
    await d.btn('Save').onclick(); assert.deepStrictEqual(d.calls, [{ p: '/v1/brokers/b1/syslog-port', o: { method: 'PUT', body: { syslog_port: '3514' } } }]);
    const f = open(shape({ syslog_port_exclude: true })); f.left.checked = false; await f.btn('Save').onclick();
    assert.deepStrictEqual(f.calls, [{ p: '/v1/brokers/b1/syslog-port-exclude', o: { method: 'PUT', body: { exclude: false } } }]);
  });
  it('nothing changed: Save and Cancel send nothing, close once and do not reload', async () => {
    const a = open(shape({ tls_port_override: 6515 })); a.sys.value = '  '; await a.btn('Save').onclick();
    assert.deepStrictEqual(a.calls, []); assert.strictEqual(a.closed(), 1); assert.strictEqual(a.routes.length, 0);
    const c = open(shape({})); c.btn('Cancel').onclick(); assert.deepStrictEqual(c.calls, []); assert.strictEqual(c.closed(), 1); assert.strictEqual(c.routes.length, 0);
  });
  it('a refusal stays in the dialog, later steps are not sent, Save works again, and a retry sends only what is left', async () => {
    const d = open(shape({}), { failOn: '/syslog-port' }); d.left.checked = true; d.sys.value = '22'; d.tls.value = '6515';
    const save = d.btn('Save'); await save.onclick();
    assert.strictEqual(d.err.textContent, 'refused /syslog-port'); assert.strictEqual(d.closed(), 0); assert.strictEqual(d.routes.length, 0); assert.strictEqual(save.disabled, false);
    assert.deepStrictEqual(d.calls.map((c) => c.p), ['/v1/brokers/b1/syslog-port-exclude', '/v1/brokers/b1/syslog-port']);   // TLS never sent
    d.sys.value = ''; d.calls.length = 0; await save.onclick();                                     // the leave-out already went through: not sent again
    assert.deepStrictEqual(d.calls.map((c) => c.p), ['/v1/brokers/b1/tls-port']); assert.strictEqual(d.closed(), 1); assert.strictEqual(d.routes.length, 1);
  });
  it('Cancel after a partly saved change reloads the page so it shows what was saved', async () => {
    const d = open(shape({}), { failOn: '/tls-port' }); d.left.checked = true; d.tls.value = '22'; await d.btn('Save').onclick();
    d.btn('Cancel').onclick(); assert.strictEqual(d.closed(), 1); assert.strictEqual(d.routes.length, 1);
  });
  it('the row has one Ports button wired to the dialog', () => assert.match(html, /textContent: 'Ports', title: '[^']*', onclick: \(\) => brokerPortsEdit\(b\)/));
});
