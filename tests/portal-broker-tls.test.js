'use strict';
// The "TLS port" column and the summary beside the TLS port row on the Brokers page (src/portal/index.html). The page has no build step, so the two functions
// are cut out of the file and run here with small stand-ins for el(), pill() and when().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, attrs, ...kids) => ({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const when = (t) => 'T' + (t ? '' : '?');
const { brokerTlsCell, brokerTlsSummary } = new Function('el', 'pill', 'when', cut('brokerTlsCell') + '\n' + cut('brokerTlsSummary') + '\nreturn { brokerTlsCell, brokerTlsSummary };')(el, pill, when);
const texts = (n) => (n && typeof n === 'object' ? [n.pill, n.attrs && n.attrs.textContent, n.attrs && n.attrs.title, ...(n.kids || []).flatMap(texts)] : [n]).filter((x) => typeof x === 'string' && x);
const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);

const NOW = Date.parse('2026-10-18T12:00:00Z');
const state = (configured, r, extra = {}) => ({ tls: config.tlsState(configured, { config_reported_at: new Date(NOW - 120000).toISOString().replace('Z', ''), ...r }, NOW), ...extra });

describe('Brokers page: TLS port cell', () => {
  it('one pill per state, the right colour', () => {
    assert.deepStrictEqual(pills(brokerTlsCell(state(6515, { config_tls_port: 6515 }))), [{ text: 'Applied 6515', cls: 'ok' }]);
    assert.deepStrictEqual(pills(brokerTlsCell(state(6515, { config_tls_port: 6514 }))), [{ text: 'Pending 6515', cls: 'off' }]);
    assert.deepStrictEqual(pills(brokerTlsCell(state(6515, { config_tls_port: 6514, config_rejected_tls_port: 6515 }))), [{ text: 'Rejected 6515', cls: 'bad' }]);
    assert.deepStrictEqual(pills(brokerTlsCell(state(6515, { config_tls_port: 6514, config_reported_at: new Date(NOW - 3600000).toISOString().replace('Z', '') }))), [{ text: 'Not asking', cls: 'bad' }]);
    assert.deepStrictEqual(pills(brokerTlsCell(state(6515, { config_tls_port: 0 }))), [{ text: 'No TLS listener', cls: 'off' }]);
    assert.deepStrictEqual(pills(brokerTlsCell(state(6515, {}))), [{ text: 'Not reporting', cls: 'off' }]);
  });
  it('the old port is shown next to a pending or rejected port, and the tooltips say what to do', () => {
    assert.match(texts(brokerTlsCell(state(6515, { config_tls_port: 6514 }))).join(' '), /\(now 6514\)/);
    assert.match(texts(brokerTlsCell(state(6515, { config_tls_port: 6514, config_rejected_tls_port: 6515 }))).join(' '), /journalctl -u asix-broker-config/);
    assert.match(texts(brokerTlsCell(state(6515, { config_tls_port: 0 }))).join(' '), /--tls-cert and --tls-key/);
    assert.match(texts(brokerTlsCell(state(6515, {}))).join(' '), /--accept-config/);
  });
  it('nothing asked: the port the listener uses, or a dash, and a note when the broker is left out', () => {
    assert.deepStrictEqual(texts(brokerTlsCell(state(null, { config_tls_port: 6514 }))), ['6514']);
    assert.deepStrictEqual(texts(brokerTlsCell(state(null, {}))), ['-']);
    assert.match(texts(brokerTlsCell(state(null, { config_tls_port: 6514 }, { config: { excluded: true } }))).join(' '), /Left out/);
  });
  it('a broker object without the field does not throw', () => {
    assert.doesNotThrow(() => brokerTlsCell({})); assert.deepStrictEqual(texts(brokerTlsCell({})), ['-']);
  });
});

describe('Brokers page: TLS summary', () => {
  const sum = (o) => ({ tls_applied: 0, tls_not_applied: 0, tls_no_listener: 0, ...o });
  it('all applied is ok, any not applied is bad, nobody asked shows nothing', () => {
    assert.deepStrictEqual(pills(brokerTlsSummary(sum({ tls_applied: 2 }))), [{ text: 'All 2 applied', cls: 'ok' }]);
    assert.deepStrictEqual(pills(brokerTlsSummary(sum({ tls_applied: 1, tls_not_applied: 2 }))), [{ text: '1 of 3 applied', cls: 'bad' }]);
    assert.deepStrictEqual(pills(brokerTlsSummary(sum())), []);
    assert.strictEqual(brokerTlsSummary(undefined), '');
  });
  it('brokers without a TLS listener are counted on their own, not as failures', () => {
    const s = brokerTlsSummary(sum({ tls_applied: 1, tls_no_listener: 2 }));
    assert.deepStrictEqual(pills(s), [{ text: 'All 1 applied', cls: 'ok' }]); assert.match(texts(s).join(' '), /2 without a TLS listener/);
  });
  it('the real summarize() output feeds it', () => {
    const mk = (r) => view.shape({ id: String(Math.random()), name: 'b', version: 'vector-0.59.0', last_seen: new Date(NOW).toISOString(), key_id: 'k', key_status: 'active', config_reported_at: new Date(NOW - 60000).toISOString().replace('Z', ''), ...r }, { now: NOW, tlsPort: 6515 });
    const s = view.summarize([mk({ config_tls_port: 6515 }), mk({ config_tls_port: 6514 }), mk({ config_tls_port: 0 })]);
    assert.deepStrictEqual(pills(brokerTlsSummary(s)), [{ text: '1 of 2 applied', cls: 'bad' }]);
  });
  it('the page wires both in: a column, the summary on the TLS row, and the old \"does not show\" sentence is gone', () => {
    assert.match(html, /\{ h: 'TLS port', f: brokerTlsCell \}/); assert.match(html, /cfg\.tls_port \? brokerTlsSummary\(sum\) : ''/);
    assert.ok(!/This page does not show whether a broker applied it yet/.test(html));
  });
});
