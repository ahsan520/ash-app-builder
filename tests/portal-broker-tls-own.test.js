'use strict';
// The "(own)" note in the TLS port column on the Brokers page (the dialog that sets it is in portal-broker-ports.test.js) (src/portal/index.html). Same approach as portal-broker-tls.test.js:
// the functions are cut out of the page and run with small stand-ins for el(), pill(), when() and api().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf(name.startsWith('async ') ? name + '(' : 'function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, attrs, ...kids) => ({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const when = (t) => 'T' + (t ? '' : '?');
const { brokerTlsCell } = new Function('el', 'pill', 'when', cut('brokerTlsCell') + '\nreturn { brokerTlsCell };')(el, pill, when);
const texts = (n) => (n && typeof n === 'object' ? [n.pill, n.attrs && n.attrs.textContent, n.attrs && n.attrs.title, ...(n.kids || []).flatMap(texts)] : [n]).filter((x) => typeof x === 'string' && x);
const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);

const NOW = Date.parse('2026-10-19T12:00:00Z');
const rowOf = (o) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: new Date(NOW - 60000), key_id: 'k1', installer_name: 'k', key_status: 'active',
  config_reported_at: new Date(NOW - 60000), ...o });
const cell = (o, tenant) => brokerTlsCell(view.shape(rowOf(o), { now: NOW, tlsPort: tenant }));

describe('Brokers page: own TLS port', () => {
  it('a broker with its own TLS port says so next to the state, whatever the state', () => {
    for (const [r, pillText] of [[{ config_tls_port: 6515 }, 'Applied 6515'], [{ config_tls_port: 6514 }, 'Pending 6515'], [{ config_tls_port: 6514, config_rejected_tls_port: 6515 }, 'Rejected 6515'],
      [{ config_tls_port: 0 }, 'No TLS listener'], [{}, 'Not reporting'], [{ config_tls_port: 6514, config_reported_at: new Date(NOW - 3600000) }, 'Not asking']]) {
      const c = cell({ tls_port_override: 6515, ...r }, 6514);
      assert.deepStrictEqual(pills(c).map((p) => p.text), [pillText], pillText);
      assert.ok(texts(c).includes(' (own)'), pillText + ' shows (own)');
    }
  });
  it('a broker that follows the tenant-wide port shows no (own)', () => {
    for (const r of [{ config_tls_port: 6514 }, { config_tls_port: 6513 }, {}]) assert.ok(!texts(cell(r, 6514)).includes(' (own)'));
    assert.ok(!texts(cell({ config_tls_port: 6514 }, null)).includes(' (own)'));
  });
  it('the page has one Ports button (the dialog is tested in portal-broker-ports.test.js); the three old prompt buttons are gone', () => {
    assert.match(html, /textContent: 'Ports', title: '[^']*', onclick: \(\) => brokerPortsEdit\(b\)/);
    assert.ok(!/textContent: 'TLS port', title/.test(html) && !html.includes('brokerTlsPortEdit') && !html.includes('brokerPortEdit(') && !html.includes('brokerPortExclude('));
  });
});
