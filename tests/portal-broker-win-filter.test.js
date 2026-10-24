'use strict';
// The "Windows filter" column on the Brokers page (src/portal/index.html). The page has no build step, so the function is cut out of the file and run with stand-ins for el(), pill() and when().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const wb = require('../src/endpoints/win-filter-broker');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, attrs, ...kids) => ({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const when = (t) => 'T' + (t ? '' : '?');
const brokerWinFilterCell = new Function('el', 'pill', 'when', cut('brokerWinFilterCell') + '\nreturn brokerWinFilterCell;')(el, pill, when);
const texts = (n) => (n && typeof n === 'object' ? [n.pill, n.attrs && n.attrs.textContent, n.attrs && n.attrs.title, ...(n.kids || []).flatMap(texts)] : [n]).filter((x) => typeof x === 'string' && x);
const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);

const NOW = Date.parse('2026-10-23T12:00:00Z'), at = (m) => new Date(NOW - m * 60000).toISOString().replace('Z', '');
const H = 'a'.repeat(64), H2 = 'b'.repeat(64), cur = { policy: true, revision: 3, sha256: H };
const cell = (row, c = cur) => brokerWinFilterCell({ win_filter: wb.winFilterState({ config_reported_at: at(2), ...row }, c, NOW) });

describe('Brokers page: Windows filter cell', () => {
  it('one pill per state, the right colour, with the revision where it is known', () => {
    assert.deepStrictEqual(pills(cell({ config_win_filter: H })), [{ text: 'Applied rev 3', cls: 'ok' }]);
    assert.deepStrictEqual(pills(cell({ config_win_filter: H2 })), [{ text: 'Pending rev 3', cls: 'off' }]);
    assert.deepStrictEqual(pills(cell({ config_win_filter: H2, config_rejected_win_filter: H })), [{ text: 'Rejected rev 3', cls: 'bad' }]);
    assert.deepStrictEqual(pills(cell({ config_win_filter: H2, config_reported_at: at(30) })), [{ text: 'Not asking', cls: 'bad' }]);
    assert.deepStrictEqual(pills(cell({})), [{ text: 'Not reporting', cls: 'off' }]);
  });
  it('a removed policy: a dash when the broker has nothing, Removing... while it still has the old filter', () => {
    const none = { policy: false, revision: 0, sha256: wb.IDENTITY_SHA };
    assert.deepStrictEqual(texts(cell({}, none)), ['-']);
    assert.deepStrictEqual(pills(cell({ config_win_filter: H2 }, none)), [{ text: 'Removing...', cls: 'off' }]);
  });
  it('the tooltips say what to do', () => {
    assert.match(texts(cell({ config_win_filter: H2, config_rejected_win_filter: H })).join(' '), /journalctl -u asix-broker-config/);
    assert.match(texts(cell({})).join(' '), /--accept-config/);
    assert.match(texts(cell({ config_win_filter: H2, config_reported_at: at(30) })).join(' '), /timer and Vector/);
  });
  it('a broker object without the field (an older server) shows a dash, never an error', () => {
    assert.deepStrictEqual(texts(brokerWinFilterCell({})), ['-']); assert.deepStrictEqual(texts(brokerWinFilterCell(null)), ['-']);
  });
  it('the column is in the Brokers table', () => { assert.match(html, /\{ h: 'Windows filter', f: brokerWinFilterCell \}/); });
});
