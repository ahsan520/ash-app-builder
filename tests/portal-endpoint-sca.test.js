'use strict';
// The Configuration checks card in an agent's detail on the Endpoints page (src/portal/index.html, agentChecksCard; docs/endpoints.md task E6f): the function is cut out of the page
// and run with small stand-ins for el(), card(), pill(), table(), kv(), when() and api(), as in portal-endpoints.test.js. No DOM, no network.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const i0 = html.indexOf('const EP_SCA_RESULTS ='), i1 = html.indexOf('async function pgEndpoints');
assert.ok(i0 >= 0 && i1 > i0, 'the card is placed before pgEndpoints');
const source = html.slice(i0, i1);

const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => (typeof x === 'string' ? x : typeof x.textContent === 'string' ? x.textContent : '')).join(' | ');
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', { className: 'kv' }, el('span', { textContent: k }), el('span', { textContent: v === null || v === undefined ? '-' : String(v) }))));
const when = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z?$/, '') : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v ?? '-') }); })))));

const POLICIES = [
  { policy_id: 'cis_win11', name: 'CIS Windows 11', description: null, passed: 120, failed: 45, not_applicable: 3, total: 168, score: 72, start_scan: '2026-10-30T10:00:00Z', end_scan: '2026-10-30T10:02:00Z' },
  { policy_id: 'weird id/../x', name: null, description: null, passed: null, failed: null, not_applicable: null, total: null, score: null, start_scan: null, end_scan: null },
];
const chk = (id, result, extra = {}) => ({ id: String(id), title: 'Title ' + id, result, reason: null, description: 'Desc ' + id, rationale: 'Why ' + id, remediation: 'Fix ' + id, command: null, condition: 'all', file: null, directory: null, process: null, registry: null, references: null, compliance: [{ key: 'cis', value: '1.' + id }], ...extra });

function open(answers = {}) {
  const calls = [];
  const api = async (p) => {
    calls.push(p);
    const a = answers[p] !== undefined ? answers[p] : answers[p.split('?')[0]];
    if (a instanceof Error) throw a;
    if (a !== undefined) return typeof a === 'function' ? a(p) : a;
    if (p === '/v1/endpoints/agents/001/sca') return { success: true, agent: '001', policies: POLICIES };
    if (/\/checks\?/.test(p)) { const q = new URLSearchParams(p.split('?')[1]), off = Number(q.get('offset')); const all = Array.from({ length: 120 }, (_, k) => chk(1000 + k, q.get('result') || 'failed')); return { success: true, total: 120, limit: 50, offset: off, checks: all.slice(off, off + 50) }; }
    throw new Error('unexpected call ' + p);
  };
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', source + '\nreturn agentChecksCard;')(el, card, pill, table, kv, when, api);
  const tree = fn('001');
  const find = (label) => walk(tree).find((n) => typeof n === 'object' && n.attrs && n.attrs.textContent === label && typeof n.attrs.onclick === 'function');
  const click = async (label) => { const t = find(label); assert.ok(t, label + ' not found in: ' + texts(tree)); await t.attrs.onclick(); };
  const select = () => walk(tree).find((n) => n && n.tag === 'select');
  const input = () => walk(tree).find((n) => n && n.tag === 'input');
  return { tree, calls, click, find, select, input, text: () => texts(tree) };
}

describe('the Configuration checks card of an agent', () => {
  it('requests nothing until the button is pressed, and the button is in the agent detail', async () => {
    const p = open(); assert.deepStrictEqual(p.calls, []); assert.ok(p.find('Show configuration checks'));
    assert.match(html, /agentChecksCard\(a\.id\)/); assert.ok(html.indexOf('function agentChecksCard') < html.indexOf('async function pgEndpoints'));
  });
  it('pressing it lists the policies with score, counts and the last scan; a missing number is a dash, a missing name falls back to the id', async () => {
    const p = open(); await p.click('Show configuration checks');
    assert.deepStrictEqual(p.calls, ['/v1/endpoints/agents/001/sca']);
    const t = p.text(); assert.match(t, /CIS Windows 11/); assert.match(t, /72%/); assert.match(t, /120/); assert.match(t, /45/); assert.match(t, /2026-10-30 10:02:00/); assert.match(t, /weird id\/\.\.\/x/);
    assert.match(t, /Press a policy to see its checks/);
  });
  it('a machine with no results says so; a failed read is shown and nothing else is drawn', async () => {
    let p = open({ '/v1/endpoints/agents/001/sca': { success: true, agent: '001', policies: [] } }); await p.click('Show configuration checks'); assert.match(p.text(), /no configuration check results for this machine/); assert.ok(!/Press a policy/.test(p.text()));
    p = open({ '/v1/endpoints/agents/001/sca': new Error('WAZUH_UNREACHABLE: The manager cannot be reached') }); await p.click('Show configuration checks'); assert.match(p.text(), /The manager cannot be reached/);
  });
  it('a policy opens its checks: failed first, 50 a page, sorted by id, the policy id encoded so it cannot change the path', async () => {
    const p = open(); await p.click('Show configuration checks'); await p.click('CIS Windows 11');
    assert.strictEqual(p.calls[1], '/v1/endpoints/agents/001/sca/cis_win11/checks?limit=50&offset=0&sort=%2Bid&result=failed');
    assert.match(p.text(), /Title 1000/); assert.match(p.text(), /1 to 50 of 120/); assert.match(p.text(), /Score 72%, 120 passed, 45 failed, 3 not applicable/);
    const q = open(); await q.click('Show configuration checks'); await q.click('weird id/../x');
    assert.strictEqual(q.calls[1].split('?')[0], '/v1/endpoints/agents/001/sca/weird%20id%2F..%2Fx/checks');
  });
  it('the result select sends the manager\'s token (not applicable has an underscore), and Any result sends none; the search is trimmed and starts again at the first page', async () => {
    const p = open(); await p.click('Show configuration checks'); await p.click('CIS Windows 11');
    const sel = p.select(); assert.strictEqual(sel.value, 'failed');
    sel.value = 'not_applicable'; await sel.onchange(); assert.match(p.calls.at(-1), /result=not_applicable/);
    sel.value = 'passed'; await sel.onchange(); assert.match(p.calls.at(-1), /result=passed/);
    sel.value = ''; await sel.onchange(); assert.ok(!/result=/.test(p.calls.at(-1)), p.calls.at(-1));
    const inp = p.input(); inp.value = '  bitlocker  '; await p.click('Search'); assert.match(p.calls.at(-1), /search=bitlocker(&|$)/); assert.match(p.calls.at(-1), /offset=0/);
    inp.value = '   '; await p.click('Search'); assert.ok(!/search=/.test(p.calls.at(-1)));
  });
  it('Next and Previous page by 50, Previous is off on the first page and Next on the last', async () => {
    const p = open(); await p.click('Show configuration checks'); await p.click('CIS Windows 11');
    assert.strictEqual(p.find('Previous').attrs.disabled || p.find('Previous').disabled, true); assert.ok(!p.find('Next').disabled);
    await p.click('Next'); assert.match(p.calls.at(-1), /offset=50/); await p.click('Next'); assert.match(p.calls.at(-1), /offset=100/); assert.match(p.text(), /101 to 120 of 120/); assert.strictEqual(p.find('Next').disabled, true);
    await p.click('Previous'); assert.match(p.calls.at(-1), /offset=50/);
    sel: { const s = p.select(); s.value = 'passed'; await s.onchange(); assert.match(p.calls.at(-1), /offset=0/); }
  });
  it('a check opens with its own text; only text is drawn, never HTML', async () => {
    const hostile = chk(1000, 'failed', { title: '<img src=x onerror=alert(1)>', remediation: '<b>Fix</b>', compliance: [{ key: 'cis', value: '1.1' }, { key: null, value: 'x' }], file: '/etc/ssh/sshd_config', reason: null });
    const p = open({ [`/v1/endpoints/agents/001/sca/cis_win11/checks?limit=50&offset=0&sort=%2Bid&result=failed`]: { success: true, total: 1, limit: 50, offset: 0, checks: [hostile] } });
    await p.click('Show configuration checks'); await p.click('CIS Windows 11'); await p.click('1000');
    const t = p.text(); assert.match(t, /Check 1000/); assert.match(t, /Why 1000/); assert.match(t, /<b>Fix<\/b>/); assert.match(t, /\/etc\/ssh\/sshd_config/); assert.match(t, /cis 1\.1, x/);
    assert.ok(!/innerHTML/.test(source) && !/insertAdjacentHTML|document\.write/.test(source), 'no HTML is built from the manager\'s text');
  });
  it('a result the manager did not name is shown as it is, not as passed; All policies goes back to the list; a failed read of the checks is shown', async () => {
    const p = open({ '/v1/endpoints/agents/001/sca/cis_win11/checks?limit=50&offset=0&sort=%2Bid&result=failed': { success: true, total: 2, limit: 50, offset: 0, checks: [chk(1, null), chk(2, 'failed')] } });
    await p.click('Show configuration checks'); await p.click('CIS Windows 11');
    const pills = walk(p.tree).filter((n) => n && n.className && /^pill /.test(n.className)).map((n) => n.className + ':' + n.textContent); assert.deepStrictEqual(pills, ['pill off:unknown', 'pill bad:failed']);
    await p.click('All policies'); assert.match(p.text(), /Press a policy/); assert.strictEqual(p.calls.at(-1), '/v1/endpoints/agents/001/sca');
    const e = open({ '/v1/endpoints/agents/001/sca/cis_win11/checks?limit=50&offset=0&sort=%2Bid&result=failed': new Error('WAZUH_TIMEOUT: The manager did not answer') });
    await e.click('Show configuration checks'); await e.click('CIS Windows 11'); assert.match(e.text(), /The manager did not answer/);
  });
});
