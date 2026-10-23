'use strict';
// The Windows event filter page (src/portal/index.html, pgWinFilter; docs/endpoints.md task E2): the function is cut out of the page and run with small stand-ins for
// el(), card(), pill(), api(), route(), alert() and confirm(), as in portal-broker-ports.test.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); return html.slice(i, html.indexOf('\n', i)); };
const sample = html.slice(html.indexOf('const WF_SAMPLE = ['), html.indexOf('async function pgWinFilter'));
const el = (tag, attrs, ...kids) => Object.assign({ tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren() { this.kids = []; }, append(...k) { this.kids.push(...k.flat(Infinity)); } }, attrs || {});
const walk = (n) => (n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => x.attrs && x.attrs.textContent).filter((x) => typeof x === 'string').join(' | ');

const SETTINGS = { available: true, configured: true, invalid: false, revision: 3, updated_at: '2026-10-23T10:00:00.000Z', policy: { version: 1, default: 'keep', channels: {}, strip_message: true, rules: [{ id: 'a', action: 'drop', channel: 'Security', event_ids: [4656] }], message_strip: [] },
  preset: { version: 1, default: 'keep', channels: {}, strip_message: true, rules: [{ id: 'noisy-security', action: 'drop', channel: 'Security', event_ids: [4656, 5156] }], message_strip: [] } };

async function open(settings = SETTINGS, answers = {}) {
  const calls = [], alerts = [], routes = [], confirms = []; let confirmWith = true;
  const api = async (p, o = {}) => {
    calls.push({ p, method: o.method || 'GET', body: o.body });
    if (answers[p] instanceof Error) throw answers[p];
    if (answers[p]) return answers[p];
    if (p === '/v1/endpoints/win-filter' && !o.method) return { settings };
    return { success: true };
  };
  const fn = new Function('el', 'card', 'pill', 'api', 'route', 'alert', 'confirm', sample + cut('async function pgWinFilter') + '\nreturn pgWinFilter;')(
    el, (title, ...kids) => el('div', { className: 'card', title }, title ? el('h3', { textContent: title }) : '', ...kids), (t, c) => el('span', { className: 'pill ' + c, textContent: t }),
    api, () => routes.push(1), (m) => alerts.push(m), (m) => { confirms.push(m); return confirmWith; });
  const tree = await fn(), all = walk(tree);
  const boxes = all.filter((n) => n.tag === 'textarea');
  return { tree, calls, alerts, routes, confirms, setConfirm: (v) => { confirmWith = v; }, policy: boxes[0], sample: boxes[1], out: all.find((n) => n.tag === 'div' && n.kids && n.kids.length === 0 && !n.attrs.className),
    btn: (label) => all.find((n) => n.tag === 'button' && n.attrs.textContent === label), text: () => texts(tree) };
}

describe('Windows event filter page', () => {
  it('has a menu entry in Data collection, tied to the ingestion module, and calls only its own routes', () => {
    assert.match(html, /\{ id: 'winfilter', label: 'Windows event filter', page: pgWinFilter \}/); assert.match(html, /'settings\/winfilter': 'ingestion'/);
    const body = cut('async function pgWinFilter'); assert.deepStrictEqual([...new Set(body.match(/\/v1\/[a-z/-]+/g))].sort(), ['/v1/endpoints/win-filter', '/v1/endpoints/win-filter/preview']);
  });
  it('shows a notice, and no editor, while the table is missing', async () => {
    const p = await open({ ...SETTINGS, available: false }); assert.match(p.text(), /no win_filter_policy table yet/); assert.strictEqual(p.policy, undefined);
  });
  it('opens with the saved policy in the editor and says it is saved at its revision', async () => {
    const p = await open(); assert.deepStrictEqual(JSON.parse(p.policy.value), SETTINGS.policy); assert.match(p.text(), /Saved, revision 3/);
    assert.ok(p.btn('Remove the policy'));
    const n = await open({ ...SETTINGS, configured: false, revision: 0, updated_at: null }); assert.match(n.text(), /No policy: every event is kept/); assert.strictEqual(n.btn('Remove the policy'), undefined);
    assert.match((await open({ ...SETTINGS, invalid: true })).text(), /no longer validates/);
  });
  it('the starting point replaces the editor text and saves nothing', async () => {
    const p = await open(); p.btn('Load the suggested starting point').onclick(); assert.deepStrictEqual(JSON.parse(p.policy.value), SETTINGS.preset); assert.deepStrictEqual(p.calls.map((c) => c.method), ['GET']);
  });
  it('Save sends the edited policy with the revision it was opened at, then reloads the page', async () => {
    const p = await open(); const edited = { ...SETTINGS.policy, default: 'drop' }; p.policy.value = JSON.stringify(edited);
    await p.btn('Save').onclick();
    assert.deepStrictEqual(p.calls[1], { p: '/v1/endpoints/win-filter', method: 'PUT', body: { policy: edited, if_revision: 3 } }); assert.strictEqual(p.routes.length, 1); assert.deepStrictEqual(p.alerts, []);
  });
  it('Save with text that is not JSON says so and sends nothing', async () => {
    const p = await open(); p.policy.value = '{ nope'; await p.btn('Save').onclick();
    assert.match(p.alerts[0], /The policy is not valid JSON/); assert.strictEqual(p.calls.length, 1); assert.strictEqual(p.routes.length, 0);
  });
  it('a refused save is shown to the person and the page is not reloaded', async () => {
    let fail = false; const calls = [], alerts = [], routes = [];
    const fn = new Function('el', 'card', 'pill', 'api', 'route', 'alert', 'confirm', sample + cut('async function pgWinFilter') + '\nreturn pgWinFilter;')(
      el, (t, ...k) => el('div', {}, ...k), (t) => el('span', { textContent: t }), async (p, o = {}) => { calls.push(o.method || 'GET'); if (o.method === 'PUT' && fail) throw new Error('409 saved by someone else'); return { settings: SETTINGS }; },
      () => routes.push(1), (m) => alerts.push(m), () => true);
    const tree = await fn(); fail = true; await walk(tree).find((n) => n.tag === 'button' && n.attrs.textContent === 'Save').onclick();
    assert.deepStrictEqual([alerts, routes.length, calls], [['409 saved by someone else'], 0, ['GET', 'PUT']]);
  });
  it('Check sends the policy and the sample events to the preview route and shows the results, the agent blocks and the Vector transform', async () => {
    const preview = { ok: true, results: [{ channel: 'Security', event_id: 4624, keep: true, rule_id: null, message: null }, { channel: 'Security', event_id: 4656, keep: false, rule_id: 'a', message: null }],
      outputs: { agent_conf: '<localfile>AGENT</localfile>', vector: '[transforms.x]VECTOR', xpath: { Security: { query: 'Event/System[EventID != 4656]', reason: null }, System: { query: null, reason: 'nothing to filter on this channel' } } } };
    const p = await open(SETTINGS, { '/v1/endpoints/win-filter/preview': { preview } });
    await p.btn('Check with the sample events').onclick();
    const c = p.calls[1]; assert.deepStrictEqual([c.p, c.method, c.body.policy, c.body.events.length], ['/v1/endpoints/win-filter/preview', 'POST', SETTINGS.policy, 2]);
    const t = texts(p.out); assert.match(t, /Kept/); assert.match(t, /Dropped/); assert.match(t, /\(removed\)/); assert.match(t, /AGENT/); assert.match(t, /VECTOR/); assert.match(t, /System: nothing to filter/); assert.ok(!/Security: /.test(t));
    assert.strictEqual(p.routes.length, 0);
  });
  it('Check shows the problems the server found, and bad JSON in either box before any request', async () => {
    const p = await open(SETTINGS, { '/v1/endpoints/win-filter/preview': { preview: { ok: false, errors: ['rule 1: id must be 1-40 characters'] } } });
    await p.btn('Check with the sample events').onclick(); assert.match(texts(p.out), /Problems in the policy[\s\S]*rule 1: id must be/);
    const q = await open(); q.sample.value = '[{'; await q.btn('Check with the sample events').onclick(); assert.match(texts(q.out), /The sample events is not valid JSON/); assert.strictEqual(q.calls.length, 1);
    const r = await open(); r.policy.value = ''; await r.btn('Check with the sample events').onclick(); assert.match(texts(r.out), /The policy is not valid JSON/); assert.strictEqual(r.calls.length, 1);
  });
  it('Remove asks first, sends clear only when confirmed, and reloads', async () => {
    const p = await open(); p.setConfirm(false); await p.btn('Remove the policy').onclick(); assert.strictEqual(p.calls.length, 1); assert.match(p.confirms[0], /Every event is kept again/);
    p.setConfirm(true); await p.btn('Remove the policy').onclick(); assert.deepStrictEqual(p.calls[1], { p: '/v1/endpoints/win-filter', method: 'PUT', body: { clear: true } }); assert.strictEqual(p.routes.length, 1);
  });
});
