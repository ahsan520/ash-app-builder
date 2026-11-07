'use strict';
// E10: the "Folders to watch, per agent group" card (src/portal/index.html groupConfigCard), cut out of the page and run with stand-ins for the page's helpers and the API.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, props, ...kids) => { const n = Object.assign({ tag, kids: kids.flat(Infinity) }, props || {}); n.props = n; n.replaceChildren = (...k) => { n.kids = k.flat(Infinity); }; n.prepend = (k) => { n.kids = [k, ...n.kids]; }; if (tag === 'select' && n.value === undefined) { const o = n.kids.find((k) => k && k.tag === 'option'); if (o) n.value = o.value; } return n; };
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const all = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(all)] : []);
const texts = (n) => all(n).flatMap((x) => [x.props && x.props.textContent, ...(x.kids || []).filter((k) => typeof k === 'string')]).filter((x) => typeof x === 'string' && x);
const btn = (n, label) => all(n).find((x) => x.tag === 'button' && x.props.textContent === label);
const tick = () => new Promise((r) => setTimeout(r, 15));

const SHA1 = 'a'.repeat(64), SHA2 = 'b'.repeat(64);
const STATUS = { success: true, write_enabled: true, manager_registered: true, writer_registered: true, writer: { registered: true, api_user: 'asix-groupconfig' }, groups: [{ name: 'default', agents: 3 }, { name: 'linux', agents: 1 }], limits: { max_entries: 50, max_realtime: 10 } };
const GROUP = { success: true, group: 'default', sha256: SHA1, state: 'none', state_text: 'ASIX has not set anything for this group', entries: [], history: [] };
// A stand-in API: `routes` maps "METHOD path" to an answer (or a function of the body, or an Error).
function build(routes, confirmAnswer = true) {
  const calls = [], alerts = [], confirms = [];
  const api = async (p, o) => { const key = ((o && o.method) || 'GET') + ' ' + p; calls.push({ key, body: o && o.body }); const a = routes[key]; if (a === undefined) throw new Error('no stand-in for ' + key); const v = typeof a === 'function' ? a(o && o.body) : a; if (v instanceof Error) throw v; return v; };
  const fn = new Function('el', 'api', 'card', 'pill', 'confirm', 'alert', cut('groupConfigCard') + '\nreturn groupConfigCard;')(el, api, card, pill, (m) => { confirms.push(m); return confirmAnswer; }, (m) => alerts.push(m));
  return { fn, calls, alerts, confirms };
}
const put = (c, ph) => all(c).filter((x) => x.tag === 'input' && x.props.type !== 'checkbox' && x.props.placeholder !== undefined)[ph || 0];

describe('before anything can be done', () => {
  it('no writer registered: says how an operator registers one and asks nothing else', async () => {
    const b = build({ 'GET /v1/endpoints/group-config': { ...STATUS, writer_registered: false, groups: [] } }); const c = b.fn(); await tick();
    assert.match(texts(c).join(' '), /register-writer --tenant/); assert.deepStrictEqual(b.calls.map((x) => x.key), ['GET /v1/endpoints/group-config']);
  });
  it('the manager not answering is shown as a problem; an error from the route is shown as it is', async () => {
    let b = build({ 'GET /v1/endpoints/group-config': { ...STATUS, groups: [], problem: { code: 'UNREACHABLE', message: 'The manager cannot be reached' } } }); let c = b.fn(); await tick(); assert.match(texts(c).join(' '), /could not be asked for its groups: The manager cannot be reached/);
    b = build({ 'GET /v1/endpoints/group-config': new Error('No central endpoint manager is registered for this tenant') }); c = b.fn(); await tick(); assert.match(texts(c).join(' '), /No central endpoint manager/);
  });
  it('writing switched off on the server: says so, still lets a person look and preview, and Apply stays off', async () => {
    const b = build({ 'GET /v1/endpoints/group-config': { ...STATUS, write_enabled: false }, 'GET /v1/endpoints/group-config/default': { ...GROUP }, 'POST /v1/endpoints/group-config/default/preview': { success: true, base_sha256: SHA1, changed: true, diff: { added: ['Linux /srv/data'], removed: [], changed: [], same: 0 } } });
    const c = b.fn(); await tick(); assert.match(texts(c).join(' '), /switched off on this server/);
    await btn(c, 'Add a folder').props.onclick(); put(c).oninput({ target: { value: '/srv/data' } }); await btn(c, 'Preview').props.onclick(); assert.match(texts(c).join(' '), /Will be added \(1\)/); assert.strictEqual(btn(c, 'Apply').props.disabled, true); assert.match(btn(c, 'Apply').props.title, /switched off/);
  });
});

describe('the flow: edit, preview, apply', () => {
  const routes = (extra = {}) => ({ 'GET /v1/endpoints/group-config': STATUS, 'GET /v1/endpoints/group-config/default': { ...GROUP }, 'POST /v1/endpoints/group-config/default/preview': { success: true, base_sha256: SHA2, changed: true, diff: { added: ['Linux /srv/data (real time)', 'Windows C:\\Data'], removed: ['Linux /old'], changed: ['Linux /x (real time)  ->  Linux /x'], same: 2 } }, 'PUT /v1/endpoints/group-config/default': { success: true, changed: true, sha256: SHA2 }, ...extra });
  it('shows the groups with their machine counts and the state of the first one', async () => {
    const b = build(routes()); const c = b.fn(); await tick(); const t = texts(c).join(' | '); assert.match(t, /default \(3 machines\)/); assert.match(t, /linux \(1 machines\)/); assert.match(t, /Nothing set by ASIX/); assert.deepStrictEqual(b.calls.map((x) => x.key), ['GET /v1/endpoints/group-config', 'GET /v1/endpoints/group-config/default']);
  });
  it('Preview sends the typed list (trimmed) and shows added, removed and changed lines; nothing is written', async () => {
    const b = build(routes()); const c = b.fn(); await tick(); await btn(c, 'Add a folder').props.onclick(); put(c).oninput({ target: { value: '  /srv/data  ' } }); await btn(c, 'Preview').props.onclick();
    const p = b.calls.find((x) => x.key.startsWith('POST')); assert.deepStrictEqual(p.body, { entries: [{ system: 'linux', path: '/srv/data', realtime: false }] });
    const t = texts(c).join(' | '); assert.match(t, /Will be added \(2\)/); assert.match(t, /Windows C:\\Data/); assert.match(t, /Will be removed \(1\)/); assert.match(t, /Will change \(1\)/); assert.match(t, /2 folders stay as they are/); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT')));
  });
  it('Apply is off until a preview of exactly this list; it asks, then sends the preview\u2019s hash; the group is read again', async () => {
    const b = build(routes()); const c = b.fn(); await tick(); await btn(c, 'Add a folder').props.onclick(); assert.strictEqual(btn(c, 'Apply').props.disabled, true); put(c).oninput({ target: { value: '/srv/data' } });
    await btn(c, 'Apply').props.onclick(); assert.strictEqual(b.confirms.length, 0, 'a click without a preview does nothing'); await btn(c, 'Preview').props.onclick(); assert.strictEqual(btn(c, 'Apply').props.disabled, false);
    await btn(c, 'Apply').props.onclick(); assert.strictEqual(b.confirms.length, 1); assert.match(b.confirms[0], /group "default"/); const w = b.calls.find((x) => x.key.startsWith('PUT'));
    assert.deepStrictEqual(w.body, { entries: [{ system: 'linux', path: '/srv/data', realtime: false }], base_sha256: SHA2 }); assert.strictEqual(b.calls.filter((x) => x.key === 'GET /v1/endpoints/group-config/default').length, 2); assert.match(texts(c).join(' '), /Done/);
  });
  it('editing after the preview switches Apply off again, and a click that still arrives sends nothing', async () => {
    const b = build(routes()); const c = b.fn(); await tick(); await btn(c, 'Add a folder').props.onclick(); put(c).oninput({ target: { value: '/srv/data' } }); await btn(c, 'Preview').props.onclick(); const apply = btn(c, 'Apply');
    put(c).oninput({ target: { value: '/srv/other' } }); assert.strictEqual(apply.props.disabled, true); await apply.props.onclick(); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT'))); assert.strictEqual(b.confirms.length, 0);
    all(c).find((x) => x.tag === 'input' && x.props.type === 'checkbox').props.onchange({ target: { checked: true } }); assert.strictEqual(apply.props.disabled, true);
  });
  it('a person who says no to the question sends nothing', async () => {
    const b = build(routes(), false); const c = b.fn(); await tick(); await btn(c, 'Add a folder').props.onclick(); put(c).oninput({ target: { value: '/srv/data' } }); await btn(c, 'Preview').props.onclick(); await btn(c, 'Apply').props.onclick();
    assert.strictEqual(b.confirms.length, 1); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT')));
  });
  it('real time and the system are sent as chosen; Remove takes a row out', async () => {
    const b = build(routes()); const c = b.fn(); await tick(); await btn(c, 'Add a folder').props.onclick(); await btn(c, 'Add a folder').props.onclick();
    const sel = all(c).filter((x) => x.tag === 'select' && x.props.onchange && !x.kids.some((k) => k.tag === 'option' && k.props.value === 'default'))[1]; sel.props.onchange({ target: { value: 'windows' } }); put(c, 1).oninput({ target: { value: 'C:\\Data' } }); put(c, 0).oninput({ target: { value: '/a' } });
    all(c).filter((x) => x.tag === 'input' && x.props.type === 'checkbox')[0].props.onchange({ target: { checked: true } }); await btn(c, 'Preview').props.onclick();
    assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body.entries, [{ system: 'linux', path: '/a', realtime: true }, { system: 'windows', path: 'C:\\Data', realtime: false }]);
    btn(c, 'Remove').props.onclick(); assert.strictEqual(all(c).filter((x) => x.tag === 'input' && x.props.placeholder !== undefined).length, 1);
  });
  it('a refusal from the server (stale file, bad path) is shown as text; a stale file reloads the group', async () => {
    const b = build(routes({ 'POST /v1/endpoints/group-config/default/preview': new Error('The folder / is not allowed'), 'PUT /v1/endpoints/group-config/default': new Error('The group configuration changed since you looked at it. Preview again.') }));
    const c = b.fn(); await tick(); await btn(c, 'Add a folder').props.onclick(); await btn(c, 'Preview').props.onclick(); assert.match(texts(c).join(' '), /not allowed/); assert.strictEqual(btn(c, 'Apply').props.disabled, true);
    const b2 = build(routes({ 'PUT /v1/endpoints/group-config/default': new Error('The group configuration changed since you looked at it. Preview again.') })); const c2 = b2.fn(); await tick(); await btn(c2, 'Add a folder').props.onclick(); put(c2).oninput({ target: { value: '/srv/data' } }); await btn(c2, 'Preview').props.onclick(); await btn(c2, 'Apply').props.onclick();
    assert.match(texts(c2).join(' '), /changed since/); assert.strictEqual(b2.calls.filter((x) => x.key === 'GET /v1/endpoints/group-config/default').length, 2);
  });
  it('choosing another group reads that group', async () => {
    const b = build(routes({ 'GET /v1/endpoints/group-config/linux': { ...GROUP, group: 'linux', sha256: SHA2, state: 'ok', state_text: 'ASIX manages the folders below', entries: [{ system: 'linux', path: '/opt/app', realtime: true }] } })); const c = b.fn(); await tick();
    const sel = all(c).find((x) => x.tag === 'select' && x.props.onchange === undefined || (x.tag === 'select' && x.kids.some((k) => k.tag === 'option' && k.props.value === 'linux'))); sel.props.value = 'linux'; await sel.props.onchange(); const t = texts(c).join(' | ');
    assert.match(t, /1 folders set by ASIX/); assert.strictEqual(put(c).props.value, '/opt/app'); assert.ok(b.calls.some((x) => x.key === 'GET /v1/endpoints/group-config/linux'));
  });
});

describe('a group ASIX must not edit, and the history', () => {
  const base = { 'GET /v1/endpoints/group-config': STATUS };
  it('markers damaged or the block edited by hand: says what to do and offers no editor', async () => {
    for (const [state, re] of [['broken', /markers .* are damaged/], ['edited', /changed by hand/]]) {
      const b = build({ ...base, 'GET /v1/endpoints/group-config/default': { ...GROUP, state, state_text: state } }); const c = b.fn(); await tick(); assert.match(texts(c).join(' '), re); assert.strictEqual(btn(c, 'Add a folder'), undefined); assert.strictEqual(btn(c, 'Apply'), undefined); assert.match(texts(c).join(' '), /Cannot edit/);
    }
  });
  const H = (id, result, action = 'apply') => ({ id, action, result, by: 'alice', at: '2026-10-31T12:00:00Z', entries_before: [], entries_after: [] });
  it('every applied change has Undo (not failed or rolled back ones); Undo asks, then sends that change\u2019s id with the current hash', async () => {
    const b = build({ ...base, 'GET /v1/endpoints/group-config/default': { ...GROUP, history: [H('11111111-1111-4111-8111-111111111111', 'applied'), H('22222222-2222-4222-8222-222222222222', 'failed'), H('33333333-3333-4333-8333-333333333333', 'rolled_back')] }, 'POST /v1/endpoints/group-config/default/undo': { success: true } });
    const c = b.fn(); await tick(); const t = texts(c).join(' | '); assert.match(t, /alice: changed the list/); assert.match(t, /Applied/); assert.match(t, /Failed/); assert.match(t, /Rolled back/);
    const undo = all(c).filter((x) => x.tag === 'button' && x.props.textContent === 'Undo'); assert.strictEqual(undo.length, 1); await undo[0].props.onclick();
    assert.strictEqual(b.confirms.length, 1); assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body, { history_id: '11111111-1111-4111-8111-111111111111', base_sha256: SHA1 }); assert.strictEqual(b.calls.filter((x) => x.key === 'GET /v1/endpoints/group-config/default').length, 2);
  });
  it('no Undo when writing is off, and a declined question sends nothing', async () => {
    let b = build({ 'GET /v1/endpoints/group-config': { ...STATUS, write_enabled: false }, 'GET /v1/endpoints/group-config/default': { ...GROUP, history: [H('11111111-1111-4111-8111-111111111111', 'applied')] } }); let c = b.fn(); await tick(); assert.strictEqual(all(c).filter((x) => x.tag === 'button' && x.props.textContent === 'Undo').length, 0);
    b = build({ ...base, 'GET /v1/endpoints/group-config/default': { ...GROUP, history: [H('11111111-1111-4111-8111-111111111111', 'applied')] } }, false); c = b.fn(); await tick(); await all(c).find((x) => x.props && x.props.textContent === 'Undo').props.onclick(); assert.ok(!b.calls.some((x) => x.key.startsWith('POST')));
  });
});

describe('the card as written', () => {
  const f = cut('groupConfigCard');
  it('uses only text, only the group configuration routes, and only PUT and POST', () => {
    assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(/.test(f)); assert.ok((f.match(/api\(([^)]*?)[,)]/g) || []).every((x) => /GC|\$?'\/v1\/endpoints\/group-config/.test(x)), 'every call goes to GC');
    assert.deepStrictEqual([...new Set(f.match(/method: '[A-Z]+'/g))].sort(), ["method: 'POST'", "method: 'PUT'"]); assert.match(f, /const GC = '\/v1\/endpoints\/group-config'/);
  });
  it('is a tab of the Endpoints page and does not name the product', () => {
    assert.match(html, /\['groups', 'Group settings', \(\) => \[groupConfigCard\(\), groupWinlogCard\(\), groupLinuxlogCard\(\)\]\]/); assert.ok(!/wazuh/i.test(f.replace(/wazuh-manager-cli\.js/, '')), 'only the operator command may name it');
  });
});
