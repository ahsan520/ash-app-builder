'use strict';
// E13: the "Linux logs read by agents, per agent group" card, cut out of the page and run with stand-ins for the page's helpers and the API.
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
const btns = (n, label) => all(n).filter((x) => x.tag === 'button' && x.props.textContent === label);
const tick = () => new Promise((r) => setTimeout(r, 15));
const SHA1 = 'a'.repeat(64), SHA2 = 'b'.repeat(64), GCF = 'GET /v1/endpoints/group-config', GL = '/v1/endpoints/group-linuxlog/default';
const STATUS = { success: true, write_enabled: true, writer_registered: true, groups: [{ name: 'default', agents: 3 }, { name: 'linux', agents: 2 }] };
const GROUP = { success: true, group: 'default', sha256: SHA1, state: 'none', state_text: 'ASIX has not set any Linux log for this group', entries: [], history: [] };
function build(routes, confirmAnswer = true) {
  const calls = [], confirms = [], alerts = [];
  const api = async (p, o) => { const key = ((o && o.method) || 'GET') + ' ' + p; calls.push({ key, body: o && o.body }); const a = routes[key]; if (a === undefined) throw new Error('no stand-in for ' + key); const v = typeof a === 'function' ? a(o && o.body) : a; if (v instanceof Error) throw v; return v; };
  const fn = new Function('el', 'api', 'card', 'pill', 'confirm', 'alert', cut('groupLinuxlogCard') + '\nreturn groupLinuxlogCard;')(el, api, card, pill, (m) => { confirms.push(m); return confirmAnswer; }, (m) => alerts.push(m));
  return { fn, calls, confirms, alerts };
}
const base = (x = {}) => ({ [GCF]: STATUS, ['GET ' + GL]: GROUP, ...x });
const addFile = (c, p) => { const inp = all(c).find((x) => x.tag === 'input' && x.props.placeholder && /log file or pattern/.test(x.props.placeholder)); inp.props.value = p; btn(c, 'Add a file').props.onclick(); };
const PREVIEW = { success: true, base_sha256: SHA2, changed: true, diff: { added: ['/var/log/app/*.log'], removed: [], same: 0 } };

describe('the Linux logs card', () => {
  it('without a writer it says so; a manager problem is shown; a group error is shown', async () => {
    let c = build({ [GCF]: { ...STATUS, writer_registered: false, groups: [] } }).fn(); await tick(); assert.match(texts(c).join(' '), /same group configuration user as the folders card/);
    c = build({ [GCF]: { ...STATUS, groups: [], problem: { message: 'The manager cannot be reached' } } }).fn(); await tick(); assert.match(texts(c).join(' '), /cannot be reached/);
    c = build(base({ ['GET ' + GL]: new Error('boom') })).fn(); await tick(); assert.match(texts(c).join(' '), /boom/);
  });
  it('shows an empty group, the explanation and the limits', async () => {
    const t = texts(build(base()).fn()).join(' '); void t; const c = build(base()).fn(); await tick(); const s = texts(c).join(' ');
    assert.match(s, /Nothing set by ASIX/); assert.match(s, /Nothing is set for this group/); assert.match(s, /system, secret and key files are refused/); assert.match(s, /may be read twice/);
  });
  it('Apply is off until a preview of exactly this list; adding or removing switches it off again; preview shows what changes', async () => {
    const b = build(base({ ['POST ' + GL + '/preview']: PREVIEW })); const c = b.fn(); await tick(); const apply = btn(c, 'Apply'); assert.strictEqual(apply.props.disabled, true);
    addFile(c, '/var/log/app/*.log'); assert.ok(texts(c).includes('/var/log/app/*.log')); await btn(c, 'Preview').props.onclick(); await tick(); assert.strictEqual(apply.props.disabled, false); assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body, { entries: [{ type: 'file', path: '/var/log/app/*.log' }] });
    assert.match(texts(c).join(' '), /Will be added \(1\)/); addFile(c, '/var/log/b.log'); assert.strictEqual(apply.props.disabled, true);
  });
  it('the journal tick box puts the journal first and takes it out again; a path already listed is not added twice', async () => {
    const b = build(base({ ['POST ' + GL + '/preview']: PREVIEW })); const c = b.fn(); await tick(); addFile(c, '/var/log/a.log'); addFile(c, '/var/log/a.log');
    const j = all(c).find((x) => x.tag === 'input' && x.props.type === 'checkbox'); j.props.onchange({ target: { checked: true } }); await btn(c, 'Preview').props.onclick();
    assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body.entries, [{ type: 'journald' }, { type: 'file', path: '/var/log/a.log' }]);
    j.props.onchange({ target: { checked: false } }); await btn(c, 'Preview').props.onclick(); assert.deepStrictEqual(b.calls.filter((x) => x.key.startsWith('POST')).pop().body.entries, [{ type: 'file', path: '/var/log/a.log' }]);
  });
  it('Apply asks, sends the entries and the preview hash, reloads; declining writes nothing; the handler itself refuses a stale preview', async () => {
    let n = 0; let b = build(base({ ['POST ' + GL + '/preview']: PREVIEW, ['PUT ' + GL]: { success: true, changed: true }, ['GET ' + GL]: () => (++n === 1 ? GROUP : { ...GROUP, sha256: SHA2, state: 'ok', entries: [{ type: 'file', path: '/var/log/a.log' }] }) })); let c = b.fn(); await tick();
    addFile(c, '/var/log/a.log'); await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick(); assert.strictEqual(b.confirms.length, 1); assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('PUT')).body, { entries: [{ type: 'file', path: '/var/log/a.log' }], base_sha256: SHA2 }); assert.match(texts(c).join(' '), /Done\. The manager holds the new list/);
    b = build(base({ ['POST ' + GL + '/preview']: PREVIEW }), false); c = b.fn(); await tick(); addFile(c, '/var/log/a.log'); await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick(); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT')));
    b = build(base({ ['POST ' + GL + '/preview']: PREVIEW })); c = b.fn(); await tick(); addFile(c, '/var/log/a.log'); await btn(c, 'Preview').props.onclick(); await tick(); addFile(c, '/var/log/z.log'); await btn(c, 'Apply').props.onclick(); await tick(); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT'))); assert.strictEqual(b.confirms.length, 0);
  });
  it('a refusal (a secret path, a stale file) is shown as text', async () => {
    let b = build(base({ ['POST ' + GL + '/preview']: new Error('The path \u201c/etc/shadow\u201d is not a place logs are read from here') })); let c = b.fn(); await tick(); addFile(c, '/etc/shadow'); await btn(c, 'Preview').props.onclick(); await tick(); assert.match(texts(c).join(' '), /not a place logs are read from here/); assert.strictEqual(btn(c, 'Apply').props.disabled, true);
    b = build(base({ ['POST ' + GL + '/preview']: PREVIEW, ['PUT ' + GL]: new Error('The group configuration changed since you looked at it. Preview again.') })); c = b.fn(); await tick(); addFile(c, '/var/log/a.log'); await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick(); assert.match(texts(c).join(' '), /The list below is the one the manager has now/);
  });
  it('writing off: preview works, Apply stays off, no Undo; a damaged or edited block cannot be edited', async () => {
    const H = [{ id: 'h1', action: 'apply', result: 'applied', entries_after: [{ type: 'journald' }], by: 'ann', at: '2026-11-07T10:00:00Z' }];
    let c = build(base({ [GCF]: { ...STATUS, write_enabled: false }, ['GET ' + GL]: { ...GROUP, history: H }, ['POST ' + GL + '/preview']: PREVIEW })).fn(); await tick(); assert.match(texts(c).join(' '), /switched off on this server/); assert.ok(!btn(c, 'Undo')); addFile(c, '/var/log/a.log'); await btn(c, 'Preview').props.onclick(); await tick(); assert.strictEqual(btn(c, 'Apply').props.disabled, true);
    for (const [state, re] of [['broken', /markers for Linux logs .* are damaged/], ['edited', /changed by hand/]]) { c = build(base({ ['GET ' + GL]: { ...GROUP, state, state_text: 'x' } })).fn(); await tick(); assert.match(texts(c).join(' '), re); assert.ok(!btn(c, 'Preview')); }
  });
  it('history: who did what; Undo only for an applied change; it asks, then sends the id and the hash', async () => {
    const H = [{ id: 'h1', action: 'apply', result: 'applied', entries_after: [{ type: 'journald' }, { type: 'file', path: '/var/log/a.log' }], by: 'ann', at: '2026-11-07T10:00:00Z' }, { id: 'h2', action: 'apply', result: 'failed', entries_after: [], by: null, at: '2026-11-07T09:00:00Z' }];
    const b = build(base({ ['GET ' + GL]: { ...GROUP, history: H }, ['POST ' + GL + '/undo']: { success: true } })); const c = b.fn(); await tick(); assert.match(texts(c).join(' '), /ann: changed the list \(The systemd journal, \/var\/log\/a\.log\)/); assert.strictEqual(btns(c, 'Undo').length, 1);
    await btn(c, 'Undo').props.onclick(); await tick(); assert.strictEqual(b.confirms.length, 1); assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body, { history_id: 'h1', base_sha256: SHA1 });
  });
  it('is on the Group settings tab after the Windows card; everything is set as text', async () => {
    assert.match(html, /groupWinlogCard\(\), groupLinuxlogCard\(\)\]\]/); assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML/.test(cut('groupLinuxlogCard')));
    const c = build(base({ ['GET ' + GL]: { ...GROUP, state: 'ok', entries: [{ type: 'file', path: '<img src=x onerror=alert(1)>' }] } })).fn(); await tick(); assert.ok(texts(c).some((x) => x.includes('<img src=x'))); assert.ok(!all(c).some((x) => x.tag === 'img'));
  });
});
