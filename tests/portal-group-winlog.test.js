'use strict';
// E11: the "Windows events read by agents, per agent group" card (src/portal/index.html groupWinlogCard), cut out of the page and run with stand-ins for the page's helpers and the API.
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
const boxes = (n) => all(n).filter((x) => x.tag === 'input' && x.props.type === 'checkbox');
const tick = () => new Promise((r) => setTimeout(r, 15));

const SHA1 = 'a'.repeat(64), SHA2 = 'b'.repeat(64);
const GCF = 'GET /v1/endpoints/group-config', GW = '/v1/endpoints/group-winlog/default';
const STATUS = { success: true, write_enabled: true, writer_registered: true, groups: [{ name: 'default', agents: 3 }, { name: 'win', agents: 2 }] };
const QUERY = 'Event/System[EventID != 4656 and EventID != 4658]';
const GROUP = { success: true, group: 'default', sha256: SHA1, state: 'none', state_text: 'ASIX has not set any Windows event channel for this group', channels: [], items: [], in_step: null, rows: [], policy_revision: 4,
  offered: ['Security', 'System', 'Application'], pushes: [{ channel: 'Security', query: QUERY, reason: null }, { channel: 'System', query: null, reason: 'nothing to filter on this channel' }, { channel: 'Application', query: null, reason: 'nothing to filter on this channel' }], history: [] };
function build(routes, confirmAnswer = true) {
  const calls = [], alerts = [], confirms = [];
  const api = async (p, o) => { const key = ((o && o.method) || 'GET') + ' ' + p; calls.push({ key, body: o && o.body }); const a = routes[key]; if (a === undefined) throw new Error('no stand-in for ' + key); const v = typeof a === 'function' ? a(o && o.body) : a; if (v instanceof Error) throw v; return v; };
  const fn = new Function('el', 'api', 'card', 'pill', 'confirm', 'alert', cut('groupWinlogCard') + '\nreturn groupWinlogCard;')(el, api, card, pill, (m) => { confirms.push(m); return confirmAnswer; }, (m) => alerts.push(m));
  return { fn, calls, alerts, confirms };
}
const base = (extra = {}) => ({ [GCF]: STATUS, ['GET ' + GW]: GROUP, ...extra });

describe('before anything can be done', () => {
  it('no writer registered: says it is the same user as the folders card and asks nothing else', async () => {
    const b = build({ [GCF]: { ...STATUS, writer_registered: false, groups: [] } }); const c = b.fn(); await tick();
    assert.match(texts(c).join(' '), /same group configuration user as the folders card/); assert.deepStrictEqual(b.calls.map((x) => x.key), [GCF]);
  });
  it('a manager that does not answer is a problem; an error from the group route is shown as it is', async () => {
    let b = build({ [GCF]: { ...STATUS, groups: [], problem: { message: 'The manager cannot be reached' } } }); let c = b.fn(); await tick(); assert.match(texts(c).join(' '), /could not be asked for its groups: The manager cannot be reached/);
    b = build(base({ ['GET ' + GW]: new Error('The saved Windows event filter policy is not valid') })); c = b.fn(); await tick(); assert.match(texts(c).join(' '), /policy is not valid/);
  });
  it('writing switched off: says so, still lets a person preview, and Apply stays off', async () => {
    const b = build(base({ [GCF]: { ...STATUS, write_enabled: false }, ['POST ' + GW + '/preview']: { success: true, base_sha256: SHA1, changed: true, diff: { added: ['Security: ' + QUERY], removed: [], changed: [], same: 0 } } }));
    const c = b.fn(); await tick(); assert.match(texts(c).join(' '), /switched off on this server/);
    boxes(c)[0].props.onchange({ target: { checked: true } }); await btn(c, 'Preview').props.onclick(); await tick();
    assert.strictEqual(btn(c, 'Apply').props.disabled, true); assert.match(btn(c, 'Apply').props.title, /switched off/);
  });
});

describe('what a person sees', () => {
  it('lists the channels the policy offers, none ticked at first, with the query the policy gives or why there is none', async () => {
    const c = build(base()).fn(); await tick(); const t = texts(c).join('\n');
    assert.strictEqual(boxes(c).length, 3); assert.ok(boxes(c).every((x) => !x.props.checked)); assert.ok(t.includes('The policy gives this query: ' + QUERY)); assert.match(t, /No filter at the agent: the whole channel is sent and the broker filters \(nothing to filter on this channel\)/);
    assert.match(t, /Nothing set by ASIX/);
  });
  it('a block in the file ticks its channels and adds one the policy does not offer', async () => {
    const b = build(base({ ['GET ' + GW]: { ...GROUP, state: 'ok', state_text: 'ASIX manages the Windows event channels below', channels: ['Microsoft-Windows-Sysmon/Operational', 'Security'], in_step: true, rows: [] } }));
    const c = b.fn(); await tick(); const names = texts(c).filter((x) => /^ /.test(x)).map((x) => x.trim());
    assert.ok(names.includes('Microsoft-Windows-Sysmon/Operational')); const ticked = boxes(c).filter((x) => x.props.checked).length; assert.strictEqual(ticked, 2); assert.match(texts(c).join(' '), /In step with the filter policy/);
  });
  it('a block written under an older policy says which channels differ and that Preview then Apply fixes it', async () => {
    const c = build(base({ ['GET ' + GW]: { ...GROUP, state: 'ok', channels: ['Security'], in_step: false, rows: [{ channel: 'Security', same: false }, { channel: 'System', same: true }] } })).fn(); await tick();
    const t = texts(c).join(' '); assert.match(t, /Out of step with the filter policy/); assert.match(t, /revision 4\) gives a different query .* for: Security\./); assert.ok(!/for: Security, System/.test(t));
  });
  it('a damaged or hand-edited block cannot be edited, and says what to do; nothing to tick or press', async () => {
    for (const [state, re] of [['broken', /markers for Windows events .* are damaged/], ['edited', /changed by hand/]]) {
      const c = build(base({ ['GET ' + GW]: { ...GROUP, state, state_text: 'x' } })).fn(); await tick(); assert.match(texts(c).join(' '), re); assert.strictEqual(boxes(c).length, 0); assert.ok(!btn(c, 'Preview')); assert.match(texts(c).join(' '), /Cannot edit/);
    }
  });
  it('says what dropping at the agent means and warns about a channel the agent already reads', async () => {
    const c = build(base()).fn(); await tick(); const s = texts(c).join(' ');
    assert.match(s, /events the policy drops are not sent at all/); assert.match(s, /may be read twice/); assert.match(s, /Show logs read/);
  });
});

describe('preview and apply', () => {
  const PREVIEW = { success: true, base_sha256: SHA2, changed: true, diff: { added: ['Security: ' + QUERY], removed: ['System'], changed: [], same: 1 } };
  it('Apply is off until a preview of exactly this selection, and any change of the ticks switches it off again', async () => {
    const b = build(base({ ['POST ' + GW + '/preview']: PREVIEW })); const c = b.fn(); await tick(); const apply = btn(c, 'Apply');
    assert.strictEqual(apply.props.disabled, true); boxes(c)[0].props.onchange({ target: { checked: true } });
    await btn(c, 'Preview').props.onclick(); await tick(); assert.strictEqual(apply.props.disabled, false);
    assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body, { channels: ['Security'] }); const t = texts(c).join(' ');
    assert.match(t, /Will be added \(1\)/); assert.match(t, /Will be removed \(1\)/); assert.match(t, /1 channels stay as they are/); assert.match(t, /Nothing else in the group configuration is touched/);
    boxes(c)[1].props.onchange({ target: { checked: true } }); assert.strictEqual(apply.props.disabled, true);
  });
  it('a preview with no change says so and leaves Apply off', async () => {
    const c = build(base({ ['POST ' + GW + '/preview']: { ...PREVIEW, changed: false } })).fn(); await tick(); await btn(c, 'Preview').props.onclick(); await tick();
    assert.match(texts(c).join(' '), /No change: the manager already has these channels/); assert.strictEqual(btn(c, 'Apply').props.disabled, true);
  });
  it('Apply asks first, sends the channels and the hash of the preview, and reloads', async () => {
    let n = 0; const b = build(base({ ['POST ' + GW + '/preview']: PREVIEW, ['PUT ' + GW]: { success: true, changed: true }, ['GET ' + GW]: () => (++n === 1 ? GROUP : { ...GROUP, sha256: SHA2, state: 'ok', channels: ['Security'], in_step: true }) }));
    const c = b.fn(); await tick(); boxes(c)[0].props.onchange({ target: { checked: true } }); await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick();
    assert.strictEqual(b.confirms.length, 1); assert.match(b.confirms[0], /Windows event channels read by group "default"/); const put = b.calls.find((x) => x.key.startsWith('PUT'));
    assert.deepStrictEqual(put.body, { channels: ['Security'], base_sha256: SHA2 }); assert.strictEqual(b.calls.filter((x) => x.key === 'GET ' + GW).length, 2); assert.match(texts(c).join(' '), /Done\. The manager holds the new channels/);
  });
  it('even if Apply is pressed after the ticks changed (no new preview), the handler itself writes nothing', async () => {
    const b = build(base({ ['POST ' + GW + '/preview']: PREVIEW })); const c = b.fn(); await tick(); boxes(c)[0].props.onchange({ target: { checked: true } }); await btn(c, 'Preview').props.onclick(); await tick();
    boxes(c)[1].props.onchange({ target: { checked: true } }); await btn(c, 'Apply').props.onclick(); await tick(); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT'))); assert.strictEqual(b.confirms.length, 0);
  });
  it('declining the question writes nothing', async () => {
    const b = build(base({ ['POST ' + GW + '/preview']: PREVIEW }), false); const c = b.fn(); await tick(); boxes(c)[0].props.onchange({ target: { checked: true } }); await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick();
    assert.ok(!b.calls.some((x) => x.key.startsWith('PUT')));
  });
  it('a refusal stays in the card as text; a stale file reloads the group and says what the list below is', async () => {
    let b = build(base({ ['POST ' + GW + '/preview']: PREVIEW, ['PUT ' + GW]: new Error('Invalid element in the configuration: query') })); let c = b.fn(); await tick(); boxes(c)[0].props.onchange({ target: { checked: true } });
    await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick(); assert.match(texts(c).join(' '), /Invalid element/);
    b = build(base({ ['POST ' + GW + '/preview']: PREVIEW, ['PUT ' + GW]: new Error('The group configuration changed since you looked at it. Preview again.') })); c = b.fn(); await tick(); boxes(c)[0].props.onchange({ target: { checked: true } });
    await btn(c, 'Preview').props.onclick(); await tick(); await btn(c, 'Apply').props.onclick(); await tick(); assert.match(texts(c).join(' '), /The list below is the one the manager has now/); assert.strictEqual(b.calls.filter((x) => x.key === 'GET ' + GW).length, 2);
  });
  it('another channel can be added by name and is ticked; a name already there is not added twice', async () => {
    const c = build(base()).fn(); await tick(); const inp = all(c).find((x) => x.tag === 'input' && x.props.placeholder && /Another channel/.test(x.props.placeholder));
    inp.props.value = 'Microsoft-Windows-Sysmon/Operational'; btn(c, 'Add a channel').props.onclick(); assert.strictEqual(boxes(c).length, 4); assert.strictEqual(boxes(c)[3].props.checked, true);
    inp.props.value = 'security'; btn(c, 'Add a channel').props.onclick(); assert.strictEqual(boxes(c).length, 4);
  });
});

describe('history and undo', () => {
  const H = [{ id: 'h1', action: 'apply', result: 'applied', channels_after: ['Security'], by: 'ann', at: '2026-11-05T10:00:00Z' }, { id: 'h2', action: 'apply', result: 'failed', channels_after: ['System'], by: null, at: '2026-11-05T09:00:00Z' }];
  it('shows who did what with the result; only an applied change has Undo, and only when writing is on', async () => {
    let c = build(base({ ['GET ' + GW]: { ...GROUP, history: H } })).fn(); await tick(); const t = texts(c).join(' ');
    assert.match(t, /ann: changed the channels \(Security\)/); assert.match(t, /someone: changed the channels \(System\)/); assert.strictEqual(all(c).filter((x) => x.tag === 'button' && x.props.textContent === 'Undo').length, 1);
    c = build(base({ [GCF]: { ...STATUS, write_enabled: false }, ['GET ' + GW]: { ...GROUP, history: H } })).fn(); await tick(); assert.ok(!btn(c, 'Undo'));
  });
  it('Undo asks, sends the history id and the hash read, and reloads', async () => {
    const b = build(base({ ['GET ' + GW]: { ...GROUP, history: H }, ['POST ' + GW + '/undo']: { success: true } })); const c = b.fn(); await tick(); await btn(c, 'Undo').props.onclick(); await tick();
    assert.strictEqual(b.confirms.length, 1); assert.match(b.confirms[0], /queries are the ones the policy gives now/); assert.deepStrictEqual(b.calls.find((x) => x.key.startsWith('POST')).body, { history_id: 'h1', base_sha256: SHA1 });
  });
});

describe('safety of what is drawn', () => {
  it('everything typed or received is set as text, never as HTML', () => { const src = cut('groupWinlogCard'); assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML/.test(src)); });
  it('the card is on the Group settings tab, after the folders card', () => { assert.match(html, /\['groups', 'Group settings', \(\) => \[groupConfigCard\(\), groupWinlogCard\(\)\]\]/); });
  it('a channel name from the server is shown as text even if it looks like markup', async () => {
    const c = build(base({ ['GET ' + GW]: { ...GROUP, channels: ['<img src=x onerror=alert(1)>'], state: 'ok', in_step: true } })).fn(); await tick();
    assert.ok(texts(c).some((x) => x.includes('<img src=x'))); assert.ok(!all(c).some((x) => x.tag === 'img'));
  });
});
