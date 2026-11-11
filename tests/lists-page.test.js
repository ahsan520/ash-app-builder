'use strict';
// L1: the Lists page, a page the module brings itself (docs/portal-shell.md). Same method as tests/actions-page.test.js: the page file is copied to a temporary
// .mjs file and imported; it draws only through ctx.el, so a fake el() and a fake server are enough.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = path.join(__dirname, '../src/portal/modules/lists/lists.js');
let tmp; let page;
before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-lists-'));
  fs.copyFileSync(PAGE, path.join(tmp, 'lists.mjs'));
  page = await import(pathToFileURL(path.join(tmp, 'lists.mjs')).href);
});
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

// ---- fakes -----------------------------------------------------------------------------------------------------
const clean = (k) => k.flat(Infinity).filter((x) => x !== '' && x != null);
const fakeEl = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: clean(kids), replaceChildren(...k) { this.kids = clean(k); } });
const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = clean(k); } });
const walk = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
const allText = (host) => host.kids.flatMap(walk).flatMap((x) => [x.textContent, ...(x.kids || []).filter((c) => typeof c === 'string')]).filter((x) => typeof x === 'string').join(' | ');
const all = (host) => host.kids.flatMap(walk);
const buttons = (host, label) => all(host).filter((n) => n.tag === 'button' && (label === undefined || n.textContent === label));
const tick = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };
const click = async (host, label, nth = 0) => { const b = buttons(host, label)[nth]; assert.ok(b, `no button "${label}" in: ${allText(host).slice(0, 600)}`); assert.ok(!b.disabled, `"${label}" is disabled`); b.onclick(); await tick(); };
const textareas = (host) => all(host).filter((n) => n.tag === 'textarea');
const selects = (host) => all(host).filter((n) => n.tag === 'select');
const inputs = (host) => all(host).filter((n) => n.tag === 'input');
const textInputs = (host) => inputs(host).filter((n) => n.type === 'text');
const type = (node, value) => { node.value = value; node.oninput({ target: node }); };
const bolds = (host) => all(host).filter((n) => n.tag === 'b').map((n) => n.textContent);   // the entry values are drawn bold; the help text that quotes an example is not
const choose = (sel, value) => { sel.onchange({ target: { value } }); };

const ID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const mkList = (n, over = {}) => ({ id: ID(n), name: 'List ' + n, kind: 'block', item_type: 'ip', description: null, allow_private: false, created_by_name: 'alice', created_at: '2026-11-10T10:00:00', updated_at: '2026-11-10T10:00:00',
  feed_enabled: false, feed_token_hint: null, feed_created_at: null, feed_last_fetch_at: null, feed_last_fetch_ip: null, entry_count: 0, ...over });
const mkEntry = (value, over = {}) => ({ value, note: null, source: 'manual', added_by_name: 'alice', added_at: '2026-11-10T10:00:00', expires_at: null, ...over });
const CHOICES = { kinds: ['block', 'allow', 'watch'], item_types: ['ip', 'domain', 'url', 'hash'], expires: ['never', '1h', '24h', '7d', '30d', '90d'] };

// A fake server holding lists and their entries; `calls` records every request.
function server(initial = [], entriesOf = {}) {
  const S = { lists: initial.map((l) => ({ ...l })), entries: { ...entriesOf }, calls: [], fail: null, refusals: [], feed: { url: 'https://asix.example:30443/v1/list-feed/asix_lt_SECRET', path: '/v1/list-feed/asix_lt_SECRET' } };
  S.api = async (p, opts = {}) => {
    const method = opts.method || 'GET'; S.calls.push({ method, path: p, body: opts.body });
    if (S.fail && S.fail.test(method + ' ' + p)) throw new Error('The server said no');
    let m;
    if (method === 'GET' && p === '/v1/lists') return { success: true, lists: S.lists, ...CHOICES };
    if (method === 'POST' && p === '/v1/lists') { const l = mkList(50, { ...opts.body, id: ID(50) }); S.lists.push(l); S.entries[l.id] = []; return { success: true, list: l }; }
    if ((m = /^\/v1\/lists\/([^/?]+)\/entries\?(.*)$/.exec(p)) && method === 'GET') {
      const q = new URLSearchParams(m[2]); const all = (S.entries[m[1]] || []).filter((e) => !q.get('q') || e.value.includes(q.get('q')));
      const off = Number(q.get('offset')); return { success: true, list: S.lists.find((l) => l.id === m[1]), entries: all.slice(off, off + Number(q.get('limit'))), total: all.length };
    }
    if ((m = /^\/v1\/lists\/([^/]+)\/entries$/.exec(p)) && method === 'POST') {
      const l = S.lists.find((x) => x.id === m[1]); const vals = opts.body.text.split('\n').map((x) => x.trim()).filter(Boolean);
      const refused = vals.filter((v) => S.refusals.includes(v)).map((v) => ({ value: v, code: 'PRIVATE_ADDRESS', message: v + ' is a private address' }));
      const added = vals.filter((v) => !S.refusals.includes(v)); S.entries[l.id] = [...(S.entries[l.id] || []), ...added.map((v) => mkEntry(v))]; l.entry_count = S.entries[l.id].length;
      return { success: true, list: l, added, existing: [], refused };
    }
    if ((m = /^\/v1\/lists\/([^/]+)\/entries\/remove$/.exec(p)) && method === 'POST') {
      const l = S.lists.find((x) => x.id === m[1]); S.entries[l.id] = S.entries[l.id].filter((e) => !opts.body.values.includes(e.value)); l.entry_count = S.entries[l.id].length; return { success: true, removed: opts.body.values, missing: [] };
    }
    if ((m = /^\/v1\/lists\/([^/]+)\/feed$/.exec(p))) {
      const l = S.lists.find((x) => x.id === m[1]);
      if (method === 'POST') { l.feed_enabled = true; l.feed_token_hint = 'CRET'; l.feed_created_at = '2026-11-10T11:00:00'; return { success: true, list: l, feed_path: S.feed.path, feed_url: S.feed.url }; }
      l.feed_enabled = false; l.feed_token_hint = null; return { success: true, list: l };
    }
    if ((m = /^\/v1\/lists\/([^/]+)$/.exec(p)) && method === 'DELETE') { S.lists = S.lists.filter((x) => x.id !== m[1]); return { success: true }; }
    throw new Error('unexpected ' + method + ' ' + p);
  };
  return S;
}
const ctxFor = (S, { write = true } = {}) => ({ el: fakeEl, api: S.api, can: (p) => (p === 'soar:lists:write' ? write : true), tenant: 't', navigate() {}, theme: 'dark', toasts: [], toast(t, k) { this.toasts.push([t, k]); } });
async function open(S, opts) { const host = fakeHost(); const ctx = ctxFor(S, opts); await page.mount(host, ctx); return { host, ctx }; }

describe('the list of lists', () => {
  it('shows each list with its purpose, type, size and whether it is published', async () => {
    const S = server([mkList(1, { name: 'Bad IPs', entry_count: 3, feed_enabled: true, feed_last_fetch_at: '2026-11-10T12:30:00', feed_last_fetch_ip: '192.168.1.1' }),
      mkList(2, { name: 'Our DNS', kind: 'allow', item_type: 'domain', entry_count: 1 })]);
    const { host } = await open(S);
    const t = allText(host);
    assert.match(t, /Bad IPs/); assert.match(t, /Block/); assert.match(t, /IP addresses and networks/); assert.match(t, /3 entries/); assert.match(t, /Published/);
    assert.match(t, /Last fetched 2026-11-10 12:30 from 192\.168\.1\.1/);
    assert.match(t, /Our DNS/); assert.match(t, /Allow/); assert.match(t, /Domain names/); assert.match(t, /1 entry/); assert.match(t, /Not published/);
  });
  it('says so when there are none', async () => { const { host } = await open(server([])); assert.match(allText(host), /There are no lists yet/); });
  it('a viewer without the write permission sees no button that changes anything', async () => {
    const S = server([mkList(1, { entry_count: 1, feed_enabled: true })], { [ID(1)]: [mkEntry('1.2.3.4')] });
    const { host } = await open(S, { write: false });
    assert.strictEqual(buttons(host, 'New list').length, 0);
    await click(host, 'Open');
    const labels = buttons(host).map((b) => b.textContent);
    for (const bad of ['Add', 'Remove', 'Make the address', 'Make a new address', 'Turn the address off', 'Delete the list…']) assert.ok(!labels.includes(bad), bad);
    assert.strictEqual(textareas(host).length, 0);
    assert.match(allText(host), /1\.2\.3\.4/);
  });
});

describe('making a list', () => {
  it('sends the name, purpose and type, then opens the new list', async () => {
    const S = server([]); const { host, ctx } = await open(S);
    await click(host, 'New list');
    type(textInputs(host)[0], 'Blocked scanners');
    choose(selects(host)[1], 'domain'); await tick();
    type(textInputs(host)[0], 'Blocked scanners');   // the redraw keeps typed text; typing again is harmless
    await click(host, 'Create');
    const post = S.calls.find((c) => c.method === 'POST' && c.path === '/v1/lists');
    assert.deepStrictEqual(post.body, { name: 'Blocked scanners', kind: 'block', item_type: 'domain', description: '' });
    assert.match(allText(host), /Blocked scanners/); assert.match(allText(host), /Entries/);
    assert.ok(ctx.toasts.some(([t]) => /created/.test(t)));
  });
  it('offers private addresses only for a block list of addresses, and sends the choice', async () => {
    const S = server([]); const { host } = await open(S);
    await click(host, 'New list');
    assert.ok(inputs(host).some((i) => i.type === 'checkbox'));
    choose(selects(host)[0], 'allow'); await tick();
    assert.ok(!inputs(host).some((i) => i.type === 'checkbox'));
    choose(selects(host)[0], 'block'); await tick();
    type(textInputs(host)[0], 'Home');
    const box = inputs(host).find((i) => i.type === 'checkbox'); box.onchange({ target: { checked: true } });
    await click(host, 'Create');
    assert.strictEqual(S.calls.find((c) => c.method === 'POST' && c.path === '/v1/lists').body.allow_private, true);
  });
  it('a refusal keeps the form and shows the reason', async () => {
    const S = server([]); S.fail = /^POST \/v1\/lists$/; const { host } = await open(S);
    await click(host, 'New list'); type(textInputs(host)[0], 'Dup');
    await click(host, 'Create');
    assert.match(allText(host), /The server said no/);
    assert.strictEqual(textInputs(host)[0].value, 'Dup');
  });
});

describe('one list', () => {
  const setup = async (opts, list = mkList(1, { entry_count: 2 }), entries = [mkEntry('203.0.113.7', { note: 'scanner', expires_at: '2026-12-01T00:00:00' }), mkEntry('198.51.100.0/24', { source: 'action' })]) => {
    const S = server([list], { [list.id]: entries }); const o = await open(S, opts); await click(o.host, 'Open'); return { S, ...o };
  };
  it('shows the entries with their note, source and expiry', async () => {
    const { host } = await setup();
    const t = allText(host);
    assert.match(t, /203\.0\.113\.7/); assert.match(t, /scanner/); assert.match(t, /expires 2026-12-01 00:00/); assert.match(t, /does not expire/); assert.match(t, /by an action/);
  });
  it('adds entries with the chosen time, and says what happened to each', async () => {
    const { S, host } = await setup();
    S.refusals = ['10.0.0.5'];
    const ta = textareas(host)[0]; type(ta, '192.0.2.1\n10.0.0.5');
    choose(selects(host).find((s) => s.kids.some((o) => o.value === '7d')), '7d');
    type(textInputs(host).find((i) => i.value === '' && !i.placeholder), 'from the blog');
    await click(host, 'Add');
    const post = S.calls.find((c) => c.method === 'POST' && /entries$/.test(c.path));
    assert.deepStrictEqual(post.body, { text: '192.0.2.1\n10.0.0.5', expires: '7d', note: 'from the blog' });
    const t = allText(host);
    assert.match(t, /Added 1\. Already on the list: 0\. Refused: 1\./); assert.match(t, /10\.0\.0\.5: 10\.0\.0\.5 is a private address/);
    assert.strictEqual(textareas(host)[0].value, '192.0.2.1\n10.0.0.5');   // with a refusal the text stays, so it can be fixed
  });
  it('clears the box when everything went in', async () => {
    const { host } = await setup();
    type(textareas(host)[0], '192.0.2.9'); await click(host, 'Add');
    assert.strictEqual(textareas(host)[0].value, ''); assert.match(allText(host), /Added 1/);
  });
  it('Add with an empty box asks for a value and sends nothing', async () => {
    const { S, host } = await setup(); const n = S.calls.length;
    await click(host, 'Add'); assert.match(allText(host), /Type or paste at least one value/); assert.strictEqual(S.calls.length, n);
  });
  it('searches by a plain text', async () => {
    const { S, host } = await setup();
    type(textInputs(host).find((i) => i.placeholder === 'Search'), '198.51'); await click(host, 'Search');
    assert.ok(S.calls.some((c) => /entries\?limit=50&offset=0&q=198\.51$/.test(c.path)));
    assert.ok(bolds(host).includes('198.51.100.0/24')); assert.ok(!bolds(host).includes('203.0.113.7'));
  });
  it('pages through a long list', async () => {
    const many = Array.from({ length: 120 }, (_, i) => mkEntry('v' + String(i).padStart(3, '0') + '.example.com'));
    const { S, host } = await setup({}, mkList(1, { item_type: 'domain', entry_count: 120 }), many);
    assert.match(allText(host), /Showing 1 to 50 of 120/);
    await click(host, 'Next');
    assert.ok(S.calls.some((c) => /offset=50/.test(c.path))); assert.match(allText(host), /Showing 51 to 100 of 120/); assert.match(allText(host), /v050\.example\.com/);
  });
  it('removing an entry takes two presses', async () => {
    const { S, host } = await setup();
    await click(host, 'Remove');
    assert.ok(!S.calls.some((c) => /entries\/remove/.test(c.path)));
    assert.match(allText(host), /Take it off the list\?/);
    await click(host, 'No'); assert.ok(!S.calls.some((c) => /entries\/remove/.test(c.path)));
    await click(host, 'Remove'); await click(host, 'Yes, remove');
    assert.deepStrictEqual(S.calls.find((c) => /entries\/remove/.test(c.path)).body, { values: ['203.0.113.7'] });
    assert.ok(!bolds(host).includes('203.0.113.7')); assert.ok(bolds(host).includes('198.51.100.0/24'));
  });
  it('the firewall address: made, shown once, never again', async () => {
    const { S, host } = await setup();
    assert.match(allText(host), /Off: nothing is published/);
    await click(host, 'Make the address');
    const shown = inputs(host).find((i) => i.readOnly);
    assert.strictEqual(shown.value, S.feed.url); assert.match(allText(host), /Copy this address now/);
    assert.match(allText(host), /ends in …CRET/);
    await click(host, 'Back to the lists'); await click(host, 'Open');
    assert.ok(!inputs(host).some((i) => i.readOnly), 'the secret must be gone after leaving the page');
    assert.ok(!allText(host).includes('SECRET'));
  });
  it('shows only the path when the server could not tell its own address', async () => {
    const { S, host } = await setup(); S.feed.url = null;
    await click(host, 'Make the address');
    assert.strictEqual(inputs(host).find((i) => i.readOnly).value, S.feed.path); assert.match(allText(host), /Put the address of ASIX in front of this path/);
  });
  it('a new address and turning it off each take two presses', async () => {
    const { S, host } = await setup(); await click(host, 'Make the address');
    await click(host, 'Make a new address');
    assert.strictEqual(S.calls.filter((c) => c.method === 'POST' && /\/feed$/.test(c.path)).length, 1); assert.match(allText(host), /old address stops working at once/);
    await click(host, 'No');
    await click(host, 'Turn the address off'); assert.match(allText(host), /stop getting this list/);
    assert.ok(!S.calls.some((c) => c.method === 'DELETE' && /feed$/.test(c.path)));
    await click(host, 'Yes, turn it off');
    assert.ok(S.calls.some((c) => c.method === 'DELETE' && /feed$/.test(c.path))); assert.match(allText(host), /Off: nothing is published/);
    await click(host, 'Make the address'); await click(host, 'Make a new address'); await click(host, 'Yes, make a new one');
    assert.strictEqual(S.calls.filter((c) => c.method === 'POST' && /\/feed$/.test(c.path)).length, 3);
  });
  it('deleting the list takes two presses and returns to the lists', async () => {
    const { S, host, ctx } = await setup();
    await click(host, 'Delete the list…'); assert.match(allText(host), /Delete "List 1" and its 2 entries\?/);
    assert.ok(!S.calls.some((c) => c.method === 'DELETE'));
    await click(host, 'Yes, delete');
    assert.ok(S.calls.some((c) => c.method === 'DELETE' && c.path === '/v1/lists/' + ID(1)));
    assert.match(allText(host), /There are no lists yet/); assert.ok(ctx.toasts.some(([t]) => /deleted/.test(t)));
  });
  it('a failed change shows the reason and keeps what was typed', async () => {
    const { S, host } = await setup(); S.fail = /entries$/;
    type(textareas(host)[0], '192.0.2.77'); await click(host, 'Add');
    assert.match(allText(host), /The server said no/); assert.strictEqual(textareas(host)[0].value, '192.0.2.77');
  });
});

describe('the page file', () => {
  const src = fs.readFileSync(PAGE, 'utf8');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/\s\/\/\s.*$/gm, '');
  it('draws only through ctx.el and talks only through ctx.api', () => {
    for (const bad of [/\bdocument\b/, /\bwindow\b/, /\binnerHTML\b/, /\balert\(/, /\bconfirm\(/, /\bfetch\(/, /\blocalStorage\b/, /\bXMLHttpRequest\b/, /\beval\(/]) assert.ok(!bad.test(code), String(bad));
  });
  it('does not draw after the page is left', async () => {
    const S = server([mkList(1)]); const host = fakeHost(); const ctx = ctxFor(S); await page.mount(host, ctx);
    page.unmount(); const before = JSON.stringify(host.kids.length);
    host.replaceChildren(); await new Promise((r) => setImmediate(r));
    assert.strictEqual(host.kids.length, 0, before);
  });
  it('is the page the manifest names', () => {
    const m = require('../src/modules/manifests/lists');
    assert.deepStrictEqual(m.ui.entries.map((e) => e.page), ['lists.js']);
    assert.ok(fs.existsSync(path.join(__dirname, '../src/portal/modules/lists', m.ui.entries[0].page)));
    assert.ok(m.permissions.includes(m.ui.entries[0].permission));
  });
});
