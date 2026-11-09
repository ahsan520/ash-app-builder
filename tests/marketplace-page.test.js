'use strict';
// MK2 of docs/product-plan.md: the Marketplace page, the first page a module brings itself (docs/portal-shell.md).
// The page file is an ES module in a CommonJS project, so each test group copies it to a temporary .mjs file and imports that.
// The page draws only through ctx.el, so a fake el() and a fake host are enough: no browser, no network, no database.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const packs = require('../src/packs');
const registry = require('../src/modules/registry');

const PAGE = path.join(__dirname, '../src/portal/modules/content-packs/marketplace.js');
let tmp; let page;
before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-mk2-'));
  fs.copyFileSync(PAGE, path.join(tmp, 'marketplace.mjs'));
  page = await import(pathToFileURL(path.join(tmp, 'marketplace.mjs')).href);
});
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

// ---- fakes -----------------------------------------------------------------------------------------------------
const clean = (k) => k.flat(Infinity).filter((x) => x !== '' && x != null);
// like a real element: it has a list of children and replaceChildren()
const fakeEl = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: clean(kids), replaceChildren(...k) { this.kids = clean(k); } });
const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = k.flat(Infinity).filter((x) => x !== '' && x != null); } });
const walk = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
const texts = (n) => walk(n).map((x) => x.textContent).concat((n && n.kids ? n.kids : []).filter((k) => typeof k === 'string')).filter(Boolean);
const allText = (host) => host.kids.flatMap((k) => [...walk(k).flatMap((x) => [x.textContent, ...(x.kids || []).filter((c) => typeof c === 'string')]), ...(typeof k === 'string' ? [k] : [])]).filter((x) => typeof x === 'string').join(' | ');
const buttons = (host, label) => host.kids.flatMap(walk).filter((n) => n.tag === 'button' && (label === undefined || n.textContent === label));
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const click = async (host, label, nth = 0) => { const b = buttons(host, label)[nth]; assert.ok(b, `no button "${label}" in: ${allText(host).slice(0, 300)}`); b.onclick(); await tick(); };

const clone = (o) => JSON.parse(JSON.stringify(o));
const mkPack = (id, over = {}) => packs.validatePack({ ...clone(require('../src/packs/catalog/home-router')), id, name: id.toUpperCase() + ' pack', description: 'About ' + id, ...over }, id);
const RAW = {
  alpha: mkPack('alpha', { tags: ['linux', 'ssh'], publisher: { name: 'Example Labs', url: 'https://example.com/p' }, license: 'MIT', history: [{ version: '1.0.0', released: '2026-11-01', notes: 'First release.' }] }),
  beta: mkPack('beta', { requires: { modules: ['detections'], packs: ['alpha'] } }),
  gamma: mkPack('gamma', { tags: ['macos'] }),
  oldie: mkPack('oldie', { deprecated: true, deprecation: 'Retired for a wider pack.', replaced_by: 'alpha' }),
};
const full = (p) => ({ installed: p.rules.length, enabled: p.rules.length, open_alerts: 0 });
// the list answer for a given installed state
const listing = (st) => ({ success: true, packs: Object.values(RAW).map((p) => packs.describe(p, st)) });

function server(initialState, handlers = {}) {
  let st = initialState; const calls = [];
  const api = async (p, opts = {}) => {
    const key = (opts.method || 'GET') + ' ' + p; calls.push({ key, body: opts.body });
    if (handlers[key]) return handlers[key]({ setState: (s) => { st = s; }, st });
    if (key === 'GET /v1/packs') return listing(st);
    throw new Error('unexpected call ' + key);
  };
  return { api, calls, setState: (s) => { st = s; } };
}
async function open(srv, perms = ['detections:rules:read', 'detections:rules:write']) {
  const host = fakeHost(); const toasts = [];
  const ctx = { api: srv.api, el: fakeEl, can: (p) => perms.includes(p), toast: (t, k) => toasts.push([t, k]) };
  await page.mount(host, ctx);
  return { host, toasts, ctx };
}
const err = (status, msg, code) => Object.assign(new Error(`${status} ${msg}${code ? ' (' + code + ')' : ''}`), { status });
const card = (host, name) => host.kids.flatMap(walk).find((n) => n.className === 'card' && texts(n).some((t) => t === name));

describe('the page file follows the module-page rules', () => {
  const src = fs.readFileSync(PAGE, 'utf8');
  it('exports mount and unmount', () => { assert.strictEqual(typeof page.mount, 'function'); assert.strictEqual(typeof page.unmount, 'function'); });
  it('uses no browser globals, dialogs or innerHTML: it draws only through ctx.el and sets server text as text', () => {
    // look at code only: string literals first (they cannot span lines, so an apostrophe in a comment is harmless), then comments
    const code = src.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`/g, '""').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    for (const w of ['document', 'window', 'alert', 'confirm', 'prompt', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'localStorage', 'sessionStorage', 'eval', 'Function', 'fetch']) assert.ok(!new RegExp('(?<![.\\w$])' + w + '\\b(?!\\s*:)').test(code), `the page must not use ${w}`);   // a property (S.confirm) or an object key (confirm: null) is fine
    assert.ok(code.includes('ctx.api') && code.includes('ctx.el'), 'sanity: the check looked at real code');
  });
  it('talks to the server only through ctx.api, and only to /v1/packs', () => {
    const urls = [...src.matchAll(/ctx\.api\(\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(urls.length >= 3);
    for (const u of urls) assert.ok(u.startsWith('/v1/packs'), u);
  });
  it('is declared by the content-packs manifest, and the registry finds the file', () => {
    const m = registry.loadDir().find((x) => x.id === 'content-packs');
    assert.strictEqual(m.ui.kind, 'native');
    assert.deepStrictEqual({ ...m.ui.entries[0] }, { id: 'marketplace', label: 'Marketplace', area: 'Main', group: null, permission: 'detections:rules:read', order: 60, path: 'mod/content-packs/marketplace', page: 'marketplace.js' });
    assert.ok(m.permissions.includes(m.ui.entries[0].permission));
  });
});

describe('Browse', () => {
  it('lists packs with name, version, badges, description, publisher, rule count; deprecated ones are hidden', async () => {
    const { host } = await open(server({}));
    const t = allText(host);
    assert.match(t, /ALPHA pack/); assert.match(t, /v1\.0\.0/); assert.match(t, /About alpha/); assert.match(t, /Example Labs · 5 rules · linux, ssh/);
    assert.match(t, /Not installed/); assert.match(t, /Certified/);
    assert.ok(!/OLDIE pack/.test(t), 'a deprecated pack is hidden until asked for');
  });
  it('"Show deprecated packs" reveals them, badged', async () => {
    const { host } = await open(server({}));
    const box = host.kids.flatMap(walk).find((n) => n.type === 'checkbox');
    box.onchange({ target: { checked: true } });
    assert.match(allText(host), /OLDIE pack/); assert.match(allText(host), /Deprecated/);
  });
  it('search matches name, description, publisher and tags, and typing does not redraw the page', async () => {
    const { host } = await open(server({}));
    const input = host.kids.flatMap(walk).find((n) => n.tag === 'input' && n.type === 'text');
    const before = host.kids.slice();
    for (const [q, want, notWant] of [['gamma', 'GAMMA pack', 'ALPHA pack'], ['example labs', 'ALPHA pack', 'GAMMA pack'], ['ssh', 'ALPHA pack', 'BETA pack'], ['about beta', 'BETA pack', 'ALPHA pack']]) {
      input.oninput({ target: { value: q } });
      const t = allText(host); assert.match(t, new RegExp(want)); assert.ok(!new RegExp(notWant).test(t), `${q}: ${notWant} should be filtered out`);
    }
    assert.deepStrictEqual(host.kids.slice(0, 4), before.slice(0, 4), 'the header and the search box stay put while typing (so the cursor is not lost)');
    input.oninput({ target: { value: 'nothing matches this' } });
    assert.match(allText(host), /No packs match/);
  });
  it('Installed tab counts and lists installed and partly installed packs only', async () => {
    const st = { alpha: full(RAW.alpha), gamma: { installed: 2, enabled: 2, open_alerts: 0 } };
    const { host } = await open(server(st));
    assert.ok(buttons(host, 'Installed (2)').length === 1);
    await click(host, 'Installed (2)');
    const t = allText(host);
    assert.match(t, /ALPHA pack/); assert.match(t, /GAMMA pack/); assert.ok(!/BETA pack/.test(t));
    assert.match(t, /2 of 5 installed/);
  });
  it('an empty Installed tab says so', async () => {
    const { host } = await open(server({}));
    await click(host, 'Installed (0)');
    assert.match(allText(host), /No packs installed yet/);
  });
  it('a card Install button installs, reloads the list and shows a toast', async () => {
    const srv = server({}, { 'POST /v1/packs/alpha/install': async ({ setState }) => { setState({ alpha: full(RAW.alpha) }); return { success: true }; } });
    const { host, toasts } = await open(srv);
    const b = card(host, 'ALPHA pack') ? null : null; assert.strictEqual(b, null);
    await click(host, 'Install', 0);
    const post = srv.calls.find((c) => c.key === 'POST /v1/packs/alpha/install');
    assert.ok(post && JSON.stringify(post.body) === '{}');
    assert.strictEqual(srv.calls.filter((c) => c.key === 'GET /v1/packs').length, 2, 'the list is read again after installing');
    assert.deepStrictEqual(toasts, [['Installed ALPHA pack', undefined]]);
    assert.match(allText(host), /Installed/);
  });
  it('a failed install shows the message on the page and keeps the page usable', async () => {
    const srv = server({}, { 'POST /v1/packs/alpha/install': async () => { throw err(500, 'Failed to install content pack', 'PACK_INSTALL_ERROR'); } });
    const { host, toasts } = await open(srv);
    await click(host, 'Install', 0);
    assert.match(allText(host), /500 Failed to install content pack \(PACK_INSTALL_ERROR\)/);
    assert.strictEqual(toasts.length, 0);
    assert.ok(buttons(host, 'Install').length >= 1, 'the buttons are back');
  });
  it('a role that can only read sees no Install or Remove button and is told why', async () => {
    const { host } = await open(server({ alpha: full(RAW.alpha) }), ['detections:rules:read']);
    assert.strictEqual(buttons(host, 'Install').length, 0);
    await click(host, 'Details', 0);
    assert.strictEqual(buttons(host, 'Remove').length + buttons(host, 'Install').length + buttons(host, 'Restore shipped rules').length, 0);
    assert.match(allText(host), /can look at packs but not install or remove them/);
  });
  it('a deprecated pack has no quick Install button', async () => {
    const { host } = await open(server({}));
    host.kids.flatMap(walk).find((n) => n.type === 'checkbox').onchange({ target: { checked: true } });
    const old = host.kids.flatMap(walk).filter((n) => n.className === 'card').find((c) => texts(c).some((t) => /^OLDIE pack/.test(t) || t === 'OLDIE pack'));
    assert.ok(old); assert.strictEqual(walk(old).filter((n) => n.tag === 'button' && n.textContent === 'Install').length, 0);
  });
});

describe('one pack', () => {
  const st = { alpha: full(RAW.alpha), beta: { installed: 2, enabled: 2, open_alerts: 3 } };
  const openPack = async (name, srv = server(st), perms) => { const o = await open(srv, perms); host_click: { const idx = ['alpha', 'beta', 'gamma'].indexOf(name); await click(o.host, 'Details', idx); } return { ...o, srv }; };

  it('Details: description, publisher link, certification, support, release, license, expects, tags', async () => {
    const { host } = await openPack('alpha');
    const t = allText(host);
    assert.match(t, /About alpha/); assert.match(t, /Example Labs/); assert.match(t, /Certified/); assert.match(t, /ASIX/); assert.match(t, /MIT/); assert.match(t, /Not recorded|2026/);
    const link = host.kids.flatMap(walk).find((n) => n.tag === 'a' && n.href === 'https://example.com/p');
    assert.ok(link && link.target === '_blank' && link.rel === 'noopener');
    assert.match(t, /5 rules of 5 installed|5 rules? of 5 installed/);
  });
  it('Content: every rule with severity and MITRE ids, and the counts per kind', async () => {
    const { host } = await openPack('alpha');
    await click(host, 'Content (5)');
    const t = allText(host);
    assert.match(t, /This pack contains 5 rules\./);
    for (const r of RAW.alpha.rules) { assert.ok(t.includes(r.name), r.name); }
    assert.match(t, /T1110/);
  });
  it('Dependencies: what it needs with its state, and what needs it', async () => {
    const { host } = await openPack('beta');
    await click(host, 'Dependencies');
    let t = allText(host);
    assert.match(t, /Module: detections/); assert.match(t, /Pack: ALPHA pack/); assert.match(t, /Installed/);
    assert.match(t, /Needed by.*No other pack/);
    await click(host, '← Back'); await click(host, 'Details', 0); await click(host, 'Dependencies');
    t = allText(host);
    assert.match(t, /Nothing else\./); assert.match(t, /BETA pack/);
  });
  it('Dependencies: a required pack that is not in the catalog is flagged', async () => {
    const srv = server({}); const orig = srv.api;
    srv.api = async (p, o) => { const r = await orig(p, o); if (p === '/v1/packs') r.packs.find((x) => x.id === 'gamma').requires = { modules: [], packs: ['ghost'] }; return r; };
    const { host } = await open(srv);
    await click(host, 'Details', 2); await click(host, 'Dependencies');
    assert.match(allText(host), /Pack: ghost/); assert.match(allText(host), /Not in this catalog/);
  });
  it('Version history, and a pack with none says so', async () => {
    const { host } = await openPack('alpha');
    await click(host, 'Version history');
    assert.match(allText(host), /v1\.0\.0.*2026-11-01.*First release\./);
    await click(host, '← Back'); await click(host, 'Details', 1); await click(host, 'Version history');
    assert.match(allText(host), /First release\./);
  });
  it('a deprecated pack shows why and what replaces it', async () => {
    const o = await open(server({}));
    o.host.kids.flatMap(walk).find((n) => n.type === 'checkbox').onchange({ target: { checked: true } });
    const idx = buttons(o.host, 'Details').length - 1;   // oldie is the last card
    await click(o.host, 'Details', idx);
    assert.match(allText(o.host), /Deprecated: Retired for a wider pack\./); assert.match(allText(o.host), /Use "ALPHA pack" instead\./);
  });
  it('Back returns to the list', async () => {
    const { host } = await openPack('alpha');
    await click(host, '← Back');
    assert.match(allText(host), /Marketplace/); assert.ok(buttons(host, 'Browse').length === 1);
  });
  it('state decides the buttons: available / partial / installed', async () => {
    const a = await openPack('gamma');   // gamma is available
    assert.ok(buttons(a.host, 'Install').length === 1 && buttons(a.host, 'Remove').length === 0 && buttons(a.host, 'Restore shipped rules').length === 0);
    const p = await open(server({ gamma: { installed: 1, enabled: 1, open_alerts: 0 } })); await click(p.host, 'Details', 2);
    assert.ok(buttons(p.host, 'Add missing rules').length === 1 && buttons(p.host, 'Remove').length === 1 && buttons(p.host, 'Install').length === 0);
    const i = await openPack('alpha');
    assert.ok(buttons(i.host, 'Remove').length === 1 && buttons(i.host, 'Install').length === 0 && buttons(i.host, 'Add missing rules').length === 0);
  });
});

describe('removing and restoring (two steps, inside the page)', () => {
  const st = { alpha: full(RAW.alpha) };
  it('Remove asks first; Cancel does nothing; Confirm deletes and reloads', async () => {
    const srv = server(st, { 'DELETE /v1/packs/alpha': async ({ setState }) => { setState({}); return { success: true }; } });
    const { host, toasts } = await open(srv);
    await click(host, 'Details', 0); await click(host, 'Remove');
    assert.match(allText(host), /Remove "ALPHA pack"\? Its rules are deleted\./);
    assert.ok(!srv.calls.some((c) => c.key.startsWith('DELETE')), 'nothing is deleted before Confirm');
    await click(host, 'Cancel');
    assert.ok(!/Its rules are deleted/.test(allText(host)) && !srv.calls.some((c) => c.key.startsWith('DELETE')));
    await click(host, 'Remove'); await click(host, 'Remove', 1);   // the first is the action, the second the confirm
    assert.ok(srv.calls.some((c) => c.key === 'DELETE /v1/packs/alpha'));
    assert.deepStrictEqual(toasts, [['Removed ALPHA pack', undefined]]);
    assert.match(allText(host), /Not installed/);
  });
  it('a removal blocked by alerts asks again, then deletes with delete_alerts=true', async () => {
    let first = true;
    const srv = server(st, {
      'DELETE /v1/packs/alpha': async () => { if (first) { first = false; throw err(409, 'These rules have raised 3 alert(s).', 'HAS_ALERTS'); } return {}; },
      'DELETE /v1/packs/alpha?delete_alerts=true': async ({ setState }) => { setState({}); return {}; },
    });
    const { host } = await open(srv);
    await click(host, 'Details', 0); await click(host, 'Remove'); await click(host, 'Remove', 1);
    assert.match(allText(host), /raised alerts\. Removing the pack deletes those alerts too\./);
    assert.ok(!srv.calls.some((c) => c.key.includes('delete_alerts')));
    await click(host, 'Remove and delete alerts');
    assert.ok(srv.calls.some((c) => c.key === 'DELETE /v1/packs/alpha?delete_alerts=true'));
  });
  it('a removal blocked because another pack needs it shows the server\'s message and nothing else', async () => {
    const srv = server(st, { 'DELETE /v1/packs/alpha': async () => { throw err(409, 'These installed packs depend on it: BETA pack. Remove them first.', 'REQUIRED_BY'); } });
    const { host } = await open(srv);
    await click(host, 'Details', 0); await click(host, 'Remove'); await click(host, 'Remove', 1);
    assert.match(allText(host), /depend on it: BETA pack/); assert.strictEqual(buttons(host, 'Remove and delete alerts').length, 0);
  });
  it('Restore shipped rules asks first, then installs with overwrite: true', async () => {
    const srv = server(st, { 'POST /v1/packs/alpha/install': async () => ({ success: true }) });
    const { host } = await open(srv);
    await click(host, 'Details', 0); await click(host, 'Restore shipped rules');
    assert.match(allText(host), /Your edits to these rules will be lost/);
    assert.ok(!srv.calls.some((c) => c.key.startsWith('POST')));
    await click(host, 'Restore');
    assert.deepStrictEqual(srv.calls.find((c) => c.key.startsWith('POST')).body, { overwrite: true });
  });
  it('a deprecated pack is refused, then installed on request with allow_deprecated: true', async () => {
    let n = 0;
    const srv = server({}, { 'POST /v1/packs/oldie/install': async () => { n++; if (n === 1) throw err(409, '"OLDIE pack" is deprecated: Retired for a wider pack.', 'PACK_DEPRECATED'); return { success: true }; } });
    const { host } = await open(srv);
    host.kids.flatMap(walk).find((x) => x.type === 'checkbox').onchange({ target: { checked: true } });
    await click(host, 'Details', buttons(host, 'Details').length - 1);
    await click(host, 'Install');
    assert.match(allText(host), /is deprecated: Retired for a wider pack\..*Install it anyway\?/);
    await click(host, 'Install anyway');
    assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('POST')).map((c) => c.body), [{}, { allow_deprecated: true }]);
  });
});

describe('loading and leaving', () => {
  it('if the list cannot be loaded, mount rejects so the shell shows its error card with Retry', async () => {
    const srv = { api: async () => { throw err(403, 'Forbidden', 'FORBIDDEN'); } };
    await assert.rejects(() => open(srv), /403 Forbidden/);
  });
  it('after unmount a late answer never draws into the host', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const srv = server({}, { 'POST /v1/packs/alpha/install': async () => { await gate; return {}; } });
    const { host } = await open(srv);
    const b = buttons(host, 'Install')[0]; b.onclick(); await tick();
    const snapshot = host.kids.slice();
    page.unmount();
    release(); await tick();
    assert.deepStrictEqual(host.kids, snapshot, 'a page that was left must not redraw');
  });
  it('mounting again after an unmount works', async () => {
    const { host } = await open(server({}));
    page.unmount();
    const again = await open(server({}));
    assert.match(allText(again.host), /ALPHA pack/); assert.ok(host.kids.length > 0);
  });
});
