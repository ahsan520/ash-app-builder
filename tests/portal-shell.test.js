'use strict';
// S2 of docs/product-plan.md: the portal shell loader in src/portal/index.html (docs/portal-shell.md).
// The portal is one HTML file with no build step, so this test cuts the two marked blocks out of it ("menu-state" and
// "module-shell") and runs them on their own with a fake el() and a fake page loader: no DOM, no network.
// Running them in a bare context is itself a check: a block that reached for `document` or `window` would throw here.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '../src/portal/index.html'), 'utf8');
const cut = (name) => { const m = html.match(new RegExp('// BEGIN ' + name + '[^\\n]*\\n([\\s\\S]*?)// END ' + name)); assert.ok(m, `the ${name} block markers are missing from index.html`); return m[1]; };

// like the page's el(), plus setAttribute (the shell sets the iframe sandbox as an attribute)
function fakeEl(tag, props, ...kids) { return { tag, ...(props || {}), kids: kids.flat(), attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } }; }
// A fresh copy of the blocks for each test group, so the module-level state (shellCur, shellSeq, shellRetry) starts clean.
function load() {
  const ctx = { el: fakeEl };
  vm.createContext(ctx);
  vm.runInContext(cut('menu-state') + '\n' + cut('module-shell') + `
    this.api = { menuSet, menuModule, shellEntries, shellIn, shellLeaf, shellCan, shellGroups, shellMount, shellRun, shellLeave, shellAgain, shellTake, shellErrorCard,
                 cur: () => shellCur, limitMs: () => SHELL_LIMIT_MS };`, ctx);
  return ctx.api;
}

const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = k; }, append(...k) { this.kids.push(...k); } });
const texts = (n) => (n == null ? [] : typeof n === 'string' ? [n] : [n.textContent, n.href, n.src, n.title, ...(n.kids || []).flatMap(texts)].filter(Boolean));
const find = (n, pred) => (n && typeof n === 'object' ? (pred(n) ? [n] : []).concat((n.kids || []).flatMap((k) => find(k, pred))) : []);
// arrays built inside the vm context have another realm's Array prototype, which deepStrictEqual rejects: compare them as plain JSON
const same = (actual, expected) => assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected);
const never = () => 0;                                  // a timer that never fires
const entry = (over = {}) => ({ id: 'browse', label: 'Marketplace', area: 'Settings', group: 'Content', permission: null, order: 20, path: 'mod/market/browse', page: 'marketplace.js', kind: 'native', moduleId: 'market', moduleName: 'Marketplace module', state: 'enabled', ...over });
const row = (id, kind, entries, state = 'enabled') => ({ id, name: id + ' name', state, ui: { kind, entries } });
const e1 = (id, over = {}) => ({ id: 'main', label: id, area: 'Main', group: null, permission: null, order: 100, path: `mod/${id}/main`, page: 'p.js', ...over });

describe('which module pages are listed', () => {
  const S = load();
  it('lists nothing while the module list is unknown or has no ui (the old menu arrays are all there is)', () => {
    same(S.shellEntries(null), []);
    same(S.shellEntries({}), []);
    same(S.shellEntries({ a: { id: 'a', ui: null }, b: { id: 'b' } }), []);
  });
  it('lists native and embedded entries only; builtin entries stay with the old arrays', () => {
    const mods = {
      nat: row('nat', 'native', [e1('nat')]),
      emb: row('emb', 'embedded', [e1('emb', { page: undefined, url: '/app/emb/' })]),
      old: row('old', 'builtin', [{ id: 'main', label: 'old', area: 'Settings', path: 'settings/retention' }]),
    };
    same(S.shellEntries(mods).map((e) => e.moduleId), ['emb', 'nat']);
  });
  it('orders by order, then by label', () => {
    const mods = { aa: row('aa', 'native', [e1('aa', { order: 50, label: 'Zed' }), { ...e1('aa'), id: 'two', path: 'mod/aa/two', label: 'Alpha', order: 50 }]), bb: row('bb', 'native', [e1('bb', { order: 5, label: 'First' })]) };
    same(S.shellEntries(mods).map((e) => e.label), ['First', 'Alpha', 'Zed']);
  });
  it('skips rows from the server that are malformed or try to claim another module\'s path', () => {
    const mods = {
      mine: row('mine', 'native', [
        e1('mine'),
        e1('mine', { path: 'mod/other/main' }),                // somebody else's path
        e1('mine', { path: 'settings/retention' }),            // an old page's path
        e1('mine', { path: 'mod/mine/../x' }),
        e1('mine', { area: 'Elsewhere' }),
        e1('mine', { label: undefined }),
        null,
      ]),
      bad: { id: 'bad', ui: { kind: 'react', entries: [e1('bad')] } },
      worse: { id: 'worse', ui: { kind: 'native', entries: 'nope' } },
    };
    same(S.shellEntries(mods).map((e) => e.path), ['mod/mine/main']);
  });
  it('keeps the module name and state on each entry', () => {
    const [e] = S.shellEntries({ nat: row('nat', 'native', [e1('nat')], 'locked') });
    assert.strictEqual(e.moduleName, 'nat name');
    assert.strictEqual(e.state, 'locked');
    assert.strictEqual(e.kind, 'native');
  });
  it('shellIn picks one menu, shellLeaf one page', () => {
    const mods = { aa: row('aa', 'native', [e1('aa', { area: 'Settings' })]), bb: row('bb', 'native', [e1('bb', { area: 'Threat Management' })]), cc: row('cc', 'native', [e1('cc')]) };
    same(S.shellIn('Settings', mods).map((e) => e.moduleId), ['aa']);
    same(S.shellIn('Threat Management', mods).map((e) => e.moduleId), ['bb']);
    same(S.shellIn('Main', mods).map((e) => e.moduleId), ['cc']);
    assert.strictEqual(S.shellLeaf('mod/bb/main', mods).moduleId, 'bb');
    assert.strictEqual(S.shellLeaf('mod/nope/main', mods), null);
    assert.strictEqual(S.shellLeaf('settings/retention', mods), null);
  });
  it('groups entries under their heading in the order first seen, "More" when there is none', () => {
    const list = [entry({ id: 'a', group: 'Content' }), entry({ id: 'b', group: null }), entry({ id: 'c', group: 'Content' })];
    same(S.shellGroups(list).map((g) => [g.group, g.items.map((i) => i.id)]), [['Content', ['a', 'c']], ['More', ['b']]]);
  });
});

describe('permissions in the menu', () => {
  const S = load();
  it('everything is allowed while the caller\'s permissions are unknown, or none is required', () => {
    assert.strictEqual(S.shellCan(null, 'packs:read'), true);
    assert.strictEqual(S.shellCan(undefined, 'packs:read'), true);
    assert.strictEqual(S.shellCan(['x'], null), true);
    assert.strictEqual(S.shellCan([], ''), true);
  });
  it('a known list must contain the permission exactly (the server matches the same way)', () => {
    assert.strictEqual(S.shellCan(['packs:read'], 'packs:read'), true);
    assert.strictEqual(S.shellCan(['packs:write'], 'packs:read'), false);
    assert.strictEqual(S.shellCan([], 'packs:read'), false);
    assert.strictEqual(S.shellCan(['packs:*'], 'packs:read'), false);
  });
});

describe('a module page greys out like any other when its module is not on', () => {
  it('menuModule finds the module from the mod/<id>/<entry> path', () => {
    const S = load();
    S.menuSet([{ id: 'market', state: 'enabled', name: 'market' }, { id: 'soar', state: 'planned', name: 'soar' }, { id: 'locked1', state: 'locked', name: 'l' }]);
    assert.strictEqual(S.menuModule('mod/market/browse'), null);
    assert.strictEqual(S.menuModule('mod/soar/main').state, 'planned');
    assert.strictEqual(S.menuModule('mod/locked1/x').state, 'locked');
    assert.strictEqual(S.menuModule('mod/unknown/x'), null);
  });
  it('the old paths behave exactly as before', () => {
    const S = load();
    S.menuSet([{ id: 'alerts', state: 'locked', name: 'a' }]);
    assert.strictEqual(S.menuModule('incidents').state, 'locked');
    assert.strictEqual(S.menuModule('dashboard'), null);
    assert.strictEqual(S.menuModule(''), null);
  });
});

describe('loading a native page', () => {
  it('imports the page file, clears the host and mounts with the given ctx', async () => {
    const S = load(); const host = fakeHost(); host.kids = ['old']; const ctx = { marker: 1 }; let url; let got;
    const mod = { mount: async (h, c) => { got = [h, c]; h.append('drawn'); }, unmount() {} };
    const r = await S.shellMount(entry(), host, ctx, 0, { setT: never, importFn: async (u) => { url = u; return mod; }, log() {} });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(url, '/portal/modules/market/marketplace.js');
    assert.strictEqual(got[0], host); assert.strictEqual(got[1], ctx);
    assert.deepStrictEqual(host.kids, ['drawn']);
    assert.strictEqual(r.unmount, mod.unmount);
  });
  it('a page without unmount is fine', async () => {
    const S = load();
    const r = await S.shellMount(entry(), fakeHost(), {}, 0, { setT: never, importFn: async () => ({ mount() {} }), log() {} });
    assert.strictEqual(r.ok, true); assert.strictEqual(r.unmount, null);
  });
  it('Retry loads a fresh copy: the attempt number goes on the address as a query', async () => {
    const S = load(); const urls = [];
    const deps = { setT: never, importFn: async (u) => { urls.push(u); return { mount() {} }; }, log() {} };
    await S.shellMount(entry(), fakeHost(), {}, 0, deps);
    await S.shellMount(entry(), fakeHost(), {}, 2, deps);
    assert.deepStrictEqual(urls, ['/portal/modules/market/marketplace.js', '/portal/modules/market/marketplace.js?r=2']);
  });
  it('waits no longer than 10 seconds for the file', async () => {
    const S = load(); const host = fakeHost(); let asked; const logs = [];
    const r = await S.shellMount(entry(), host, {}, 0, { importFn: () => new Promise(() => {}), setT: (fn, ms) => { asked = ms; fn(); return 1; }, log: (e, c) => logs.push(c) });
    assert.strictEqual(S.limitMs(), 10000);
    assert.strictEqual(asked, 10000);
    assert.strictEqual(r.ok, false);
    assert.match(r.cause, /did not finish loading in 10 seconds/);
    assert.match(texts(host.kids[0]).join(' '), /did not finish loading in 10 seconds/);
    assert.strictEqual(logs.length, 1);
  });
});

describe('a page that fails shows the error card and nothing else breaks', () => {
  const cases = [
    ['the file is missing (import rejects)', () => ({ importFn: async () => { throw new Error('Failed to fetch dynamically imported module'); } }), /Failed to fetch dynamically imported module/],
    ['the file has a syntax error', () => ({ importFn: async () => { throw new SyntaxError('Unexpected token }'); } }), /Unexpected token/],
    ['the file has no mount()', () => ({ importFn: async () => ({ nothing: true }) }), /no mount\(\) function/],
    ['the file exports nothing', () => ({ importFn: async () => null }), /no mount\(\) function/],
    ['mount throws', () => ({ importFn: async () => ({ mount() { throw new Error('boom in mount'); } }) }), /boom in mount/],
    ['mount rejects', () => ({ importFn: async () => ({ mount: async () => { throw new Error('rejected in mount'); } }) }), /rejected in mount/],
    ['the loader itself throws at once', () => ({ importFn: () => { throw new Error('no loader here'); } }), /no loader here/],
  ];
  for (const [name, mk, re] of cases) {
    it(name, async () => {
      const S = load(); const host = fakeHost(); const logs = [];
      host.kids = ['half drawn page'];
      const r = await S.shellMount(entry(), host, {}, 0, { setT: never, log: (e, c) => logs.push([e.moduleId, c]), retry() {}, ...mk() });
      assert.strictEqual(r.ok, false);
      assert.strictEqual(r.unmount, null);
      assert.strictEqual(host.kids.length, 1, 'the card replaces whatever was drawn');
      const card = host.kids[0];
      const all = texts(card).join(' | ');
      assert.match(all, /This page could not be loaded/);
      assert.match(all, /Marketplace module/);            // names the module
      assert.match(all, re);                              // and the cause
      assert.match(all, /rest of ASIX is not affected/);
      assert.ok(find(card, (n) => n.tag === 'button' && n.textContent === 'Retry').length === 1);
      assert.ok(find(card, (n) => n.tag === 'a' && n.href === '#/modules').length === 1);
      assert.deepStrictEqual(logs.map((x) => x[0]), ['market']);
      assert.match(logs[0][1], re);
    });
  }
  it('the Retry button calls retry', async () => {
    const S = load(); const host = fakeHost(); let again = 0;
    await S.shellMount(entry(), host, {}, 0, { setT: never, importFn: async () => { throw new Error('x'); }, log() {}, retry: () => { again++; } });
    find(host.kids[0], (n) => n.textContent === 'Retry')[0].onclick();
    assert.strictEqual(again, 1);
  });
  it('a cause is shown as text, never as markup (it is set through textContent)', async () => {
    const S = load(); const host = fakeHost();
    await S.shellMount(entry(), host, {}, 0, { setT: never, importFn: async () => { throw new Error('<img src=x onerror=alert(1)>'); }, log() {} });
    const errNode = find(host.kids[0], (n) => n.className === 'err')[0];
    assert.strictEqual(typeof errNode.textContent, 'string');
    assert.ok(!('innerHTML' in errNode));
  });
  it('refuses a page name or module id that is not a plain name, without importing anything', async () => {
    const S = load(); let imported = 0;
    for (const bad of [{ page: '../x.js' }, { page: 'a/b.js' }, { page: 'x.html' }, { page: undefined }, { moduleId: '../etc' }, { moduleId: 'A' }]) {
      const host = fakeHost();
      const r = await S.shellMount(entry(bad), host, {}, 0, { setT: never, importFn: async () => { imported++; return { mount() {} }; }, log() {} });
      assert.strictEqual(r.ok, false, JSON.stringify(bad));
      assert.match(texts(host.kids[0]).join(' '), /page name is not valid/);
    }
    assert.strictEqual(imported, 0);
  });
});

describe('an embedded tool', () => {
  const emb = (over = {}) => entry({ kind: 'embedded', page: undefined, url: '/app/soar/', moduleId: 'soar', moduleName: 'SOAR', label: 'Playbooks', ...over });
  it('is shown in an iframe with a sandbox, plus a link to open it in a new tab', async () => {
    const S = load(); const host = fakeHost();
    const r = await S.shellMount(emb(), host, {}, 0, { log() {} });
    assert.strictEqual(r.ok, true);
    const [frame] = find(host, (n) => n.tag === 'iframe');
    assert.strictEqual(frame.src, '/app/soar/');
    assert.strictEqual(frame.title, 'Playbooks');
    assert.match(frame.attrs.sandbox, /allow-scripts/);
    assert.ok(!/allow-top-navigation/.test(frame.attrs.sandbox), 'the tool must not be able to navigate the portal away');
    assert.ok(!('sandbox' in frame), 'set as an attribute, not as a property (a property assignment is not reliable everywhere)');
    const [link] = find(host, (n) => n.tag === 'a');
    assert.strictEqual(link.href, '/app/soar/'); assert.strictEqual(link.target, '_blank'); assert.strictEqual(link.rel, 'noopener');
  });
  it('refuses an address outside /app/<module id>/ and draws the error card instead', async () => {
    const S = load();
    for (const url of ['/app/other/', 'https://evil.example/', '/portal/x', '/app/soarx/', undefined, 42]) {
      const host = fakeHost();
      const r = await S.shellMount(emb({ url }), host, {}, 0, { log() {} });
      assert.strictEqual(r.ok, false, String(url));
      assert.strictEqual(find(host, (n) => n.tag === 'iframe').length, 0);
      assert.match(texts(host.kids[0]).join(' '), /tool address is not valid/);
    }
  });
  it('if the sandbox cannot be set, no iframe is shown at all: the error card appears instead', async () => {
    const S = load(); const host = fakeHost();
    const noAttr = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: kids.flat() });   // an element with no setAttribute
    const r = await S.shellMount(emb(), host, {}, 0, { el: noAttr, log() {} });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(find(host, (n) => n.tag === 'iframe').length, 0);
    assert.match(texts(host.kids[0]).join(' '), /This page could not be loaded/);
  });
  it('an unknown kind is an error card too', async () => {
    const S = load(); const host = fakeHost();
    const r = await S.shellMount(entry({ kind: 'react' }), host, {}, 0, { log() {} });
    assert.strictEqual(r.ok, false);
    assert.match(texts(host.kids[0]).join(' '), /unknown page kind/);
  });
});

describe('leaving a page, and a page that finishes late', () => {
  it('shellRun remembers the page; shellLeave calls its unmount once', async () => {
    const S = load(); let un = 0;
    const r = await S.shellRun(entry(), fakeHost(), {}, { setT: never, importFn: async () => ({ mount() {}, unmount() { un++; } }), log() {} });
    assert.strictEqual(r.ok, true);
    assert.ok(S.cur());
    S.shellLeave(); S.shellLeave();
    assert.strictEqual(un, 1);
    assert.strictEqual(S.cur(), null);
  });
  it('an unmount that throws does not stop leaving', async () => {
    const S = load();
    await S.shellRun(entry(), fakeHost(), {}, { setT: never, importFn: async () => ({ mount() {}, unmount() { throw new Error('cleanup failed'); } }), log() {} });
    assert.doesNotThrow(() => S.shellLeave());
    assert.strictEqual(S.cur(), null);
  });
  it('a failed page is not remembered', async () => {
    const S = load();
    await S.shellRun(entry(), fakeHost(), {}, { setT: never, importFn: async () => { throw new Error('x'); }, log() {} });
    assert.strictEqual(S.cur(), null);
  });
  it('a page that finishes after the person moved on is unmounted at once and never becomes the current page', async () => {
    const S = load(); let un = 0; let release;
    const slow = new Promise((res) => { release = res; });
    const run = S.shellRun(entry(), fakeHost(), {}, { setT: never, importFn: () => slow, log() {} });
    S.shellLeave();                                    // navigation happened while the file was still loading
    release({ mount() {}, unmount() { un++; } });
    await run;
    assert.strictEqual(un, 1);
    assert.strictEqual(S.cur(), null);
  });
  it('Retry bookkeeping: each press counts once, and the next page opening takes and resets it', () => {
    const S = load(); let redone = 0;
    assert.strictEqual(S.shellTake(), 0);
    S.shellAgain(() => { redone++; }); S.shellAgain(() => { redone++; });
    assert.strictEqual(redone, 2);
    assert.strictEqual(S.shellTake(), 2);
    assert.strictEqual(S.shellTake(), 0);
  });
});

describe('the portal is wired to the shell, and the old pages are still there', () => {
  const routeSrc = html.slice(html.indexOf('async function route() {'), html.indexOf('// ---- shared UI helpers'));
  const navSrc = html.slice(html.indexOf('function navArea(active)'), html.indexOf('async function route() {'));
  it('route() leaves the previous page first and runs a module page through shellRun with the retry hook', () => {
    assert.match(routeSrc, /^async function route\(\) \{\n  shellLeave\(\);/);
    assert.match(routeSrc, /shellRun\(dyn, host, shellCtx\(\), \{ attempt, retry: \(\) => shellAgain\(route\) \}\)/);
    assert.match(routeSrc, /shellCan\(myPerms, dyn\.permission\)/);
  });
  it('route() still falls back to the old leaves and renders old pages exactly as before', () => {
    assert.match(routeSrc, /leaves\.find\(\(l\) => l\.path === path\) \|\| leaves\[0\]/);
    assert.match(routeSrc, /const view = await leaf\.page\(\)/);
    assert.match(routeSrc, /menuModule\(leaf\.path\)/);
  });
  it('the menu builds the old arrays first, then the module pages under the menu each one asked for', () => {
    for (const [arr, area] of [['THREAT', 'Threat Management'], ['SETTINGS', 'Settings'], ['NAV', 'Main']]) {
      const at = navSrc.indexOf(arr + '.forEach'); const dyn = navSrc.indexOf(`dynRows(nav, '${area}'`);
      assert.ok(at > 0 && dyn > at, `${arr} must be drawn before its module pages`);
    }
  });
  it('the caller\'s permissions are read from /v1/auth/me, and a failed call leaves them unknown', () => {
    assert.match(html, /myPerms = Array\.isArray\(m\.permissions\) \? m\.permissions : null/);
    assert.match(html, /let myPerms = null;/);
  });
  it('the old menu arrays and their pages are untouched', () => {
    for (const s of ["{ id: 'dashboard', label: 'Dashboards & Reports'", "{ id: 'retention', label: 'Storage & retention', page: pgStorage }", "{ id: 'correlations', label: 'Correlations', page: pgCorrelations }", "{ id: 'packs', label: 'Content packs'"]) assert.ok(html.includes(s), s);
  });
  it('the page handed to a module is a small fixed set', () => {
    const m = html.match(/function shellCtx\(\) \{\n  return (\{[^\n]*\});\n\}/);
    assert.ok(m, 'shellCtx not found');
    const keys = ['api', 'el', 'tenant', 'can', 'navigate', 'toast', 'theme'];
    for (const k of keys) assert.ok(new RegExp('[{ ,]' + k + '[:,} ]').test(m[1]), 'ctx.' + k);
  });
});
