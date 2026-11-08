'use strict';
// S1 of docs/product-plan.md ("Status of Phase 5"): the optional `ui` block in a module manifest (docs/portal-shell.md).
// Every rule has a deliberate break that must fail with a message naming the problem, and the real manifests must still load.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const registry = require('../src/modules/registry');
const modulesIndex = require('../src/modules');
const profiles = require('../src/modules/profiles');

let tmp; let manifests; let portal;
before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-ui-'));
  manifests = path.join(tmp, 'manifests'); portal = path.join(tmp, 'portal-modules');
  fs.mkdirSync(manifests); fs.mkdirSync(path.join(portal, 'market'), { recursive: true });
  fs.writeFileSync(path.join(portal, 'market', 'marketplace.js'), 'export async function mount() {}\n');
});
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

// Writes one manifest file per module into a fresh folder and loads it the way the gateway does.
let n = 0;
function load(mods, opts = {}) {
  const dir = path.join(manifests, 'case' + (++n)); fs.mkdirSync(dir);
  for (const m of mods) {
    const full = { name: m.id, tier: 'home', entitlement: null, status: 'available', requires: [], permissions: [], ...m };
    fs.writeFileSync(path.join(dir, full.id + '.js'), 'module.exports = ' + JSON.stringify(full) + ';\n');
  }
  return registry.loadDir(dir, { portalDir: portal, ...opts });
}
const native = (over = {}) => ({ id: 'market', permissions: ['packs:read'], ui: { kind: 'native', entries: [{ id: 'browse', label: 'Marketplace', area: 'Configuration', page: 'marketplace.js', ...over }] } });
const embedded = (over = {}, mod = {}) => ({ id: 'soar-tool', proxy: { env: 'ASIX_SOAR_URL' }, ui: { kind: 'embedded', entries: [{ id: 'main', label: 'Playbooks', area: 'Investigation', url: '/app/soar-tool/', ...over }] }, ...mod });
const builtin = (id, p) => ({ id, ui: { kind: 'builtin', entries: [{ id: 'main', label: id, area: 'Settings', path: p }] } });
const fails = (mods, re, opts) => assert.throws(() => load(mods, opts), (e) => e instanceof registry.ManifestError && re.test(e.message), 'expected a ManifestError matching ' + re);

describe('manifest ui block: accepted', () => {
  it('a module without a ui block is unchanged', () => {
    const [m] = load([{ id: 'plain' }]);
    assert.strictEqual(m.ui, undefined);
  });
  it('a native entry gets defaults and a computed menu path', () => {
    const [m] = load([native({ permission: 'packs:read', group: 'Content' })]);
    assert.deepStrictEqual({ ...m.ui.entries[0] }, { id: 'browse', label: 'Marketplace', area: 'Configuration', group: 'Content', permission: 'packs:read', order: 100, path: 'mod/market/browse', page: 'marketplace.js' });
    assert.strictEqual(m.ui.kind, 'native');
  });
  it('permission and group are optional', () => {
    const [m] = load([native()]);
    assert.strictEqual(m.ui.entries[0].permission, null);
    assert.strictEqual(m.ui.entries[0].group, null);
  });
  it('an embedded entry with a proxy loads', () => {
    const [m] = load([embedded()]);
    assert.strictEqual(m.ui.entries[0].url, '/app/soar-tool/');
    assert.strictEqual(m.ui.entries[0].path, 'mod/soar-tool/main');
  });
  it('a builtin entry keeps the existing menu path', () => {
    const [m] = load([builtin('retention-x', 'settings/retention')]);
    assert.strictEqual(m.ui.entries[0].path, 'settings/retention');
  });
  it('the real manifests still load (no portal pages are declared yet)', () => {
    const list = registry.loadDir();
    assert.ok(list.length >= 10);
    assert.ok(list.every((m) => !m.ui || registry.UI_KINDS.includes(m.ui.kind)));
  });
});

describe('manifest ui block: rejected', () => {
  it('ui that is not an object', () => fails([{ id: 'abc', ui: 'yes' }], /ui must be an object/));
  it('an unknown kind', () => fails([{ id: 'abc', ui: { kind: 'react', entries: [{}] } }], /ui\.kind must be one of/));
  it('no entries', () => fails([{ id: 'abc', ui: { kind: 'native', entries: [] } }], /non-empty array/));
  it('an entry that is not an object', () => fails([{ id: 'abc', ui: { kind: 'native', entries: ['x'] } }], /entries\[0\] must be an object/));
  it('a bad entry id', () => fails([native({ id: 'Bad Id' })], /\.id must be lowercase/));
  it('the same entry id twice in one module', () => {
    const m = native(); m.ui.entries.push({ ...m.ui.entries[0] });
    fails([m], /used twice in this module/);
  });
  it('a missing label', () => fails([native({ label: '' })], /label is required/));
  it('a missing area', () => fails([native({ area: undefined })], /area is required/));
  it('an order that is not a whole number in range', () => { fails([native({ order: 1.5 })], /order must be/); fails([native({ order: -1 })], /order must be/); fails([native({ order: 10000 })], /order must be/); });
  it('a permission the module does not own', () => fails([native({ permission: 'other:read' })], /one of this module's own permissions/));
  it('a native entry without a page', () => fails([native({ page: undefined })], /\.page must be a file name/));
  it('a native page with a folder in it', () => { for (const bad of ['../x.js', 'a/b.js', '/etc/x.js', 'x.html', '..js']) fails([native({ page: bad })], /\.page must be a file name/); });
  it('a native page whose file does not exist', () => fails([native({ page: 'missing.js' })], /does not exist/));
  it('a native entry that also has a url', () => fails([native({ url: '/app/market/' })], /takes "page" only/));
  it('an embedded entry with a url outside /app/<id>/', () => { for (const bad of ['/app/other/', '/portal/x', 'https://evil.example/', '/app/soar-tool/../x', '/app/soar-tool/?a=1', '/app/soar-tool/ x']) fails([embedded({ url: bad })], /url must start with \/app\/soar-tool\//); });
  it('an embedded module without a proxy', () => { const m = embedded(); delete m.proxy; fails([m], /must declare proxy/); });
  it('an embedded proxy with a bad variable name', () => fails([embedded({}, { proxy: { env: 'soar_url' } })], /must declare proxy/));
  it('an embedded entry that also has a page', () => fails([embedded({ page: 'x.js' })], /takes "url" only/));
  it('a proxy on a module that is not embedded', () => fails([native(), ].map((m) => ({ ...m, proxy: { env: 'ASIX_X_URL' } })), /proxy is only for/));
  it('a builtin entry without a path, or with a bad one', () => { fails([builtin('a1', undefined)], /\.path must be the menu path/); fails([builtin('a2', '../x')], /\.path must be the menu path/); });
  it('two modules claiming the same builtin menu path', () => fails([builtin('first', 'settings/retention'), builtin('second', 'settings/retention')], /already used by module/));
});

describe('GET /v1/modules data: resolve() passes the entries on', () => {
  const lic = { features: ['soar'] };
  it('carries ui through and never the proxy address', () => {
    const list = load([native(), embedded()]);
    const rows = modulesIndex.resolve(list, profiles.get('enterprise'), lic);
    const byId = Object.fromEntries(rows.map((r) => [r.id, r]));
    assert.strictEqual(byId.market.ui.entries[0].page, 'marketplace.js');
    assert.strictEqual(byId['soar-tool'].ui.entries[0].url, '/app/soar-tool/');
    assert.ok(!JSON.stringify(rows).includes('ASIX_SOAR_URL'), 'the proxy variable name must not reach the browser');
    assert.ok(!('proxy' in byId['soar-tool']));
  });
  it('is null for a module without a ui block', () => {
    const rows = modulesIndex.resolve(load([{ id: 'plain' }]), profiles.get('home'), lic);
    assert.strictEqual(rows[0].ui, null);
  });
});
