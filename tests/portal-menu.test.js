'use strict';
// "Menu follows module state" in src/portal/index.html. The portal is one HTML file with no build step, so this
// test cuts the marked block out of it and runs it on its own (it has no DOM or api() calls), then checks the
// map against the real module manifests and the real menu paths.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '../src/portal/index.html'), 'utf8');
const m = html.match(/\/\/ BEGIN menu-state[^\n]*\n([\s\S]*?)\/\/ END menu-state/);
assert.ok(m, 'the menu-state block markers are missing from index.html');
const ctx = {};
vm.createContext(ctx);
vm.runInContext(m[1] + '\nthis.api = { MENU_MODULE, menuSet, menuModule, state: () => menuMods };', ctx);
const { MENU_MODULE, menuSet, menuModule } = ctx.api;

const mods = (states) => Object.entries(states).map(([id, state]) => ({ id, state, name: id }));

describe('menu follows module state', () => {
  it('shows everything until the module list is known (fails open)', () => {
    assert.strictEqual(menuModule('dashboard'), null);
    assert.strictEqual(menuModule('settings/retention'), null);
  });
  it('returns the module row only for a module that is not enabled', () => {
    menuSet(mods({ dashboards: 'enabled', alerts: 'locked', posture: 'planned', detections: 'enabled' }));
    assert.strictEqual(menuModule('dashboard'), null);
    assert.strictEqual(menuModule('incidents').state, 'locked');
    assert.strictEqual(menuModule('posture').state, 'planned');
    assert.strictEqual(menuModule('threat/bioc'), null);
  });
  it('leaves unmapped paths, unknown modules and an empty list alone', () => {
    menuSet(mods({ alerts: 'locked' }));
    assert.strictEqual(menuModule('modules'), null);          // the Modules page is never greyed out
    assert.strictEqual(menuModule('settings'), null);
    assert.strictEqual(menuModule('not/a/path'), null);
    assert.strictEqual(menuModule('dashboard'), null);        // module missing from the list
    menuSet([]); assert.strictEqual(menuModule('incidents'), null);
    menuSet(undefined); assert.strictEqual(menuModule('incidents'), null);
  });
  it('one locked module greys all of its menu entries', () => {
    menuSet(mods({ ingestion: 'locked' }));
    for (const p of ['settings/sources', 'settings/collectors', 'settings/installers', 'settings/parsing', 'settings/datamodel']) assert.ok(menuModule(p), p);
    assert.strictEqual(menuModule('settings/retention'), null);
  });
  it('every mapped module id is a real manifest', () => {
    const ids = new Set(require('../src/modules/registry').loadDir().map((x) => x.id));
    for (const [p, id] of Object.entries(MENU_MODULE)) assert.ok(ids.has(id), `${p} -> unknown module "${id}"`);
  });
  it('every mapped path is a real menu entry, and the core pages are always mapped to core', () => {
    const grab = (name) => { const mm = html.match(new RegExp('const ' + name + ' = \\[([\\s\\S]*?)\\n\\];')); assert.ok(mm, name); return [...mm[1].matchAll(/\{ id: '([a-z]+)'[^}]*?(page:|home:|soon:)/g)].map((x) => x[1]); };
    const real = new Set([...grab('NAV'), ...grab('SETTINGS').map((i) => 'settings/' + i), ...grab('THREAT').map((i) => 'threat/' + i)]);
    for (const p of Object.keys(MENU_MODULE)) assert.ok(real.has(p), `"${p}" is not a menu path`);
    assert.ok(!('modules' in MENU_MODULE));
  });
});
