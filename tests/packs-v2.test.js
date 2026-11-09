'use strict';
// MK1 of docs/product-plan.md ("Status of Phase 5"): content pack manifest v2.
// Every rule has a deliberate break that must fail with a message naming the problem; the three shipped packs must keep working.
const { describe, it } = require('node:test');
const assert = require('assert');
const packs = require('../src/packs');
const registry = require('../src/modules/registry');

const clone = (o) => JSON.parse(JSON.stringify(o));
const base = () => clone(require('../src/packs/catalog/home-router'));
const ok = (over = {}, id = 'home-router') => packs.validatePack({ ...base(), ...over }, id);
const fails = (over, re, id = 'home-router') => assert.throws(() => packs.validatePack({ ...base(), ...over }, id), (e) => re.test(e.message), 'expected an error matching ' + re);

describe('the shipped packs keep working', () => {
  const list = packs.load(undefined, { strict: true });
  it('all three load in strict mode with the v2 defaults', () => {
    assert.deepStrictEqual(list.map((p) => p.id), ['home-linux', 'home-macos', 'home-router']);
    for (const p of list) {
      assert.deepStrictEqual(p.publisher, { name: 'ASIX', url: null });
      assert.strictEqual(p.certification, 'certified'); assert.strictEqual(p.supported_by, 'asix');
      assert.strictEqual(p.deprecated, false); assert.strictEqual(p.core, false);
      assert.deepStrictEqual(p.requires, { modules: [], packs: [] });
      assert.strictEqual(p.contents.rules, p.rules.length);
      assert.strictEqual(p.history[0].version, p.version);
      assert.ok(p.tags.length > 0);
    }
  });
  it('a pack written the old way (no v2 field at all) still validates', () => {
    const old = clone(base()); for (const k of ['tags', 'history']) delete old[k];
    const p = packs.validatePack(old, 'home-router');
    assert.deepStrictEqual(p.history, []); assert.deepStrictEqual(p.tags, []); assert.strictEqual(p.released, null);
  });
  it('the catalog as a whole has no problems, checked against the real module ids', () => {
    assert.deepStrictEqual(packs.checkCatalog(list, registry.loadDir().map((m) => m.id)), []);
  });
  it('the old rule checks still apply', () => {
    const p = base(); p.rules[0].severity = 'huge';
    assert.throws(() => packs.validatePack(p, 'home-router'), /severity must be one of/);
  });
});

describe('v2 fields: accepted', () => {
  it('a full manifest', () => {
    const p = ok({
      publisher: { name: 'Example Labs', url: 'https://example.com/packs' }, certification: 'community', supported_by: 'none', core: true,
      tags: ['router', 'wifi'], license: 'MIT', requires: { modules: ['detections'], packs: ['home-linux'] },
      history: [{ version: '1.1.0', released: '2026-11-08', notes: 'More rules.' }, { version: '1.0.0', notes: 'First release.' }], version: '1.1.0',
    });
    assert.deepStrictEqual(p.publisher, { name: 'Example Labs', url: 'https://example.com/packs' });
    assert.strictEqual(p.certification, 'community'); assert.strictEqual(p.supported_by, 'none'); assert.strictEqual(p.core, true);
    assert.deepStrictEqual(p.requires, { modules: ['detections'], packs: ['home-linux'] });
    assert.strictEqual(p.released, '2026-11-08'); assert.strictEqual(p.history[1].released, null);
  });
  it('community packs are supported by the community unless they say otherwise', () => {
    assert.strictEqual(ok({ certification: 'community' }).supported_by, 'community');
  });
  it('a deprecated pack with a reason and a replacement', () => {
    const p = ok({ deprecated: true, deprecation: 'Replaced by a wider pack.', replaced_by: 'home-linux' });
    assert.strictEqual(p.deprecated, true); assert.strictEqual(p.replaced_by, 'home-linux');
  });
});

describe('v2 fields: rejected', () => {
  it('a field nobody knows (a typo must not pass silently)', () => fails({ tag: ['x'] }, /unknown field "tag"/));
  for (const [kind, task] of [['parsers', 'no task for it yet'], ['dashboards', 'no task for it yet'], ['playbooks', 'task SR3'], ['actions', 'task SR2'], ['integrations', 'task SR1']]) {
    it(`content of kind "${kind}" is refused for now and names ${task}`, () => fails({ [kind]: [{}] }, new RegExp(`"${kind}" cannot be in a pack yet.*${task}`)));
  }
  it('a bad publisher', () => { for (const v of ['ASIX', [], { name: '' }, { name: 'x'.repeat(61) }, { name: 'ok', url: 'http://plain.example' }, { name: 'ok', url: 'javascript:alert(1)' }, { name: 'ok', url: 'https://has space' }]) fails({ publisher: v }, /publisher/); });
  it('an unknown certification or support', () => { fails({ certification: 'gold' }, /certification must be one of/); fails({ supported_by: 'vendor' }, /supported_by must be one of/); });
  it('core and deprecated must be true or false', () => { fails({ core: 'yes' }, /core must be true or false/); fails({ deprecated: 1 }, /deprecated must be true or false/); });
  it('deprecated needs a reason; a reason or replacement without deprecated is refused', () => {
    fails({ deprecated: true }, /deprecation .* must be text/);
    fails({ deprecated: true, deprecation: '' }, /deprecation .* must be text/);
    fails({ deprecation: 'old' }, /only go with deprecated: true/);
    fails({ replaced_by: 'home-linux' }, /only go with deprecated: true/);
    fails({ deprecated: true, deprecation: 'old', replaced_by: 'home-router' }, /replaced_by must be the id of another pack/);
    fails({ deprecated: true, deprecation: 'old', replaced_by: 'Not An Id' }, /replaced_by/);
  });
  it('bad, duplicate or too many tags', () => {
    fails({ tags: ['Linux'] }, /tags must be a list/); fails({ tags: 'linux' }, /tags must be a list/);
    fails({ tags: ['a', 'a'] }, /tags has a duplicate/); fails({ tags: Array.from({ length: 11 }, (_, i) => 't' + i) }, /at most 10/);
  });
  it('requires: wrong shape, unknown key, bad ids, itself, duplicates', () => {
    fails({ requires: ['detections'] }, /requires must be/); fails({ requires: { services: [] } }, /requires must be/);
    fails({ requires: { modules: ['Bad Id'] } }, /requires\.modules must be a list/); fails({ requires: { packs: ['Bad Id'] } }, /requires\.packs must be a list/);
    fails({ requires: { packs: ['home-router'] } }, /cannot require itself/); fails({ requires: { modules: ['detections', 'detections'] } }, /requires\.modules has a duplicate/);
  });
  it('a bad license', () => fails({ license: '' }, /license must be text/));
  it('history: must start with the current version, newest first, each once, with real dates and notes', () => {
    fails({ history: [{ version: '0.9.0', notes: 'old' }] }, /history must start with the current version 1\.0\.0/);
    fails({ version: '1.1.0', history: [{ version: '1.1.0', notes: 'a' }, { version: '1.2.0', notes: 'b' }] }, /newest first/);
    fails({ history: [{ version: '1.0.0', notes: 'a' }, { version: '1.0.0', notes: 'b' }] }, /newest first, each once/);
    fails({ history: [{ version: '1.0.0', notes: 'a', released: '2026-02-30' }] }, /released must be a real date/);
    fails({ history: [{ version: '1.0.0', notes: 'a', released: 'yesterday' }] }, /released must be a real date/);
    fails({ history: [{ version: '1.0', notes: 'a' }] }, /version must look like 1\.0\.0/);
    fails({ history: [{ version: '1.0.0' }] }, /notes must be text/);
    fails({ history: 'x' }, /history must be a list/);
    fails({ history: Array.from({ length: 51 }, (_, i) => ({ version: `1.0.${51 - i}`, notes: 'n' })), version: '1.0.51' }, /at most 50/);
  });
});

describe('what the API shows (describe) and the state of a pack', () => {
  const [linux, macos, router] = packs.load(undefined, { strict: true });
  it('stateOf: available, partial, installed', () => {
    assert.strictEqual(packs.stateOf(router, {}), 'available');
    assert.strictEqual(packs.stateOf(router, { 'home-router': { installed: 2 } }), 'partial');
    assert.strictEqual(packs.stateOf(router, { 'home-router': { installed: router.rules.length } }), 'installed');
    assert.strictEqual(packs.stateOf(router, undefined), 'available');
  });
  it('describe carries every v2 field and the installed counts', () => {
    const d = packs.describe(router, { 'home-router': { installed: 3, enabled: 2, open_alerts: 1 } });
    for (const k of ['publisher', 'certification', 'supported_by', 'core', 'deprecated', 'deprecation', 'replaced_by', 'tags', 'license', 'requires', 'history', 'released', 'contents']) assert.ok(k in d, k);
    assert.strictEqual(d.state, 'partial'); assert.strictEqual(d.installed_rules, 3); assert.strictEqual(d.enabled_rules, 2); assert.strictEqual(d.open_alerts, 1);
    assert.strictEqual(d.rule_count, router.rules.length);
  });
  it('describe never sends rule definitions or internal keys to the browser', () => {
    const json = JSON.stringify(packs.describe(linux, {}));
    assert.ok(!/"definition"|"builtin_key"|"regex"/.test(json));
    assert.ok(packs.describe(macos, {}).rules.every((r) => Object.keys(r).sort().join() === 'category,description,key,kind,mitre,name,severity'));
  });
});

describe('install and removal checks', () => {
  const mk = (id, over = {}) => ({ ...clone(base()), ...over, id });
  const A = packs.validatePack(mk('home-router'), 'home-router');
  const B = packs.validatePack(mk('base-pack'), 'base-pack');
  const C = packs.validatePack(mk('needs-base', { requires: { modules: ['detections'], packs: ['base-pack'] } }), 'needs-base');
  const D = packs.validatePack(mk('old-pack', { deprecated: true, deprecation: 'Retired.', replaced_by: 'base-pack' }), 'old-pack');
  const all = [A, B, C, D];
  const full = (p) => ({ installed: p.rules.length, enabled: p.rules.length, open_alerts: 0 });

  it('a plain pack installs', () => assert.strictEqual(packs.installBlockers(A, { st: {}, allPacks: all, enabledModules: new Set() }), null));
  it('a deprecated pack is refused and names the replacement; allow_deprecated lets it through', () => {
    const r = packs.installBlockers(D, { st: {}, allPacks: all, enabledModules: new Set() });
    assert.strictEqual(r.status, 409); assert.strictEqual(r.code, 'PACK_DEPRECATED'); assert.match(r.message, /Retired\./); assert.match(r.message, /Use "Home router and firewall" instead/);
    assert.strictEqual(packs.installBlockers(D, { st: {}, allPacks: all, enabledModules: new Set(), allowDeprecated: true }), null);
  });
  it('a module that is off blocks the install and is named', () => {
    const r = packs.installBlockers(C, { st: { 'base-pack': full(B) }, allPacks: all, enabledModules: new Set() });
    assert.strictEqual(r.code, 'MODULE_REQUIRED'); assert.match(r.message, /detections/);
  });
  it('a pack that is missing or only partly installed blocks the install and is named', () => {
    const on = new Set(['detections']);
    for (const st of [{}, { 'base-pack': { installed: 1, enabled: 1, open_alerts: 0 } }]) {
      const r = packs.installBlockers(C, { st, allPacks: all, enabledModules: on });
      assert.strictEqual(r.code, 'PACK_REQUIRED'); assert.match(r.message, /Home router and firewall|base-pack/);
    }
    assert.strictEqual(packs.installBlockers(C, { st: { 'base-pack': full(B) }, allPacks: all, enabledModules: on }), null);
  });
  it('a required pack that is not in the catalog at all blocks the install', () => {
    const r = packs.installBlockers(C, { st: { 'base-pack': full(B) }, allPacks: [A, C], enabledModules: new Set(['detections']) });
    assert.strictEqual(r.code, 'PACK_REQUIRED'); assert.match(r.message, /base-pack/);
  });
  it('removal is refused while an installed pack depends on it, and allowed once that one is gone', () => {
    const st = { 'base-pack': full(B), 'needs-base': full(C) };
    const r = packs.removeBlockers('base-pack', all, st);
    assert.strictEqual(r.status, 409); assert.strictEqual(r.code, 'REQUIRED_BY'); assert.match(r.message, /Home router and firewall|needs-base|Remove them first/);
    assert.strictEqual(packs.removeBlockers('base-pack', all, { 'base-pack': full(B) }), null);
    assert.strictEqual(packs.removeBlockers('base-pack', all, { 'base-pack': full(B), 'needs-base': { installed: 0 } }), null);
    assert.strictEqual(packs.removeBlockers('needs-base', all, st), null);
  });
});

describe('catalog-wide checks', () => {
  const mk = (id, req = {}, over = {}) => packs.validatePack({ ...clone(base()), id, requires: req, ...over }, id);
  it('unknown module, unknown pack and unknown replacement are reported', () => {
    const l = [mk('aaa', { modules: ['nope'], packs: ['ghost'] }), mk('bbb', {}, { deprecated: true, deprecation: 'x', replaced_by: 'phantom' })];
    const out = packs.checkCatalog(l, ['detections']);
    assert.ok(out.includes('aaa: requires unknown module "nope"')); assert.ok(out.includes('aaa: requires unknown pack "ghost"')); assert.ok(out.includes('bbb: replaced_by names unknown pack "phantom"'));
  });
  it('a loop between packs is reported once, naming the path', () => {
    const out = packs.checkCatalog([mk('aaa', { packs: ['bbb'] }), mk('bbb', { packs: ['ccc'] }), mk('ccc', { packs: ['aaa'] })], []);
    assert.strictEqual(out.length, 1); assert.match(out[0], /dependency loop: aaa -> bbb -> ccc -> aaa/);
  });
  it('a pack that requires a deprecated pack is reported', () => {
    const out = packs.checkCatalog([mk('aaa', { packs: ['old'] }), mk('old', {}, { deprecated: true, deprecation: 'x' })], []);
    assert.deepStrictEqual(out, ['aaa: requires deprecated pack "old"']);
  });
  it('a clean catalog has no problems, and a chain without a loop is fine', () => {
    assert.deepStrictEqual(packs.checkCatalog([mk('aaa', { packs: ['bbb'] }), mk('bbb', { packs: ['ccc'] }), mk('ccc')], []), []);
  });
});
