'use strict';
// SR1: the checks of integrations that need no database (src/integrations/*, src/secrets/provider.js).
process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const { describe, it } = require('node:test');
const assert = require('assert');
const catalog = require('../src/integrations/catalog');
const model = require('../src/integrations/model');
const secrets = require('../src/secrets/provider');

const OPN = catalog.get('opnsense'); const FEED = catalog.get('threat-feed'); const VT = catalog.get('virustotal');

describe('the definitions that ship', () => {
  it('are valid, sorted, frozen and described', () => {
    const all = catalog.list();
    assert.deepStrictEqual(all.map((d) => d.id).sort(), ['fortigate', 'opnsense', 'pfsense', 'threat-feed', 'virustotal']);
    for (const d of all) { assert.deepStrictEqual(catalog.checkDefinition(d), [], d.id); assert.ok(Object.isFrozen(d)); assert.ok(d.description.length > 20); assert.ok(d.credentials.length >= 1); }
  });
  it('a firewall needs an address and a secret; a feed needs an address and a format and its token is optional', () => {
    assert.deepStrictEqual(OPN.config.map((f) => [f.name, f.type, f.required]), [['base_url', 'url', true]]);
    assert.deepStrictEqual(OPN.credentials.map((f) => [f.name, !!f.required]), [['api_key', true], ['api_secret', true]]);
    assert.deepStrictEqual(FEED.credentials.map((f) => [f.name, !!f.required]), [['token', false]]);
  });
  it('the check refuses a bad definition', () => {
    const ok = { id: 'x-y', name: 'X', publisher: 'P', description: 'd', category: 'other', kind: 'builtin', config: [], credentials: [{ name: 'k', label: 'K' }] };
    assert.deepStrictEqual(catalog.checkDefinition(ok), []);
    for (const bad of [null, { ...ok, id: 'X' }, { ...ok, category: 'nope' }, { ...ok, kind: 'pack' }, { ...ok, name: '' }, { ...ok, config: [{ name: 'k', label: 'dup', type: 'string' }] },
      { ...ok, config: [{ name: 'a', label: 'A', type: 'enum' }] }, { ...ok, config: [{ name: 'a', label: 'A', type: 'boolean', required: true }] }, { ...ok, config: [{ name: 'A!', label: 'A', type: 'string' }] },
      { ...ok, credentials: [{ name: 'k', label: 'K', type: 'string' }] }, { ...ok, credentials: [{ name: 'k', label: 'K', max: 99999 }] }]) assert.ok(catalog.checkDefinition(bad).length, JSON.stringify(bad));
    assert.throws(() => catalog.register(ok.id === 'x-y' ? { ...ok, id: 'opnsense' } : ok), /already registered/);
  });
});

describe('settings', () => {
  it('create needs every required setting and writes an address in one form', () => {
    assert.deepStrictEqual(model.parseCreate(OPN, { name: ' Edge ', config: { base_url: 'HTTPS://fw.example.com:8443/' } }).value, { name: 'Edge', config: { base_url: 'https://fw.example.com:8443' } });
    for (const b of [{ name: 'x' }, { name: 'x', config: {} }, { name: '', config: { base_url: 'https://a.b' } }, { name: 'x', config: { base_url: 'ftp://a.b' } }, { name: 'x', config: { base_url: 'https://u:p@a.b' } },
      { name: 'x', config: { base_url: 'https://a.b', extra: 'y' } }, { name: 'x', config: { base_url: 'https://a b' } }, { name: 'x', config: { base_url: 'https://a.b' }, junk: 1 }, null, []]) assert.ok(model.parseCreate(OPN, b).error, JSON.stringify(b));
  });
  it('a choice must be one of its values; a definition with no settings takes none', () => {
    assert.ok(!model.parseCreate(FEED, { name: 'f', config: { feed_url: 'https://f.example/list.txt', format: 'csv' } }).error);
    assert.ok(model.parseCreate(FEED, { name: 'f', config: { feed_url: 'https://f.example/list.txt', format: 'xml' } }).error);
    assert.deepStrictEqual(model.parseCreate(VT, { name: 'vt' }).value, { name: 'vt', config: {} });
    assert.ok(model.parseCreate(VT, { name: 'vt', config: { a: 'b' } }).error);
  });
  it('a change touches only what is sent; null removes an optional setting but never a required one', () => {
    assert.deepStrictEqual(model.parsePatch(OPN, { config: { base_url: 'https://new.example' }, enabled: false, name: 'N' }).value, { config: { base_url: 'https://new.example' }, enabled: false, name: 'N' });
    assert.ok(model.parsePatch(OPN, { config: { base_url: null } }).error);
    for (const b of [{}, { definition_id: 'x' }, { enabled: 'yes' }, { name: '' }, { config: { base_url: 'nope' } }]) assert.ok(model.parsePatch(OPN, b).error, JSON.stringify(b));
  });
});

describe('credentials', () => {
  it('set and clear by name, trimmed', () => {
    assert.deepStrictEqual(model.parseCredentials(OPN, { values: { api_key: '  k1  ' }, clear: ['api_secret'] }).value, { values: { api_key: 'k1' }, clear: ['api_secret'] });
  });
  it('refuses unknown names, empty or multi-line values, both set and clear, and nothing at all', () => {
    for (const b of [{}, { values: {} }, { values: { nope: 'x' } }, { values: { api_key: '' } }, { values: { api_key: 'a\nb' } }, { values: { api_key: 5 } }, { values: { api_key: 'x'.repeat(5000) } },
      { values: { api_key: 'x' }, clear: ['api_key'] }, { clear: ['nope'] }, { clear: 'api_key' }, { values: { api_key: 'x' }, extra: 1 }, null]) assert.ok(model.parseCredentials(OPN, b).error, JSON.stringify(b));
  });
  it('an error never contains the value that was sent', () => {
    for (const b of [{ values: { api_key: 'SECRET-VALUE\nline2' } }, { values: { nope: 'SECRET-VALUE' } }, { values: { api_key: 'SECRET-VALUE'.repeat(500) } }]) {
      const r = model.parseCredentials(OPN, b); assert.ok(r.error); assert.ok(!JSON.stringify(r).includes('SECRET-VALUE'));
    }
  });
});

describe('status', () => {
  const row = (over) => ({ enabled: true, credential_fields: [], ...over });
  it('Not configured until every required credential is set', () => {
    assert.strictEqual(model.statusOf(OPN, row()), 'not_configured');
    assert.strictEqual(model.statusOf(OPN, row({ credential_fields: ['api_key'] })), 'not_configured');
    assert.strictEqual(model.statusOf(OPN, row({ credential_fields: ['api_key', 'api_secret'] })), 'configured');
    assert.strictEqual(model.statusOf(FEED, row()), 'configured', 'an optional token is not needed');
  });
  it('disabled wins; a definition that is gone is never configured', () => {
    assert.strictEqual(model.statusOf(OPN, row({ enabled: false, credential_fields: ['api_key', 'api_secret'] })), 'disabled');
    assert.strictEqual(model.statusOf(null, row({ credential_fields: ['x'] })), 'not_configured');
  });
});

describe('the secrets provider', () => {
  it('seals and opens, differently every time, and a tampered value fails', () => {
    assert.ok(secrets.configured()); assert.strictEqual(secrets.providerName, 'local');
    const a = secrets.seal({ api_key: 'abc' }); const b = secrets.seal({ api_key: 'abc' });
    assert.notStrictEqual(a, b); assert.ok(!a.includes('abc'));
    assert.deepStrictEqual(secrets.open(a), { api_key: 'abc' });
    const parts = a.split('.'); parts[3] = parts[3].slice(0, -2) + (parts[3].endsWith('AA') ? 'BB' : 'AA');
    assert.throws(() => secrets.open(parts.join('.')));
    assert.throws(() => secrets.open('garbage'));
  });
  it('reports not configured without the key, instead of throwing at start', () => {
    const k = process.env.NOTIFY_ENCRYPTION_KEY; delete process.env.NOTIFY_ENCRYPTION_KEY;
    assert.strictEqual(secrets.configured(), false); assert.throws(() => secrets.seal({ a: 1 }), /NOTIFY_ENCRYPTION_KEY/);
    process.env.NOTIFY_ENCRYPTION_KEY = k;
  });
});
