'use strict';
// The registry of the central Wazuh indexer, without a database (src/endpoints/wazuh-indexer-store.js, docs/endpoints.md task E6e): what a registration must look like, what a route
// may show, and that the password is sealed. The table itself and row security are in wazuh-indexer-db.test.js.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const fake = require('./fixtures/fake-wazuh-api');
const store = require('../src/endpoints/wazuh-indexer-store');

describe('parseRegistration', () => {
  let dir, cert;
  before(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wzixstore-')); cert = fake.makeCert(dir, { days: 2 }).cert; });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const good = () => ({ url: 'https://10.1.2.3:9200', user: 'asix-vuln-acme', password: 'Str0ng-pw!', ca_pem: cert, index: 'wazuh-states-vulnerabilities-acme-mgr', label: 'Acme' });

  it('a good registration is accepted and normalised: the origin, the exact index, only the certificate block, the fingerprint', () => {
    const r = store.parseRegistration({ ...good(), ca_pem: 'junk before\n' + cert + '\njunk after' });
    assert.ok(r.reg, r.error);
    assert.deepStrictEqual([r.reg.index_url, r.reg.index_user, r.reg.index_name, r.reg.label], ['https://10.1.2.3:9200', 'asix-vuln-acme', 'wazuh-states-vulnerabilities-acme-mgr', 'Acme']);
    assert.strictEqual(r.reg.ca_pem, cert.trim() + '\n');
    assert.strictEqual(r.reg.cert_sha256, new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, '').toLowerCase());
    assert.strictEqual(store.parseRegistration({ ...good(), label: undefined }).reg.label, null);
  });
  it('each wrong part is refused with a message that names it, and the index must be exact', () => {
    const cases = [[null, /JSON object/], [[], /JSON object/], [{ ...good(), url: 'http://10.1.2.3:9200' }, /https/], [{ ...good(), url: 'https://10.1.2.3:9200/_search' }, /just https/], [{ ...good(), url: 'https://169.254.169.254:9200' }, /not an address/],
      [{ ...good(), user: 'a' }, /user/], [{ ...good(), user: 'bad user' }, /user/], [{ ...good(), password: 'short' }, /password/], [{ ...good(), password: 'x'.repeat(129) }, /password/],
      [{ ...good(), index: undefined }, /index/], [{ ...good(), index: 'wazuh-states-vulnerabilities-*' }, /index/], [{ ...good(), index: '_all' }, /index/], [{ ...good(), index: 'wazuh-alerts-4.x-2026.10.31' }, /index/], [{ ...good(), index: 'wazuh-states-vulnerabilities-A' }, /index/],
      [{ ...good(), ca_pem: 'not a cert' }, /certificate/], [{ ...good(), ca_pem: '' }, /certificate/], [{ ...good(), ca_pem: cert + cert }, /exactly one/], [{ ...good(), label: 'x'.repeat(101) }, /label/]];
    for (const [input, re] of cases) { const r = store.parseRegistration(input); assert.match(r.error || '', re, JSON.stringify(input).slice(0, 90)); assert.strictEqual(r.reg, undefined); }
  });
  it('an expired certificate is refused (the proxy would never connect)', () => {
    const real = Date.now; Date.now = () => real() + 5 * 86400000;
    try { assert.match(store.parseRegistration(good()).error, /expired/); } finally { Date.now = real; }
  });
});

describe('view and credentials', () => {
  const KEY = crypto.randomBytes(32).toString('base64'); let saved;
  before(() => { saved = process.env.NOTIFY_ENCRYPTION_KEY; process.env.NOTIFY_ENCRYPTION_KEY = KEY; });
  after(() => { if (saved === undefined) delete process.env.NOTIFY_ENCRYPTION_KEY; else process.env.NOTIFY_ENCRYPTION_KEY = saved; });
  const box = require('../src/notifications/secret-box');
  const row = () => ({ tenant_id: 'T1', index_url: 'https://wazuh-indexer.internal:9200', index_user: 'asix-vuln-acme', secret_enc: box.encrypt({ password: 'Str0ng-pw!' }), ca_pem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n',
    cert_sha256: 'a'.repeat(64), index_name: 'wazuh-states-vulnerabilities-acme-mgr', label: 'L', updated_at: new Date('2026-11-01T00:00:00Z') });

  it('the view says where, which index and as whom, and never carries the password, the sealed password or the certificate text', () => {
    const v = store.view(row());
    assert.deepStrictEqual(v, { available: true, registered: true, label: 'L', host: 'wazuh-indexer.internal', port: 9200, index: 'wazuh-states-vulnerabilities-acme-mgr', index_user: 'asix-vuln-acme', cert_sha256: 'a'.repeat(64), updated_at: new Date('2026-11-01T00:00:00Z') });
    const text = JSON.stringify(v); for (const s of ['Str0ng', 'secret_enc', 'BEGIN CERTIFICATE', 'https://']) assert.ok(!text.includes(s), s);
    assert.deepStrictEqual(store.view(null), { available: true, registered: false }); assert.deepStrictEqual(store.view(null, false), { available: false, registered: false });
  });
  it('the sealed password opens for the proxy, and the row is sealed, not plain', () => {
    const c = store.credentials(row()); assert.strictEqual(c.index_password, 'Str0ng-pw!'); assert.deepStrictEqual([c.tenant_id, c.index_name], ['T1', 'wazuh-states-vulnerabilities-acme-mgr']); assert.ok(!row().secret_enc.includes('Str0ng'));
  });
  it('without NOTIFY_ENCRYPTION_KEY it says NO_KEY; a different key cannot open it', () => {
    const r = row(); const k = process.env.NOTIFY_ENCRYPTION_KEY;
    process.env.NOTIFY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64'); assert.throws(() => store.credentials(r));
    delete process.env.NOTIFY_ENCRYPTION_KEY; assert.throws(() => store.credentials(r), (e) => e.code === 'NO_KEY');
    process.env.NOTIFY_ENCRYPTION_KEY = k;
  });
  it('isMissingTable only matches Postgres "undefined table"', () => { assert.ok(store.isMissingTable({ code: '42P01' })); assert.ok(!store.isMissingTable({ code: '23505' })); assert.ok(!store.isMissingTable(null)); });
});
