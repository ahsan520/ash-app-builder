'use strict';
// SR1 against a real PostgreSQL (platform schema applied): the real routes, SQL, secrets provider and audit table. Only the sign-in chain is replaced
// (as in tests/lists-db.test.js).   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/integrations-db.test.js
// The point of this file is that a credential, once typed, is found NOWHERE it should not be: not in a response, not in a table in plain text, not in the audit
// trail, not in a log line, not in an error.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_PROFILE = process.env.ASIX_PROFILE || 'home';
const KEY_A = Buffer.alloc(32, 11).toString('base64'); const KEY_B = Buffer.alloc(32, 22).toString('base64');
process.env.NOTIFY_ENCRYPTION_KEY = KEY_A;

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT; let USER; const asked = [];
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared,
  guarded: (permission) => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = USER; asked.push([req.method, req.route ? req.route.path : req.path, permission]); next(); }],
};
const modules = require('../src/modules');
const secrets = require('../src/secrets/provider');
const service = require('../src/integrations/service');

const SECRETS = ['k-9f3a-OPN-KEY', 's-7b21-OPN-SECRET', 'k-NEW-6c0d-ROTATED', 'tok-4d88-FEED-TOKEN'];
const logs = []; const realErr = console.error; const realLog = console.log;
console.error = (...a) => { logs.push(a.join(' ')); realErr(...a); };

async function main() {
  const stamp = Date.now();
  const q = (t, p) => db.query(t, p);
  const mkTenant = async (n) => (await q('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['integ-' + n + '-' + stamp])).rows[0].id;
  const mkUser = async (t, n) => (await q('INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id', [t, `${n}-${stamp}`, `${n}-${stamp}@example.test`])).rows[0].id;
  const A = await mkTenant('a'); const B = await mkTenant('b'); const alice = await mkUser(A, 'alice'); const eve = await mkUser(B, 'eve');
  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/integrations'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const seen = [];   // every byte the server ever sent back
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text(); seen.push(text); let json = null; try { json = JSON.parse(text); } catch { /* */ }
    return { status: r.status, json, text };
  };
  const code = (r) => r.json && r.json.error && r.json.error.code;
  const as = (t, u) => { TENANT = t; USER = u; };
  const rows = async (sql, p) => (await q(sql, p)).rows;
  const creds = (id, body) => call('PUT', `/v1/integrations/${id}/credentials`, body);
  const row = async (id) => (await rows('SELECT * FROM integration_instances WHERE id = $1', [id]))[0];
  const auditRows = async (t) => (await rows('SELECT action, resource FROM audit_events WHERE tenant_id = $1 AND action LIKE $2 ORDER BY created_at, action', [t, 'soar:integration:%']));
  as(A, alice);

  try {
    // 1. definitions and the empty list
    let r = await call('GET', '/v1/integrations/definitions');
    assert.deepStrictEqual([r.status, r.json.definitions.map((d) => d.id).sort(), r.json.secrets_configured], [200, ['fortigate', 'opnsense', 'pfsense', 'threat-feed', 'virustotal'], true]);
    assert.ok(r.json.categories.includes('firewall'));
    assert.deepStrictEqual(r.json.definitions.find((d) => d.id === 'opnsense').credentials.map((c) => c.name), ['api_key', 'api_secret']);
    r = await call('GET', '/v1/integrations'); assert.deepStrictEqual([r.status, r.json.integrations], [200, []]);

    // 2. making one: Not configured, the unique name, other tenants, bad bodies
    r = await call('POST', '/v1/integrations', { definition_id: 'opnsense', name: 'Edge firewall', config: { base_url: 'https://fw.example.com/' } });
    assert.strictEqual(r.status, 201);
    const fw = r.json.integration;
    assert.deepStrictEqual([fw.status, fw.config, fw.enabled, fw.definition_name, fw.category, fw.known_definition], ['not_configured', { base_url: 'https://fw.example.com' }, true, 'OPNsense', 'firewall', true]);
    assert.deepStrictEqual(fw.credentials, [{ name: 'api_key', label: 'API key', required: true, set: false }, { name: 'api_secret', label: 'API secret', required: true, set: false }]);
    assert.ok(!('credential_enc' in fw));
    r = await call('POST', '/v1/integrations', { definition_id: 'opnsense', name: 'edge FIREWALL', config: { base_url: 'https://x.example' } }); assert.deepStrictEqual([r.status, code(r)], [409, 'NAME_TAKEN']);
    r = await call('POST', '/v1/integrations', { definition_id: 'nope', name: 'x' }); assert.deepStrictEqual([r.status, code(r)], [400, 'UNKNOWN_DEFINITION']);
    r = await call('POST', '/v1/integrations', { definition_id: 'opnsense', name: 'x' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']);
    as(B, eve); r = await call('POST', '/v1/integrations', { definition_id: 'opnsense', name: 'Edge firewall', config: { base_url: 'https://b.example' } }); assert.strictEqual(r.status, 201); const bFw = r.json.integration; as(A, alice);
    r = await call('GET', '/v1/integrations/' + bFw.id); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND'], 'another tenant\'s integration is not found');
    r = await creds(bFw.id, { values: { api_key: SECRETS[0] } }); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    r = await call('GET', '/v1/integrations/nope'); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_ID']);

    // 3. credentials go in and never come out; the status follows
    r = await creds(fw.id, { values: { api_key: SECRETS[0] } });
    assert.deepStrictEqual([r.status, r.json.integration.status, r.json.integration.credentials.map((c) => c.set)], [200, 'not_configured', [true, false]]);
    r = await creds(fw.id, { values: { api_secret: SECRETS[1] } });
    assert.deepStrictEqual([r.json.integration.status, r.json.integration.credentials.map((c) => c.set)], ['configured', [true, true]]);
    assert.ok(r.json.integration.credential_set_at); assert.strictEqual(r.json.integration.credential_set_by_name, 'alice-' + stamp);
    let rec = await row(fw.id);
    assert.ok(rec.credential_enc && rec.credential_enc.startsWith('v1.')); assert.deepStrictEqual(rec.credential_fields, ['api_key', 'api_secret']);
    assert.deepStrictEqual(secrets.open(rec.credential_enc), { api_key: SECRETS[0], api_secret: SECRETS[1] });
    for (const route of ['/v1/integrations', '/v1/integrations/' + fw.id]) { r = await call('GET', route); assert.ok(!/credential_enc|v1\.[A-Za-z0-9_-]{10,}/.test(r.text), route); }

    // 4. replacing one keeps the other; clearing one drops the status; clearing all works
    r = await creds(fw.id, { values: { api_key: SECRETS[2] } }); assert.strictEqual(r.json.integration.status, 'configured');
    assert.deepStrictEqual(secrets.open((await row(fw.id)).credential_enc), { api_key: SECRETS[2], api_secret: SECRETS[1] });
    r = await creds(fw.id, { clear: ['api_secret'] }); assert.deepStrictEqual([r.json.integration.status, r.json.integration.credentials.map((c) => c.set)], ['not_configured', [true, false]]);
    assert.deepStrictEqual(secrets.open((await row(fw.id)).credential_enc), { api_key: SECRETS[2] });
    r = await creds(fw.id, { clear: ['api_key'] }); assert.strictEqual((await row(fw.id)).credential_enc, null, 'nothing left to keep: nothing is stored');
    r = await creds(fw.id, { values: { api_key: SECRETS[0], api_secret: SECRETS[1] } }); assert.strictEqual(r.json.integration.status, 'configured');
    r = await call('DELETE', `/v1/integrations/${fw.id}/credentials`); assert.deepStrictEqual([r.status, r.json.integration.status], [200, 'not_configured']);
    rec = await row(fw.id); assert.deepStrictEqual([rec.credential_enc, rec.credential_fields], [null, []]);
    await creds(fw.id, { values: { api_key: SECRETS[0], api_secret: SECRETS[1] } });

    // 5. bad requests never echo the value that came with them
    for (const b of [{ values: { api_key: SECRETS[0] + '\nmore' } }, { values: { nope: SECRETS[0] } }, { values: { api_key: SECRETS[0].repeat(400) } }, { values: { api_key: SECRETS[0] }, clear: ['api_key'] }, {}]) {
      r = await creds(fw.id, b); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY'], JSON.stringify(b).slice(0, 60));
    }
    assert.deepStrictEqual(secrets.open((await row(fw.id)).credential_enc), { api_key: SECRETS[0], api_secret: SECRETS[1] }, 'a refused request changes nothing');

    // 6. settings, switching off, and what the code that talks to the product gets
    r = await call('PUT', '/v1/integrations/' + fw.id, { name: 'Edge firewall (renamed)', config: { base_url: 'https://fw2.example.com:8443' } });
    assert.deepStrictEqual([r.status, r.json.integration.name, r.json.integration.config], [200, 'Edge firewall (renamed)', { base_url: 'https://fw2.example.com:8443' }]);
    r = await call('PUT', '/v1/integrations/' + fw.id, { config: { base_url: null } }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']);
    r = await call('PUT', '/v1/integrations/' + fw.id, { definition_id: 'pfsense' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY'], 'the product never changes');
    r = await call('POST', '/v1/integrations', { definition_id: 'virustotal', name: 'VT' }); const vt = r.json.integration; assert.strictEqual(vt.status, 'not_configured');
    r = await call('PUT', '/v1/integrations/' + fw.id, { name: 'vt' }); assert.deepStrictEqual([r.status, code(r)], [409, 'NAME_TAKEN']);
    const use = (id, purpose, t = A) => db.withTenant(t, (c) => service.useCredentials(c, t, id, purpose));
    let u = await use(fw.id, 'firewall.block');
    assert.deepStrictEqual([u.definition_id, u.config, u.credentials], ['opnsense', { base_url: 'https://fw2.example.com:8443' }, { api_key: SECRETS[0], api_secret: SECRETS[1] }]);
    assert.strictEqual((await use(vt.id, 'x')).code, 'NOT_CONFIGURED');
    assert.strictEqual((await use(fw.id, 'x', B)).code, 'NOT_FOUND', 'another tenant cannot use it');
    r = await call('PUT', '/v1/integrations/' + fw.id, { enabled: false }); assert.deepStrictEqual([r.json.integration.status, r.json.integration.enabled], ['disabled', false]);
    assert.strictEqual((await use(fw.id, 'x')).code, 'DISABLED');
    r = await call('PUT', '/v1/integrations/' + fw.id, { enabled: true }); assert.strictEqual(r.json.integration.status, 'configured');
    // an optional credential: the feed is configured without it
    r = await call('POST', '/v1/integrations', { definition_id: 'threat-feed', name: 'Blocklist feed', config: { feed_url: 'https://feeds.example.org/bad.txt', format: 'plain-text' } });
    assert.strictEqual(r.json.integration.status, 'configured'); const feed = r.json.integration;
    u = await use(feed.id, 'ioc.import'); assert.deepStrictEqual(u.credentials, {});
    r = await creds(feed.id, { values: { token: SECRETS[3] } }); assert.deepStrictEqual(r.json.integration.credentials, [{ name: 'token', label: 'Token (if the feed needs one)', required: false, set: true }]);

    // 7. the key: missing = 503 and a plain notice; changed = the old secrets are unreadable, the status still works, clearing and re-entering works
    process.env.NOTIFY_ENCRYPTION_KEY = '';
    r = await creds(fw.id, { values: { api_key: SECRETS[2] } }); assert.deepStrictEqual([r.status, code(r)], [503, 'SECRETS_NOT_CONFIGURED']);
    r = await call('GET', '/v1/integrations'); assert.deepStrictEqual([r.status, r.json.secrets_configured, r.json.integrations.find((i) => i.id === fw.id).status], [200, false, 'configured']);
    process.env.NOTIFY_ENCRYPTION_KEY = KEY_B;
    r = await creds(fw.id, { values: { api_key: SECRETS[2] } }); assert.deepStrictEqual([r.status, code(r)], [409, 'SECRET_UNREADABLE']);
    assert.strictEqual((await use(fw.id, 'x')).code, 'SECRET_UNREADABLE');
    r = await call('DELETE', `/v1/integrations/${fw.id}/credentials`); assert.strictEqual(r.status, 200);
    r = await creds(fw.id, { values: { api_key: SECRETS[0], api_secret: SECRETS[1] } }); assert.strictEqual(r.json.integration.status, 'configured');
    assert.deepStrictEqual(secrets.open((await row(fw.id)).credential_enc), { api_key: SECRETS[0], api_secret: SECRETS[1] });
    process.env.NOTIFY_ENCRYPTION_KEY = KEY_A;
    await call('DELETE', `/v1/integrations/${fw.id}/credentials`); await creds(fw.id, { values: { api_key: SECRETS[0], api_secret: SECRETS[1] } });

    // 8. a definition ASIX no longer has: still listed and deletable, never configured, nothing can be saved
    await q(`UPDATE integration_instances SET definition_id = 'removed-product' WHERE id = $1`, [vt.id]);
    r = await call('GET', '/v1/integrations/' + vt.id); assert.deepStrictEqual([r.json.integration.known_definition, r.json.integration.status, r.json.integration.credentials], [false, 'not_configured', []]);
    r = await creds(vt.id, { values: { api_key: 'x' } }); assert.deepStrictEqual([r.status, code(r)], [400, 'UNKNOWN_DEFINITION']);
    r = await call('PUT', '/v1/integrations/' + vt.id, { name: 'renamed' }); assert.deepStrictEqual([r.status, code(r)], [400, 'UNKNOWN_DEFINITION']);
    r = await call('DELETE', '/v1/integrations/' + vt.id); assert.strictEqual(r.status, 200);

    // 9. the limit per tenant
    await q(`INSERT INTO integration_instances (tenant_id, definition_id, name, created_by_name) SELECT $1, 'virustotal', 'bulk ' || g, 'test' FROM generate_series(1, 47) g`, [A]);   // 2 + 47 + 1 = 50
    r = await call('POST', '/v1/integrations', { definition_id: 'virustotal', name: 'the fiftieth' }); assert.strictEqual(r.status, 201);
    r = await call('POST', '/v1/integrations', { definition_id: 'virustotal', name: 'one too many' }); assert.deepStrictEqual([r.status, code(r)], [409, 'TOO_MANY']);

    // 10. THE POINT: no secret anywhere it should not be
    const everything = JSON.stringify([
      await rows('SELECT * FROM integration_instances'), await rows('SELECT * FROM audit_events WHERE tenant_id IN ($1, $2)', [A, B]), seen, logs]);
    for (const s of SECRETS) assert.ok(!everything.includes(s), `a secret appeared in plain text: ${s}`);
    const aud = await auditRows(A);
    for (const a of ['soar:integration:create', 'soar:integration:update', 'soar:integration:credentials-set', 'soar:integration:credentials-clear', 'soar:integration:credentials-use', 'soar:integration:delete']) assert.ok(aud.some((x) => x.action === a), a);
    assert.ok(aud.some((x) => x.action === 'soar:integration:credentials-set' && /set=api_key,api_secret cleared=-/.test(x.resource)), 'the audit names the fields');
    assert.ok(aud.some((x) => x.action === 'soar:integration:credentials-use' && /purpose=firewall\.block/.test(x.resource)), 'every use is audited with its purpose');
    assert.ok(aud.some((x) => x.action === 'soar:integration:credentials-clear' && /api_key,api_secret/.test(x.resource)));

    // 11. permissions per route and the module switch
    const perm = (m, p) => [...new Set(asked.filter((x) => x[0] === m && x[1] === p).map((x) => x[2]))];
    for (const [m, p, want] of [['GET', '/v1/integrations/definitions', 'soar:integrations:read'], ['GET', '/v1/integrations', 'soar:integrations:read'], ['GET', '/v1/integrations/:id', 'soar:integrations:read'],
      ['POST', '/v1/integrations', 'soar:integrations:write'], ['PUT', '/v1/integrations/:id', 'soar:integrations:write'], ['DELETE', '/v1/integrations/:id', 'soar:integrations:write'],
      ['PUT', '/v1/integrations/:id/credentials', 'soar:integrations:write'], ['DELETE', '/v1/integrations/:id/credentials', 'soar:integrations:write']]) assert.deepStrictEqual(perm(m, p), [want], `${m} ${p}`);
    const real = modules.isEnabled; modules.isEnabled = async (id) => (id === 'integrations' ? false : real(id));
    for (const [m, p, body] of [['GET', '/v1/integrations/definitions'], ['GET', '/v1/integrations'], ['POST', '/v1/integrations', { definition_id: 'virustotal', name: 'z' }], ['GET', `/v1/integrations/${fw.id}`],
      ['PUT', `/v1/integrations/${fw.id}`, { enabled: false }], ['DELETE', `/v1/integrations/${fw.id}`], ['PUT', `/v1/integrations/${fw.id}/credentials`, { values: { api_key: 'x' } }], ['DELETE', `/v1/integrations/${fw.id}/credentials`]]) {
      r = await call(m, p, body); assert.deepStrictEqual([r.status, code(r)], [403, 'MODULE_DISABLED'], `${m} ${p}`);
    }
    modules.isEnabled = real;
    r = await call('DELETE', '/v1/integrations/' + fw.id); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([(await call('GET', '/v1/integrations/' + fw.id)).status, (await call('DELETE', '/v1/integrations/' + fw.id)).status], [404, 404]);
    realLog('integrations-db: all checks passed');
  } finally {
    srv.close();
    for (const t of [A, B]) {
      for (const tbl of ['integration_instances', 'audit_events', 'case_events', 'case_alerts', 'cases', 'users']) await q(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t]).catch((e) => realErr('cleanup', tbl, e.message));
      await q('DELETE FROM tenants WHERE id = $1', [t]).catch((e) => realErr('cleanup tenants', e.message));
    }
    await db.close();
  }
}
main().then(() => process.exit(0)).catch((e) => { realErr(e); process.exit(1); });
