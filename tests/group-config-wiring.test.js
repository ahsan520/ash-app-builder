'use strict';
// E10: the pieces around the feature that no behaviour test would notice if they were forgotten: the switch is off in the manifest, the permission is in the role, the route is mounted
// before the readiness route, every route has the right permission, the tables have row security, and the writer registration is only a user and a password.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
const store = require('../src/endpoints/group-config-store');

describe('deployment', () => {
  it('the server switch is in the manifest and OFF', () => { assert.match(read('k8s/30-asix-api.yaml'), /- name: ASIX_ENDPOINT_CONFIG_WRITE\n\s+value: "false"/); });
  it('the new permission is in portal-admin, in both the insert and the update list', () => { assert.strictEqual((read('scripts/deploy/bootstrap-portal.sh').match(/'modules:read', 'endpoints:config:write'\]/g) || []).length, 2); });
  it('the route is mounted before the readiness route', () => { const g = read('src/gateway/index.js'); const m = g.indexOf("require('./routes/group-config')"); assert.ok(m > 0 && m < g.indexOf("app.get('/v1/health/ready'")); });
  it('the schema has both tables with row security and a policy per tenant, and the history can only say apply, remove or undo', () => {
    const s = read('k8s/12-schema-init.yaml');
    for (const t of ['wazuh_manager_writers', 'endpoint_group_config_history']) { assert.match(s, new RegExp('ALTER TABLE ' + t + ' ENABLE ROW LEVEL SECURITY')); assert.match(s, new RegExp('CREATE POLICY ' + t + '_tenant_isolation ON ' + t)); assert.match(s, new RegExp('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + t + ' TO asix_admin')); }
    assert.match(s, /action IN \('apply', 'remove', 'undo'\)/); assert.match(s, /result IN \('applied', 'rolled_back', 'failed'\)/);
  });
});

describe('the route file', () => {
  const src = read('src/gateway/routes/group-config.js');
  it('has exactly the routes and permissions it should: reads and preview need capacity:read, a change and an undo need endpoints:config:write', () => {
    const routes = [...src.matchAll(/router\.(get|post|put|patch|delete)\('([^']+)', \.\.\.guarded\('([^']+)'\)/g)].map((m) => m[1].toUpperCase() + ' ' + m[2] + ' ' + m[3]);
    assert.deepStrictEqual(routes, ['GET /v1/endpoints/group-config capacity:read', 'GET /v1/endpoints/group-config/:group capacity:read', 'POST /v1/endpoints/group-config/:group/preview capacity:read', 'PUT /v1/endpoints/group-config/:group endpoints:config:write', 'POST /v1/endpoints/group-config/:group/undo endpoints:config:write']);
    assert.ok(!/router\.(patch|delete)\(/.test(src));
  });
  it('both writing routes check the server switch first, and the switch is read each time (no cached value)', () => {
    assert.strictEqual((src.match(/writeGate\(req, res\)/g) || []).length, 2); assert.match(src, /const writeOn = \(\) => String\(process\.env\.ASIX_ENDPOINT_CONFIG_WRITE/);
  });
  it('nothing in a request chooses an address, a credential or a path to the manager', () => { assert.ok(!/req\.(body|query|params)\.(url|address|host|user|password|path)/.test(src)); assert.ok(!/api_url|ca_pem/.test(src.replace(/\/\/.*$/gm, '').replace(/managerStore\.[a-z]+/g, ''))); });
  it('no password reaches a log line or a response', () => { for (const l of src.split('\n').filter((x) => /console\.(error|log|warn)/.test(x))) assert.ok(!/password|secret|creds|\.w\b|ctx/.test(l), l); assert.ok(!/api_password|api_secret_enc/.test(src.replace(/\/\/.*$/gm, ''))); });
  it('the old file text is stored but never sent to the page', () => { const shape = src.slice(src.indexOf('const shapeHistory')); assert.ok(!/before_content/.test(shape.split('\n')[0])); });
});

describe('the writer registration is only a user and a password', () => {
  it('accepts a user and a password', () => { assert.deepStrictEqual(store.parseRegistration({ user: 'asix-groupconfig', password: 'Sup3r-secret!' }), { reg: { api_user: 'asix-groupconfig', password: 'Sup3r-secret!' } }); });
  it('refuses everything else: an address, a certificate, a short or odd user or password, a non-object', () => {
    for (const bad of [null, [], 'x', 5, { user: 'ab', password: 'Sup3r-secret!' }, { user: 'a b c', password: 'Sup3r-secret!' }, { user: 'asix-groupconfig' }, { user: 'asix-groupconfig', password: 'short' }, { user: 'asix-groupconfig', password: 'x'.repeat(129) }, { user: 'asix-groupconfig', password: 'bad\npassword!' }, { user: 'asix-groupconfig', password: 'Sup3r-secret!', url: 'https://10.0.0.1:55000' }, { user: 'asix-groupconfig', password: 'Sup3r-secret!', ca_pem: 'x' }]) assert.ok(store.parseRegistration(bad).error, JSON.stringify(bad));
  });
  it('a view never carries the sealed password', () => { assert.deepStrictEqual(store.writerView(null), { registered: false }); assert.ok(!JSON.stringify(store.writerView({ api_user: 'u', api_secret_enc: 'v1.a.b.c', updated_at: 1 })).includes('v1.')); });
  it('a history row needs a known action and result', async () => {
    for (const h of [{ action: 'delete', result: 'applied' }, { action: 'apply', result: 'weird' }]) await assert.rejects(store.record({ query: async () => ({ rows: [] }) }, 't', 'g', h), /bad history row/);
    await assert.rejects(store.settle({ query: async () => ({ rowCount: 1 }) }, 't', 'i', 'weird'), /bad history result/);
  });
});
