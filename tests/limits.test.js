'use strict';
// License limits (src/modules/limits.js): the pure rules, and the storage routes that enforce them.
// The sign-in chain and the database are replaced (require.cache); the route code and the rules are real.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');

const limits = require('../src/modules/limits');
const CAP = { tenants: 1, retention_days_max: 90 };
const NONE = { tenants: null, retention_days_max: null };

describe('retention cap rules', () => {
  it('allows anything when the cap is null or missing', () => {
    assert.strictEqual(limits.checkRetentionChange({ default_days: 3650, overrides: [{ source_type: 'x', retention_days: null }] }, NONE), null);
    assert.strictEqual(limits.checkRetentionChange({ default_days: 3650 }, {}), null);
    assert.strictEqual(limits.checkRetentionChange({ default_days: 3650 }, undefined), null);
  });
  it('allows up to and including the cap', () => {
    assert.strictEqual(limits.checkRetentionChange({ default_days: 90, overrides: [{ source_type: 'a', retention_days: 90 }, { source_type: 'b', retention_days: 1 }] }, CAP), null);
  });
  it('refuses a default above the cap, an override above it and keep-forever', () => {
    assert.strictEqual(limits.checkRetentionChange({ default_days: 91 }, CAP).code, 'LICENSE_LIMIT');
    assert.match(limits.checkRetentionChange({ overrides: [{ source_type: 'auth', retention_days: 365 }] }, CAP).message, /"auth".*90 days/);
    assert.match(limits.checkRetentionChange({ overrides: [{ source_type: 'auth', retention_days: null }] }, CAP).message, /forever/);
  });
  it('checks only what the request changes (toggling auto purge is never blocked)', () => {
    assert.strictEqual(limits.checkRetentionChange({ auto_purge: true }, CAP), null);
  });
  it('reports stored settings that are over the cap, without judging the rest', () => {
    const pol = { default_days: 120, overrides: [{ source_type: 'a', retention_days: 30 }, { source_type: 'b', retention_days: null }, { source_type: 'c', retention_days: 400 }] };
    assert.deepStrictEqual(limits.retentionOverLimit(pol, CAP).map((o) => o.scope), ['default', 'b', 'c']);
    assert.deepStrictEqual(limits.retentionOverLimit(pol, NONE), []);
    assert.deepStrictEqual(limits.retentionOverLimit({ default_days: 90, overrides: [] }, CAP), []);
  });
});

describe('tenant cap rules', () => {
  it('blocks creating a tenant only when the cap is reached', () => {
    assert.strictEqual(limits.checkTenantCreate(0, CAP), null);
    assert.strictEqual(limits.checkTenantCreate(1, CAP).code, 'LICENSE_LIMIT');
    assert.match(limits.checkTenantCreate(1, CAP).message, /1 tenant and 1 already exists/);
    assert.strictEqual(limits.checkTenantCreate(5, { tenants: 5 }).limit, 'tenants');
    assert.strictEqual(limits.checkTenantCreate(99, NONE), null);
  });
  it('usage report lists only tenants over the cap', () => {
    assert.deepStrictEqual(limits.usageReport(CAP, { tenants: 1 }), []);
    assert.deepStrictEqual(limits.usageReport(CAP, { tenants: 3 }), [{ limit: 'tenants', used: 3, allowed: 1 }]);
    assert.deepStrictEqual(limits.usageReport(CAP, null), []);
  });
});

describe('currentLimits', () => {
  it('uses the snapshot, and falls back to the Home defaults if it fails', async () => {
    assert.deepStrictEqual(await limits.currentLimits(async () => ({ limits: NONE })), NONE);
    assert.deepStrictEqual(await limits.currentLimits(async () => { throw new Error('bad profile'); }), { tenants: 1, retention_days_max: 90 });
  });
});

describe('storage routes enforce the retention cap', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  let policy = { default_days: 90, auto_purge: false }; let overrides = []; let writes = 0;
  const fakeDb = {
    query: async (sql) => {
      if (/FROM retention_settings/.test(sql)) return { rows: [{ auto_purge: policy.auto_purge, default_days: policy.default_days }] };
      if (/FROM retention_policies/.test(sql)) return { rows: overrides };
      if (/FROM retention_runs/.test(sql)) return { rows: [] };
      return { rows: [] };
    },
    withTenant: async (t, fn) => { writes++; return fn({ query: async () => ({ rows: [] }) }); },
  };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  const env = { ...process.env };
  before(async () => {
    require.cache[require.resolve('../src/gateway/shared')].exports = {
      ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
    };
    process.env.ASIX_PROFILE = 'home'; delete process.env.ASIX_LICENSE; process.env.ASIX_LICENSE_FILE = '/nonexistent/license.jwt';
    require('../src/modules').resetCache();
    delete require.cache[require.resolve('../src/gateway/routes/storage')];
    const router = require('../src/gateway/routes/storage');
    const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
    setEventStore(new MemoryEventStore());
    const app = express(); app.use(express.json()); app.use(router);
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; process.env = env; require('../src/modules').resetCache(); });
  const put = async (body) => { const r = await fetch(base + '/v1/storage/retention', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };

  it('refuses a default above the Home cap with 403 LICENSE_LIMIT and saves nothing', async () => {
    writes = 0;
    const r = await put({ default_days: 365 });
    assert.strictEqual(r.status, 403); assert.strictEqual(r.body.error.code, 'LICENSE_LIMIT'); assert.strictEqual(writes, 0);
  });
  it('refuses keep-forever for a source', async () => {
    const r = await put({ overrides: [{ source_type: 'syslog', retention_days: null }] });
    assert.strictEqual(r.status, 403);
  });
  it('accepts values within the cap', async () => {
    writes = 0;
    const r = await put({ default_days: 60, overrides: [{ source_type: 'syslog', retention_days: 90 }] });
    assert.strictEqual(r.status, 200); assert.strictEqual(writes, 1);
  });
  it('shape errors still win (400) over the limit', async () => {
    assert.strictEqual((await put({ default_days: 'x' })).status, 400);
  });
  it('GET reports the cap and what is over it, and deletes nothing', async () => {
    policy = { default_days: 365, auto_purge: true }; overrides = [{ source_type: 'old', retention_days: null }];
    const r = await (await fetch(base + '/v1/storage/retention')).json();
    assert.strictEqual(r.limit_days, 90);
    assert.deepStrictEqual(r.over_limit.map((o) => o.scope), ['default', 'old']);
  });
  it('toggling automatic purge is allowed even while a stored value is over the cap', async () => {
    assert.strictEqual((await put({ auto_purge: false })).status, 200);
  });
});
