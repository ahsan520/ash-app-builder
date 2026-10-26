'use strict';
// Rotating a broker's key (POST /v1/brokers/:id/rotate-key): the pure name and command helpers, then the real route with
// the sign-in chain and the database replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const view = require('../src/brokers/broker-view');
const { hashKey } = require('../src/ingest/http-ingest');

describe('rotatedName', () => {
  const NOW = Date.UTC(2026, 9, 17, 23, 14, 5);
  it('names the broker and the minute, and fits the installer name rule', () => {
    assert.strictEqual(view.rotatedName('broker-1', NOW), 'broker-1-key-20261017-2314');
    for (const n of ['broker-1', 'rack:7/vm 2', '::odd::', '', null, 'x'.repeat(300)]) {
      const s = view.rotatedName(n, NOW);
      assert.match(s, /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$/, String(n));
    }
  });
  it('differs from one minute to the next, so two keys in different minutes never collide', () => {
    assert.notStrictEqual(view.rotatedName('b', NOW), view.rotatedName('b', NOW + 60000));
  });
});

describe('rotateCommand', () => {
  it('has the key and the broker name, and says to repeat the original TLS options', () => {
    const c = view.rotateCommand('broker-1', 'asix_ik_SECRET');
    assert.match(c, /--key asix_ik_SECRET/); assert.match(c, /--name broker-1/); assert.match(c, /bootstrap-broker\.sh/); assert.match(c, /--tls-cert/);
  });
});

describe('POST /v1/brokers/:id/rotate-key', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  const ID = '22222222-2222-4222-8222-222222222222';
  let calls; let selectRows; let insertError;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
    calls.push({ sql, args });
    if (/^\s*SELECT/i.test(sql)) return { rows: selectRows };
    if (insertError) throw insertError;
    return { rows: [{ id: 'new-key-id', name: args[1], platform: args[3], key_prefix: args[4], created_at: new Date() }] };
  } }), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(() => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'user-1'; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/brokers')];
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/brokers'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; });
  const post = async (id) => { const r = await fetch(base + '/v1/brokers/' + id + '/rotate-key', { method: 'POST' }); return { status: r.status, json: await r.json() }; };
  const reset = () => { calls = []; insertError = null; selectRows = [{ id: ID, name: 'broker-1', version: 'vector-0.47.0', key_id: 'old-key-id', key_platform: 'linux' }]; };

  it('makes a new key for this tenant, stores only its hash, and returns the key, the command and the old key id once', async () => {
    reset();
    const r = await post(ID);
    assert.strictEqual(r.status, 201); assert.match(r.json.key, /^asix_ik_/);
    assert.strictEqual(r.json.old_installer_id, 'old-key-id'); assert.strictEqual(r.json.broker.name, 'broker-1');
    assert.match(r.json.command, new RegExp('--key ' + r.json.key)); assert.match(r.json.installer.name, /^broker-1-key-\d{8}-\d{4}$/);
    const ins = calls.find((c) => /INSERT INTO ingestion_keys/.test(c.sql));
    assert.strictEqual(ins.args[0], TENANT); assert.strictEqual(ins.args[5], hashKey(r.json.key)); assert.strictEqual(ins.args[6], 'user-1');
    assert.ok(!JSON.stringify(ins.args).includes(r.json.key), 'the plain key is never stored');
    assert.ok(!calls.some((c) => /UPDATE ingestion_keys/.test(c.sql)), 'the old key is not revoked here');
  });
  it('is a 404 for something that is not a broker, or not found, and a 400 for a bad id', async () => {
    reset(); selectRows = [{ id: ID, name: 'laptop', version: '1.0', key_id: 'k', key_platform: 'linux' }];
    assert.strictEqual((await post(ID)).status, 404); assert.ok(!calls.some((c) => /INSERT/.test(c.sql)));
    selectRows = []; assert.strictEqual((await post(ID)).status, 404);
    assert.strictEqual((await post('nope')).status, 400);
  });
  it('works for a broker whose key was deleted (no old key to revoke)', async () => {
    reset(); selectRows = [{ id: ID, name: 'broker-1', version: 'vector-0.47.0', key_id: null, key_platform: null }];
    const r = await post(ID); assert.strictEqual(r.status, 201); assert.strictEqual(r.json.old_installer_id, null);
    assert.strictEqual(calls.find((c) => /INSERT INTO ingestion_keys/.test(c.sql)).args[3], 'linux');
  });
  it('says so when a key with that name already exists (two presses in one minute)', async () => {
    reset(); insertError = Object.assign(new Error('dup'), { code: '23505' });
    assert.strictEqual((await post(ID)).status, 409);
  });
});
