'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-placement-db.test.js
// Skips itself otherwise. The REAL heartbeat route stores the size and the agent count, the REAL brokers and placement routes read and change them;
// only the sign-in chain and the event store are replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

async function main() {
  const stamp = Date.now();
  const mk = async (name) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', [name + stamp])).rows[0].id;
  const A = await mk('plc-a-'), B = await mk('plc-b-');
  const keyFor = async (tenant, label) => { const k = generateKey(); await db.withTenant(tenant, (c) => c.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, label, k.slice(0, 12), hashKey(k)])); return k; };
  const keyA = await keyFor(A, 'plc-key-a'), keyB = await keyFor(B, 'plc-key-b');
  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(express.json());
  app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-placement'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const api = async (method, url, body) => { const r = await fetch(base + url, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
  const beat = (key, name, collector = {}) => fetch(base + '/v1/ingest/heartbeat', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key }, body: JSON.stringify({ collector: { name, os: 'Vector broker VM', version: 'vector-0.59.0', ...collector } }) });
  const n1 = 'plc-1-' + stamp, n2 = 'plc-2-' + stamp, n3 = 'plc-3-' + stamp, nB = 'plc-b1-' + stamp;
  const find = async (name) => (await api('GET', '/v1/brokers')).body.brokers.find((b) => b.name === name);
  const stored = async (tenant, name) => (await db.withTenant(tenant, (c) => c.query('SELECT host_cpus, host_mem_mb, agents_enrolled, broker_group, agent_limit FROM collectors WHERE name = $1', [name]))).rows[0];
  try {
    // ---- the heartbeat stores size and count; an older script leaves them alone ----
    TENANT = A;
    assert.strictEqual((await beat(keyA, n1, { inputs: 'syslog:514,wazuh,wazuhalerts', host: { cpus: 4, mem_mb: 7800 }, agents: 10 })).status, 200);
    assert.deepStrictEqual(await stored(A, n1), { host_cpus: 4, host_mem_mb: 7800, agents_enrolled: 10, broker_group: null, agent_limit: null });
    const b1 = await find(n1);
    assert.deepStrictEqual(b1.capacity, { cpus: 4, mem_mb: 7800, enrolled: 10, recommended: 45, limit: 45, limit_source: 'estimated', free: 35, used_percent: 22, state: 'ok' });
    assert.strictEqual(b1.group, null);
    assert.strictEqual((await beat(keyA, n1, { inputs: 'syslog:514,wazuh,wazuhalerts' })).status, 200, 'an older script');
    assert.deepStrictEqual(await stored(A, n1), { host_cpus: 4, host_mem_mb: 7800, agents_enrolled: 10, broker_group: null, agent_limit: null }, 'nothing was erased');
    assert.strictEqual((await beat(keyA, n1, { host: { cpus: 8, mem_mb: 15800 }, agents: 0 })).status, 200);
    assert.deepStrictEqual((await stored(A, n1)).agents_enrolled, 0, 'zero agents is a real answer');
    assert.strictEqual((await stored(A, n1)).host_cpus, 8);
    // nonsense is ignored, never an error and never stored
    assert.strictEqual((await beat(keyA, n1, { host: { cpus: -3, mem_mb: 'lots' }, agents: 'many' })).status, 200);
    assert.deepStrictEqual(await stored(A, n1), { host_cpus: 8, host_mem_mb: 15800, agents_enrolled: 0, broker_group: null, agent_limit: null });
    // a broker with no manager says no count, and shows an unknown capacity
    assert.strictEqual((await beat(keyA, n2, { inputs: 'syslog:514' })).status, 200);
    assert.strictEqual((await find(n2)).capacity.state, 'unknown');
    assert.strictEqual((await api('GET', '/v1/brokers')).body.summary.agents_enrolled, 0);

    // ---- set group and limit ----
    let r = await api('PUT', '/v1/brokers/' + b1.id + '/placement', { group: 'acme', agent_limit: 20 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.broker.group, 'acme'); assert.strictEqual(r.body.broker.capacity.limit, 20); assert.strictEqual(r.body.broker.capacity.limit_source, 'set');
    assert.deepStrictEqual(await stored(A, n1), { host_cpus: 8, host_mem_mb: 15800, agents_enrolled: 0, broker_group: 'acme', agent_limit: 20 });
    r = await api('PUT', '/v1/brokers/' + b1.id + '/placement', { group: null });   // only the group; the limit is left alone
    assert.strictEqual(r.status, 200); assert.strictEqual((await stored(A, n1)).agent_limit, 20); assert.strictEqual((await stored(A, n1)).broker_group, null);
    r = await api('PUT', '/v1/brokers/' + b1.id + '/placement', { group: 'acme', agent_limit: null });
    assert.strictEqual(r.status, 200); assert.strictEqual((await stored(A, n1)).agent_limit, null); assert.strictEqual(r.body.broker.capacity.limit_source, 'estimated');
    for (const [body, code] of [[{}, 'INVALID_BODY'], [{ x: 1 }, 'INVALID_BODY'], [{ group: 'a b' }, 'INVALID_GROUP'], [{ group: '-x' }, 'INVALID_GROUP'], [{ group: 5 }, 'INVALID_GROUP'], [{ agent_limit: 0 }, 'INVALID_LIMIT'], [{ agent_limit: 'x' }, 'INVALID_LIMIT'], [{ agent_limit: 100001 }, 'INVALID_LIMIT'], [{ group: 'ok', agent_limit: -1 }, 'INVALID_LIMIT']]) {
      r = await api('PUT', '/v1/brokers/' + b1.id + '/placement', body); assert.strictEqual(r.status, 400, JSON.stringify(body)); assert.strictEqual(r.body.error.code, code, JSON.stringify(body));
    }
    assert.strictEqual((await stored(A, n1)).broker_group, 'acme', 'a refused request changed nothing, not even its valid half');
    assert.strictEqual((await api('PUT', '/v1/brokers/not-a-uuid/placement', { group: 'x' })).status, 400);
    assert.strictEqual((await api('PUT', '/v1/brokers/00000000-0000-4000-8000-000000000000/placement', { group: 'x' })).status, 404);

    // ---- another tenant's broker, and a collector that is not a broker ----
    TENANT = B; assert.strictEqual((await beat(keyB, nB, { inputs: 'syslog:514,wazuh', host: { cpus: 4, mem_mb: 8192 }, agents: 1 })).status, 200);
    const bB = await find(nB); await api('PUT', '/v1/brokers/' + bB.id + '/placement', { group: 'acme' });
    TENANT = A;
    assert.strictEqual((await api('PUT', '/v1/brokers/' + bB.id + '/placement', { group: 'hijack' })).status, 404, 'a tenant cannot change another tenant\'s broker');
    TENANT = B; assert.strictEqual((await stored(B, nB)).broker_group, 'acme'); TENANT = A;
    const plain = 'plc-plain-' + stamp;
    await db.withTenant(A, (c) => c.query("INSERT INTO collectors (tenant_id, key_id, name, platform, version, events_total) VALUES ($1, NULL, $2, 'linux', '1.0', 0)", [A, plain]));
    const plainId = (await db.withTenant(A, (c) => c.query('SELECT id FROM collectors WHERE name = $1', [plain]))).rows[0].id;
    assert.strictEqual((await api('PUT', '/v1/brokers/' + plainId + '/placement', { group: 'x' })).status, 404, 'only brokers (a Vector heartbeat) can be grouped');

    // ---- groups, next broker, plan ----
    assert.strictEqual((await beat(keyA, n2, { inputs: 'syslog:514,wazuh', host: { cpus: 2, mem_mb: 4096 }, agents: 10 })).status, 200);
    assert.strictEqual((await beat(keyA, n3, { inputs: 'syslog:514,wazuh', host: { cpus: 8, mem_mb: 16384 }, agents: 30 })).status, 200);
    const b2 = await find(n2), b3 = await find(n3);
    await api('PUT', '/v1/brokers/' + b2.id + '/placement', { group: 'acme' }); await api('PUT', '/v1/brokers/' + b3.id + '/placement', { group: 'acme' });
    await beat(keyA, n1, { host: { cpus: 4, mem_mb: 8192 }, agents: 40 });   // n1: limit 48, 83%: near
    r = await api('GET', '/v1/brokers/placement');
    assert.strictEqual(r.status, 200);
    const acme = r.body.groups.find((g) => g.name === 'acme');
    assert.strictEqual(acme.brokers, 3, 'the other tenant\'s broker in a group of the same name is not counted');
    assert.strictEqual(acme.enrolled, 80); assert.strictEqual(acme.limit, 48 + 24 + 96);
    assert.strictEqual(acme.next.name, n3, 'the big VM at 31 percent is the least full for its size');
    assert.strictEqual(r.body.brokers.find((b) => b.name === n1).capacity.state, 'near');
    assert.strictEqual(r.body.plan, null); assert.deepStrictEqual(r.body.settings, { per_cpu: 12, per_gb: 6, near_percent: 80 });
    assert.ok(!JSON.stringify(r.body).includes(nB), 'nothing of the other tenant');
    r = await api('GET', '/v1/brokers/placement?endpoints=3000');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.plan.endpoints, 3000); assert.strictEqual(r.body.plan.per_broker, r.body.typical_limit); assert.ok(r.body.plan.brokers_total > r.body.plan.brokers_for_load); assert.strictEqual(r.body.plan.brokers_now, 3);
    for (const bad of ['0', 'x', '-4', '1.5', '']) assert.strictEqual((await api('GET', '/v1/brokers/placement?endpoints=' + bad)).status, 400, bad);

    // ---- the installer pointed at a broker ----
    r = await api('GET', '/v1/brokers/placement/installer/linux?broker=' + b3.id + '&group=windows');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.broker.name, n3); assert.strictEqual(r.body.broker.address, '127.0.0.1'); assert.strictEqual(r.body.installer.manager, '127.0.0.1'); assert.strictEqual(r.body.installer.group, 'windows');
    assert.ok(r.body.installer.script.includes('127.0.0.1') && r.body.installer.script.includes(r.body.installer.password_token));
    r = await api('GET', '/v1/brokers/placement/installer/windows?broker=auto&broker_group=acme');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.broker.name, n3, 'auto picks the next broker of the group'); assert.strictEqual(r.body.installer.filename, 'asix-endpoint-install.ps1');
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux?broker=auto&broker_group=nope')).status, 404);
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux?broker=auto')).status, 400);
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux')).status, 400);
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux?broker=xyz')).status, 400);
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux?broker=' + b3.id + '&group=a%20b')).status, 400, 'the agent group alphabet is enforced');
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux?broker=' + bB.id)).status, 404, 'another tenant\'s broker');
    assert.strictEqual((await api('GET', '/v1/brokers/placement/installer/linux?broker=' + plainId)).status, 404);
    // a full broker is refused unless forced; a broker with no manager is refused outright
    await api('PUT', '/v1/brokers/' + b2.id + '/placement', { agent_limit: 10 });   // n2: 10 of 10
    r = await api('GET', '/v1/brokers/placement/installer/linux?broker=' + b2.id); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'BROKER_FULL');
    r = await api('GET', '/v1/brokers/placement/installer/linux?broker=' + b2.id + '&force=1'); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.broker.over_limit, true);
    await beat(keyA, 'plc-nomgr-' + stamp, { inputs: 'syslog:514', host: { cpus: 4, mem_mb: 8192 } });
    const nm = await find('plc-nomgr-' + stamp);
    r = await api('GET', '/v1/brokers/placement/installer/linux?broker=' + nm.id + '&force=1'); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'BROKER_NOT_AVAILABLE', 'force only covers "full"');
    // everything in the group full: auto says so, with the reasons
    await api('PUT', '/v1/brokers/' + b1.id + '/placement', { agent_limit: 40 }); await api('PUT', '/v1/brokers/' + b3.id + '/placement', { agent_limit: 30 });
    r = await api('GET', '/v1/brokers/placement/installer/linux?broker=auto&broker_group=acme'); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'NO_BROKER_AVAILABLE'); assert.match(r.body.error.message, /full/);

    // ---- the schema refuses what the code refuses ----
    for (const [col, val] of [['host_cpus', 0], ['host_mem_mb', 10], ['agents_enrolled', -1], ['agent_limit', 0], ['broker_group', 'a b']]) {
      await assert.rejects(db.withTenant(A, (c) => c.query(`UPDATE collectors SET ${col} = $1 WHERE name = $2`, [val, n1])), (e) => e.code === '23514', col + ' check');
    }
    console.log('broker-placement-db: ok');
  } finally {
    srv.close();
    await db.pool.end().catch(() => {});
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
