'use strict';
// The two ingest lanes now write through the event store. This checks them end to end on a real Postgres.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/event-ingest-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
process.env.BROKER_INGEST_TOKEN = 'test-broker-token';

const db = require('../src/db');
const { router: httpIngest, generateKey, hashKey } = require('../src/ingest/http-ingest');
const coreRoutes = require('../src/gateway/routes/core');

async function main() {
  const stamp = Date.now();
  const T = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['ingest-store-' + stamp])).rows[0].id;
  const key = generateKey();
  await db.withTenant(T, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,'k1','linux',$2,$3)", [T, key.slice(0, 12), hashKey(key)]));
  const app = express(); app.use(httpIngest); app.use(express.json()); app.use(coreRoutes);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const send = async (p, body, headers) => { const r = await fetch(base + p, { method: 'POST', headers, body }); return { status: r.status, json: await r.json() }; };
  const rows = async (src) => (await db.withTenant(T, (c) => c.query('SELECT * FROM events WHERE source_type = $1 ORDER BY raw', [src]))).rows;
  const keyAuth = { authorization: 'Bearer ' + key };
  const brokerAuth = { authorization: 'Bearer test-broker-token', 'content-type': 'application/json' };

  try {
    // --- key lane, text/plain: a syslog-shaped line keeps its event time and parsed fields
    let r = await send('/v1/ingest/http', '2026-10-13T10:00:01+00:00 web01 sshd[2201]: Failed password for root\nplain line', { ...keyAuth, 'content-type': 'text/plain', 'x-asix-source-type': 'it-text', 'x-asix-collector': 'c-text' });
    assert.strictEqual(r.status, 202); assert.strictEqual(r.json.accepted, 2);
    let e = await rows('it-text');
    assert.strictEqual(e.length, 2);
    const sshd = e.find((x) => /Failed password/.test(x.raw));
    assert.strictEqual(sshd.collector_id, 'c-text'); assert.strictEqual(sshd.parsed.app_name, 'sshd');
    assert.strictEqual(new Date(sshd.event_time + 'Z').toISOString(), '2026-10-13T10:00:01.000Z');
    assert.ok(sshd.received_at, 'received_at stamped by the database');
    assert.strictEqual(e.find((x) => x.raw === 'plain line').event_time, null);

    // --- key lane, JSON, with a NUL character that used to fail the whole batch
    r = await send('/v1/ingest/http', JSON.stringify({ collector: { name: 'c-json' }, source_type: 'it-json', events: [{ message: 'ab\u0000cd', fields: { k: 'v\u0000w' } }, { message: 'second' }] }), { ...keyAuth, 'content-type': 'application/json' });
    assert.strictEqual(r.status, 202); assert.strictEqual(r.json.accepted, 2);
    e = await rows('it-json');
    assert.deepStrictEqual(e.map((x) => x.raw), ['abcd', 'second']);
    assert.strictEqual(e[0].parsed.k, 'vw');
    // collector bookkeeping and the events commit together
    const col = (await db.withTenant(T, (c) => c.query("SELECT events_total FROM collectors WHERE name = 'c-json'"))).rows[0];
    assert.strictEqual(Number(col.events_total), 2);

    // --- an invalid event is a 400 and nothing from the batch is stored (oversize parsed fields)
    r = await send('/v1/ingest/http', JSON.stringify({ collector: { name: 'c-big' }, source_type: 'it-big', events: [{ message: 'fine' }, { message: 'huge', fields: { blob: 'x'.repeat(1024 * 1024) } }] }), { ...keyAuth, 'content-type': 'application/json' });
    assert.ok(r.status === 400 || r.status === 413, 'rejected, got ' + r.status);
    assert.strictEqual((await rows('it-big')).length, 0);

    // --- broker lane
    r = await send('/v1/ingest/events', JSON.stringify({ tenant_id: T, source_type: 'it-broker', collector_id: 'b1', events: [{ raw: 'one', event_time: '2026-10-13T11:00:00Z', parsed: { a: 1 } }, { raw: 'two' }] }), brokerAuth);
    assert.strictEqual(r.status, 202); assert.strictEqual(r.json.inserted, 2);
    e = await rows('it-broker');
    assert.deepStrictEqual(e.map((x) => x.raw), ['one', 'two']);
    assert.deepStrictEqual(e[0].parsed, { a: 1 }); assert.strictEqual(e[0].collector_id, 'b1');

    // missing raw: a clean 400 (was a 500), and the good event in the same batch is not stored
    r = await send('/v1/ingest/events', JSON.stringify({ tenant_id: T, source_type: 'it-broker2', events: [{ raw: 'ok' }, { parsed: {} }] }), brokerAuth);
    assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INGEST_INVALID_EVENT');
    assert.strictEqual((await rows('it-broker2')).length, 0);
    r = await send('/v1/ingest/events', JSON.stringify({ tenant_id: T, source_type: 'it-broker2', events: [null] }), brokerAuth);
    assert.strictEqual(r.status, 400);
    r = await send('/v1/ingest/events', JSON.stringify({ tenant_id: 'not-a-uuid', source_type: 'it-broker2', events: [{ raw: 'x' }] }), brokerAuth);
    assert.strictEqual(r.status, 400);
    console.log('event ingest (db) ok');
  } finally {
    srv.close();
    await db.withTenant(T, (c) => c.query('DELETE FROM events')).catch(() => {});
    await db.query('DELETE FROM audit_events WHERE tenant_id = $1', [T]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = $1', [T]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = $1', [T]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = $1', [T]).catch(() => {});
    await db.close();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
