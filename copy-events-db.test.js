'use strict';
// The event copy tool on real servers: PostgreSQL and ClickHouse, driven through its real command line.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... ASIX_CLICKHOUSE_URL=http://user:pass@127.0.0.1:8123/asix node --test tests/copy-events-db.test.js
// Needs both servers, with the platform schema in PostgreSQL. Skips itself otherwise. It uses throwaway tenants and removes their events.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 and ASIX_CLICKHOUSE_URL to run against Postgres and ClickHouse)'); process.exit(0); }
if (!process.env.ASIX_CLICKHOUSE_URL) { console.error('ASIX_TEST_DB=1 needs ASIX_CLICKHOUSE_URL'); process.exit(1); }

const test = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { execFile } = require('child_process');
const db = require('../src/db');
const { PostgresEventStore } = require('../src/events/postgres-store');
const { ClickHouseEventStore } = require('../src/events/clickhouse-store');
const { copyAll } = require('../src/events/copy-events');

const CLI = path.join(__dirname, '..', 'src', 'events', 'copy-events.js');
const pg = new PostgresEventStore(), ch = new ClickHouseEventStore();
const stamp = Date.now();
let T1, T2, T3;

const cli = (...args) => new Promise((resolve) => execFile('node', [CLI, ...args], { env: process.env, timeout: 120000 }, (err, stdout, stderr) => resolve({ code: err ? err.code : 0, out: stdout + stderr })));
const num = (out, label) => Number((out.match(new RegExp(`${label} (\\d+)`)) || [])[1]);

// 3,000 events for T1 over three days, written with SQL so received_at has MICROSECONDS (the case that matters), a null collector,
// null event times, unicode, nested JSON, and quotes in raw. 500 for T2. T3 has none.
async function seed() {
  const mk = async (name) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', [name + stamp])).rows[0].id;
  [T1, T2, T3] = [await mk('copy-a-'), await mk('copy-b-'), await mk('copy-c-')];
  const insert = (tenant, n, tag) => db.withTenant(tenant, async (c) => {
    for (let i = 0; i < n; i++) {
      const day = 1 + (i % 3), sec = String(i % 60).padStart(2, '0'), micros = String(100000 + (i * 7919) % 899999);
      await c.query(
        `INSERT INTO events (id, tenant_id, source_type, collector_id, received_at, event_time, raw, parsed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [crypto.randomUUID(), tenant, i % 3 ? 'syslog' : 'json', i % 4 ? 'c-' + (i % 4) : null, `2026-10-0${day} 10:${String(i % 50).padStart(2, '0')}:${sec}.${micros}`,
          i % 2 ? `2026-10-0${day} 09:00:${sec}.5` : null, `${tag} "quoted" ünïcode ✓ line ${i}`, JSON.stringify({ n: i, host: 'h' + (i % 5), nested: { list: [1, 2.5, 'x', null], flag: i % 2 === 0 }, text: 'café' })]);
    }
  });
  await insert(T1, 3000, 'a'); await insert(T2, 500, 'b');
}

async function clean() {
  for (const t of [T1, T2, T3].filter(Boolean)) {
    await ch.deleteBefore(t, '2100-01-01T00:00:00Z').catch(() => {});
    await db.withTenant(t, (c) => c.query('DELETE FROM events')).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = $1', [t]).catch(() => {});
  }
  await db.close();
}

test('PostgreSQL -> ClickHouse by the command line: everything copied, verified, nothing else touched', async () => {
  await seed();
  try {
    await ch.init();
    let r = await cli('--from', 'postgres', '--to', 'clickhouse', '--tenant', T1, '--batch', '400');
    assert.strictEqual(r.code, 0, r.out);
    assert.match(r.out, /RESULT: OK/); assert.strictEqual(num(r.out, 'read'), 3000); assert.strictEqual(num(r.out, 'copied'), 3000); assert.strictEqual(num(r.out, 'verified'), 3000);
    assert.strictEqual(await ch.count(T1), 3000);
    assert.strictEqual(await ch.count(T2), 0, 'the other tenant was not copied');
    // same events per day on both sides
    const day = async (s, t) => (await s.groupCounts(t, { by: 'day' })).map((g) => [g.key, g.events]);
    assert.deepStrictEqual(await day(ch, T1), await day(pg, T1));
    assert.strictEqual((await day(pg, T1)).length, 3);

    // a second run copies nothing
    r = await cli('--from', 'postgres', '--to', 'clickhouse', '--tenant', T1);
    assert.strictEqual(r.code, 0, r.out); assert.strictEqual(num(r.out, 'copied'), 0); assert.strictEqual(num(r.out, 'already there'), 3000);
    assert.strictEqual(await ch.count(T1), 3000);

    // a dry run on T2 writes nothing and says what it would do
    r = await cli('--from', 'postgres', '--to', 'clickhouse', '--tenant', T2, '--dry-run');
    assert.strictEqual(r.code, 0, r.out); assert.match(r.out, /DRY RUN/); assert.match(r.out, /would copy 500/);
    assert.strictEqual(await ch.count(T2), 0);

    // an event that arrives in PostgreSQL afterwards is picked up by a later run with --since
    await pg.insertBatch(T1, [{ source_type: 'syslog', raw: 'arrived later', received_at: '2026-10-05T00:00:00.000Z', parsed: { late: true } }]);
    r = await cli('--from', 'postgres', '--to', 'clickhouse', '--tenant', T1, '--since', '2026-10-04T00:00:00Z');
    assert.strictEqual(r.code, 0, r.out); assert.strictEqual(num(r.out, 'copied'), 1); assert.strictEqual(await ch.count(T1), 3001);

    // the copy reads back identical, field by field, for a sample (the tool already did this for every event)
    const p = (await pg.scan(T1, { limit: 50 })).events, c = (await ch.getByIds(T1, p.map((e) => e.id)));
    assert.strictEqual(c.length, 50);
    for (const e of p) assert.deepStrictEqual(c.find((x) => x.id === e.id), e);
  } catch (e) { await clean(); throw e; }
});

test('ClickHouse -> PostgreSQL: events from the same origin are not duplicated (microsecond vs millisecond), new ones are added', async () => {
  try {
    await ch.insertBatch(T1, Array.from({ length: 40 }, (_, i) => ({ source_type: 'syslog', raw: 'only in clickhouse ' + i, received_at: `2026-10-06T00:00:${String(i).padStart(2, '0')}.250Z`, parsed: { i } })));
    const before = await pg.count(T1);
    const r = await cli('--from', 'clickhouse', '--to', 'postgres', '--tenant', T1);
    assert.strictEqual(r.code, 0, r.out); assert.match(r.out, /RESULT: OK/);
    assert.strictEqual(num(r.out, 'copied'), 40, r.out);                  // only the 40 that PostgreSQL did not have
    assert.strictEqual(await pg.count(T1), before + 40, 'no duplicates of the 3,001 that came from PostgreSQL');
    const again = await cli('--from', 'clickhouse', '--to', 'postgres', '--tenant', T1);
    assert.strictEqual(num(again.out, 'copied'), 0);
  } catch (e) { await clean(); throw e; }
});

test('all tenants in one call, including an empty tenant; a bad tenant id and a missing tenant are refused', async () => {
  try {
    const res = await copyAll(pg, ch, [{ id: T1, name: 'a' }, { id: T2, name: 'b' }, { id: T3, name: 'c' }], { batch: 700 });
    assert.strictEqual(res.ok, true);
    assert.strictEqual(res.tenants[1].copied, 500); assert.strictEqual(res.tenants[2].read, 0);
    assert.strictEqual(await ch.count(T2), 500);
    let r = await cli('--from', 'postgres', '--to', 'clickhouse', '--tenant', 'not-a-uuid'); assert.strictEqual(r.code, 2);
    r = await cli('--from', 'postgres', '--to', 'clickhouse', '--tenant', crypto.randomUUID()); assert.strictEqual(r.code, 1); assert.match(r.out, /no such tenant/);
    r = await cli('--from', 'postgres', '--to', 'postgres'); assert.strictEqual(r.code, 2);
  } finally { await clean(); }
});
