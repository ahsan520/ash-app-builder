'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/parse-watch-db.test.js
// Skips itself otherwise. The unparsed-events alert on a real events table through the real event store, the real alerts table and the real
// notification dispatcher, and the watchdog's real cycle.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const assert = require('assert');
const db = require('../src/db');
const { getEventStore } = require('../src/events');
const pw = require('../src/ingestion/parse-watch');
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const box = require('../src/notifications/secret-box');

const MIN = 60000, HOUR = 3600000;
const ev = (age, parsed) => ({ source_type: 'syslog', collector_id: null, raw: 'line', parsed, received_at: new Date(Date.now() - age).toISOString() });
const bad = (age, reason) => ev(age, { _parse_error: reason });
// received `age` ago, but the event's own time says 4 hours earlier (a sender's local time read as UTC): it must still count
const skewed = (age, reason) => ({ ...bad(age, reason), event_time: new Date(Date.now() - age - 4 * HOUR).toISOString() });

async function main() {
  const stamp = Date.now();
  const T = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['pw-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['pw-b-' + stamp])).rows[0].id;
  const cfg = { threshold: 5, windowMin: 15 };
  const alerts = async (t = T) => (await db.query('SELECT id, status, severity, title, summary, group_key, rule_id, event_count, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at, id', [t, pw.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const cycle = (o = {}) => pw.runTenant(T, { cfg, ...o });
  const store = getEventStore();
  try {
    await db.query("INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,'pw-hook','webhook',true,'high',$2)", [T, box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' })]);
    // 4 unparsed in the window, plenty of fine events, old unparsed ones outside the window, another tenant with a lot: below the limit
    await store.insertBatch(T, [bad(1 * MIN, 'PARSE_TIMEOUT'), bad(2 * MIN, 'PARSE_TIMEOUT'), bad(3 * MIN, 'PARSE_FAILED'), bad(4 * MIN, 'PARSE_TIMEOUT'),
      ...Array.from({ length: 20 }, (_, i) => ev((i + 1) * 30000, { host: 'fine' })), ...Array.from({ length: 30 }, (_, i) => bad(2 * HOUR + i * MIN, 'PARSE_FAILED'))]);
    await store.insertBatch(OTHER, Array.from({ length: 40 }, (_, i) => bad((i + 1) * 10000, 'PARSE_WORKER_CRASH')));
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });

    // off: nothing, even with a lot
    assert.deepStrictEqual(await cycle({ cfg: { threshold: 0, windowMin: 15 } }), { raised: 0, closed: 0 });

    // the fifth one reaches the limit: start-up grace raises nothing, then exactly one alert with the reasons
    await store.insertBatch(T, [skewed(5 * MIN, 'PARSE_QUARANTINED')]);
    assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    let al = await alerts(); assert.strictEqual(al.length, 1);
    assert.strictEqual(al[0].status, 'open'); assert.strictEqual(al[0].severity, 'high'); assert.strictEqual(al[0].rule_id, null); assert.strictEqual(al[0].group_key, 'parser:unparsed');
    assert.strictEqual(al[0].event_count, 5); assert.strictEqual(al[0].title, 'Events stored unparsed: 5 in 15 minutes');
    assert.deepStrictEqual(al[0].details.by_reason, { PARSE_TIMEOUT: 3, PARSE_FAILED: 1, PARSE_WORKER_CRASH: 0, PARSE_QUARANTINED: 1 });
    assert.match(al[0].summary, /PARSE_TIMEOUT: 3/);
    assert.strictEqual((await alerts(OTHER)).length, 0, 'other tenant is not touched');

    // the existing dispatcher sends it once
    const sent = [];
    assert.strictEqual((await dispatcher.runTenant(T, { send: async (t, c, m) => { sent.push(m); } })).queued, 1);
    assert.strictEqual(sent[0].rule, 'Events stored unparsed');
    assert.strictEqual((await dispatcher.runTenant(T, { send: async () => { throw new Error('must not send again'); } })).queued, 0);

    // more events, acknowledged: still one alert
    await store.insertBatch(T, [skewed(1 * MIN, 'PARSE_TIMEOUT'), skewed(1 * MIN, 'PARSE_TIMEOUT')]);
    await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [al[0].id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });

    // closed by hand while still over the limit: not raised again (60 minute cooldown)
    await db.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp WHERE id = $1", [al[0].id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    // an hour later it is raised again
    await db.query("UPDATE alerts SET updated_at = localtimestamp - interval '61 minutes' WHERE id = $1", [al[0].id]);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); assert.strictEqual(al.length, 2);

    // the window moves on: below the limit closes it with an ASIX note and the marker; the next episode raises at once
    assert.deepStrictEqual(await cycle({ now: Date.now() + 40 * MIN }), { raised: 0, closed: 1 });
    al = await alerts(); assert.strictEqual(al[1].status, 'closed'); assert.strictEqual(al[1].details.closed_by, 'asix');
    const n = await notes(al[1].id); assert.strictEqual(n.length, 1); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /below the limit/);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    assert.strictEqual((await alerts()).length, 3);

    // turning it off closes the open one
    assert.deepStrictEqual(await cycle({ cfg: { threshold: 0, windowMin: 15 } }), { raised: 0, closed: 1 });

    // the watchdog's real cycle runs it too, without error (off by default: the environment variable is not set)
    delete process.env.ASIX_PARSE_ALERT_MIN_EVENTS;
    const total = await wd.runOnce({ raiseAllowed: true });
    assert.strictEqual(total.errors, 0);
    process.env.ASIX_PARSE_ALERT_MIN_EVENTS = '5'; process.env.ASIX_PARSE_ALERT_WINDOW_MIN = '15';
    assert.strictEqual((await wd.runOnce({ raiseAllowed: true })).errors, 0, 'on, through the real cycle');
    assert.ok((await alerts()).length >= 3);
    console.log('parse-watch-db: all checks passed');
  } finally {
    for (const t of ['notification_deliveries', 'notification_channels', 'alert_notes', 'alerts', 'events']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[T, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[T, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
