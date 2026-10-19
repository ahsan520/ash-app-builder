'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/notify-recovered-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected. Real queries, the REAL watchdog raising and closing alerts and the REAL
// notification dispatcher; only the final send is replaced by a recorder.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const assert = require('assert');
const db = require('../src/db');
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const rec = require('../src/notifications/recovered');
const box = require('../src/notifications/secret-box');

const cfg = () => box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' });

async function main() {
  const stamp = Date.now();
  const TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rc-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rc-b-' + stamp])).rows[0].id;
  const addCollector = async (tenant, name, minutesAgo, watch = true) => (await db.query(
    "INSERT INTO collectors (tenant_id, name, platform, last_seen, watch_disconnect) VALUES ($1,$2,'linux', localtimestamp - ($3 || ' minutes')::interval, $4) RETURNING id",
    [tenant, name, String(minutesAgo), watch])).rows[0].id;
  const addChannel = async (tenant, name, minSeverity = 'high') => (await db.query(
    "INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,$2,'webhook',true,$3,$4) RETURNING id", [tenant, name, minSeverity, cfg()])).rows[0].id;
  const chA = await addChannel(TENANT, 'rc-a'), chCrit = await addChannel(TENANT, 'rc-critical-only', 'critical'), chOther = await addChannel(OTHER, 'rc-other');
  const names = { fine: 'fine-' + stamp, flaky: 'flaky-' + stamp, hand: 'hand-' + stamp, unsent: 'unsent-' + stamp, off: 'off-' + stamp, foreign: 'foreign-' + stamp };
  const c = {};
  for (const k of ['fine', 'flaky', 'hand', 'unsent', 'off']) c[k] = await addCollector(TENANT, names[k], 60);
  c.foreign = await addCollector(OTHER, names.foreign, 60);

  const alertOf = async (tenant, name) => (await db.query("SELECT * FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND title = $3", [tenant, wd.RULE_NAME, 'Collector disconnected: ' + name])).rows[0];
  const recRows = async (tenant = TENANT) => (await db.query('SELECT r.*, c.name AS channel FROM notification_recoveries r JOIN notification_channels c ON c.id = r.channel_id WHERE r.tenant_id = $1 ORDER BY r.created_at', [tenant])).rows;
  const back = (id) => db.query('UPDATE collectors SET last_seen = localtimestamp WHERE id = $1', [id]);
  const sent = [];
  const record = async (type, config, msg) => { sent.push(msg); };

  try {
    // ---- outages raised by the real watchdog, announced by the real dispatcher (env still off)
    assert.strictEqual((await wd.runTenant(TENANT)).raised, 5);
    assert.strictEqual((await wd.runTenant(OTHER)).raised, 1);
    const unsentFail = async (type, config, msg) => { if (/unsent-/.test(msg.title)) throw new Error('webhook down'); sent.push(msg); };
    const d1 = await dispatcher.runTenant(TENANT, { send: unsentFail });
    assert.strictEqual(d1.queued, 5); assert.strictEqual(d1.resolved, 0);
    assert.strictEqual(sent.length, 4, 'four alert messages sent, the unsent one failed and stays pending');
    await dispatcher.runTenant(OTHER, { send: record });
    sent.length = 0;
    const st = async (alertId, ch = chA) => (await db.query('SELECT status FROM notification_deliveries WHERE alert_id = $1 AND channel_id = $2', [alertId, ch])).rows[0];
    assert.strictEqual((await st((await alertOf(TENANT, names.unsent)).id)).status, 'pending');
    assert.strictEqual((await st((await alertOf(TENANT, names.fine)).id)).status, 'sent');
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM notification_deliveries WHERE channel_id = $1', [chCrit])).rows[0].n, 0, 'the critical-only channel was never told');

    // ---- the problems go away: fine, flaky, unsent and foreign come back (ASIX closes them); hand is closed by an analyst; off stays open
    for (const k of ['fine', 'flaky', 'unsent']) await back(c[k]);
    await back(c.foreign);
    assert.deepStrictEqual(await wd.runTenant(TENANT), { raised: 0, closed: 3 });
    assert.deepStrictEqual(await wd.runTenant(OTHER), { raised: 0, closed: 1 });
    await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [(await alertOf(TENANT, names.hand)).id]);   // by hand: no ASIX note
    const fineAlert = await alertOf(TENANT, names.fine);
    assert.strictEqual(fineAlert.status, 'closed');
    assert.strictEqual((await alertOf(TENANT, names.off)).status, 'open');

    // ---- OFF (the default): nothing is queued or sent, whatever the alerts look like
    delete process.env.ASIX_NOTIFY_RECOVERED;
    const off = await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(off.resolved, 0); assert.strictEqual(sent.length, 0); assert.strictEqual((await recRows()).length, 0);
    process.env.ASIX_NOTIFY_RECOVERED = 'false';
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 0); assert.strictEqual(sent.length, 0);

    // ---- ON: one Resolved message per alert that ASIX closed AND that channel was sent; none for the others
    process.env.ASIX_NOTIFY_RECOVERED = 'true';
    const flakyFail = async (type, config, msg) => { if (/flaky-/.test(msg.title)) throw new Error('webhook down'); sent.push(msg); };
    const on = await dispatcher.runTenant(TENANT, { send: flakyFail });
    assert.strictEqual(on.resolved, 2, 'fine and flaky; not hand (closed by an analyst), not unsent (never delivered), not off (still open)');
    assert.strictEqual(sent.length, 1);
    const m = sent[0];
    assert.strictEqual(m.kind, 'recovered'); assert.strictEqual(m.title, 'Resolved: Collector disconnected: ' + names.fine);
    assert.strictEqual(m.summary, 'The collector is connected again.'); assert.strictEqual(m.status, 'closed'); assert.strictEqual(m.id, fineAlert.id);
    const rows = await recRows();
    assert.deepStrictEqual(rows.map((r) => r.channel), ['rc-a', 'rc-a']);
    const by = Object.fromEntries(rows.map((r) => [r.alert_id, r]));
    assert.strictEqual(by[fineAlert.id].status, 'sent'); assert.ok(by[fineAlert.id].sent_at);
    const flakyRow = by[(await alertOf(TENANT, names.flaky)).id];
    assert.strictEqual(flakyRow.status, 'pending'); assert.strictEqual(flakyRow.attempts, 1); assert.match(flakyRow.last_error, /webhook down/);
    assert.ok(new Date(flakyRow.next_attempt_at) > new Date(), 'retry is in the future');
    for (const k of ['hand', 'unsent', 'off']) assert.ok(!by[(await alertOf(TENANT, names[k])).id], k + ' gets no resolved message');

    // ---- never twice: another cycle sends nothing; the failed one waits for its time, then goes out
    sent.length = 0;
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 0); assert.strictEqual(sent.length, 0);
    await db.query('UPDATE notification_recoveries SET next_attempt_at = localtimestamp - interval \'1 second\' WHERE id = $1', [flakyRow.id]);
    await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(sent.length, 1); assert.match(sent[0].title, /^Resolved: .*flaky-/);
    const after = (await recRows()).find((r) => r.id === flakyRow.id);
    assert.strictEqual(after.status, 'sent'); assert.strictEqual(after.attempts, 2); assert.strictEqual(after.last_error, null);
    sent.length = 0;
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 0); assert.strictEqual(sent.length, 0);

    // ---- gives up after five tries, like an alert message
    await db.query("UPDATE notification_recoveries SET status = 'pending', attempts = 4, next_attempt_at = localtimestamp - interval '1 second' WHERE id = $1", [flakyRow.id]);
    await dispatcher.runTenant(TENANT, { send: async () => { throw new Error('still down'); } });
    const gaveUp = (await recRows()).find((r) => r.id === flakyRow.id);
    assert.strictEqual(gaveUp.status, 'failed'); assert.strictEqual(gaveUp.attempts, 5); assert.match(gaveUp.last_error, /still down/);

    // ---- the other tenant is separate: its own channel, its own message, nothing in this tenant's rows
    const other = await dispatcher.runTenant(OTHER, { send: record });
    assert.strictEqual(other.resolved, 1);
    assert.strictEqual(sent.length, 1); assert.match(sent[0].title, /foreign-/);
    assert.strictEqual((await recRows(OTHER)).length, 1); assert.strictEqual((await recRows(OTHER))[0].channel_id, chOther);
    assert.strictEqual((await recRows()).length, 2);
    // row-level security is on with the same policy as the other tenant tables (the test user is a superuser, which bypasses it, so check the definition)
    const pol = (await db.query("SELECT c.relrowsecurity, (SELECT count(*)::int FROM pg_policies p WHERE p.tablename = 'notification_recoveries' AND p.policyname = 'notification_recoveries_tenant_isolation') AS policies FROM pg_class c WHERE c.relname = 'notification_recoveries'")).rows[0];
    assert.strictEqual(pol.relrowsecurity, true); assert.strictEqual(pol.policies, 1);
    // one row per channel and alert
    await assert.rejects(db.query('INSERT INTO notification_recoveries (tenant_id, channel_id, alert_id) VALUES ($1,$2,$3)', [TENANT, chA, fineAlert.id]), (e) => e.code === '23505');

    // ---- a channel switched off before the message goes out: skipped, not sent; a channel that never got the alert is never told
    sent.length = 0;
    await back(c.off);
    assert.deepStrictEqual(await wd.runTenant(TENANT), { raised: 0, closed: 1 });
    await db.query('UPDATE notification_channels SET enabled = false WHERE id = $1', [chA]);
    assert.strictEqual(await rec.enqueue(TENANT), 0, 'a disabled channel is not queued');
    await db.query('UPDATE notification_channels SET enabled = true WHERE id = $1', [chA]);
    assert.strictEqual(await rec.enqueue(TENANT), 1);
    await db.query('UPDATE notification_channels SET enabled = false WHERE id = $1', [chA]);
    await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(sent.length, 0);
    const skipped = (await recRows()).find((r) => r.status === 'skipped');
    assert.ok(skipped && /disabled/.test(skipped.last_error));
    await db.query('UPDATE notification_channels SET enabled = true WHERE id = $1', [chA]);

    // ---- other kinds of closed alerts send nothing: an alert merged into another one, and one with a detection rule behind it
    const rule = (await db.query("INSERT INTO detection_rules (tenant_id, name, severity, definition) VALUES ($1,'rc-rule','high','{}'::jsonb) RETURNING id", [TENANT])).rows[0].id;
    const mk = async (ruleId, merged, note) => {
      const a = (await db.query("INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, status, title, summary, merged_into_id) VALUES ($1,$2,'x','high','closed','t','s',$3) RETURNING id", [TENANT, ruleId, merged])).rows[0].id;
      await db.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1,$2,NULL,'ASIX',$3)", [TENANT, a, note]);
      await db.query("INSERT INTO notification_deliveries (tenant_id, channel_id, alert_id, status) VALUES ($1,$2,$3,'sent')", [TENANT, chA, a]);
      return a;
    };
    const primary = (await db.query("INSERT INTO alerts (tenant_id, rule_name, severity, status, title) VALUES ($1,'x','high','open','p') RETURNING id", [TENANT])).rows[0].id;
    const aMerged = await mk(null, primary, 'Merged 1 repeat alert into this one.'), aRule = await mk(rule, null, 'Closed by ASIX.'), aMergeNote = await mk(null, null, 'Merged 2 repeat alerts into this one by x.');
    const before = (await recRows()).length;
    assert.strictEqual(await rec.enqueue(TENANT), 0);
    assert.strictEqual((await recRows()).length, before);
    assert.ok(aMerged && aRule && aMergeNote);
    // an alert closed long ago is left alone (one day window), even with an ASIX note
    const old = await mk(null, null, 'The collector is connected again.');
    await db.query("UPDATE alerts SET updated_at = localtimestamp - interval '2 days' WHERE id = $1", [old]);
    assert.strictEqual(await rec.enqueue(TENANT), 0);
    await db.query("UPDATE alerts SET updated_at = localtimestamp WHERE id = $1", [old]);
    assert.strictEqual(await rec.enqueue(TENANT), 1, 'the same alert inside the window is queued');
    console.log('notify-recovered-db: all checks passed');
  } finally {
    await db.query('DELETE FROM notification_recoveries WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM notification_deliveries WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM notification_channels WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM alert_notes WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM detection_rules WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
    delete process.env.ASIX_NOTIFY_RECOVERED;
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
