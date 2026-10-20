'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/notify-recovered-manual-db.test.js
// Skips itself otherwise. The REAL watchdog raises and closes alerts, the REAL dispatcher sends; only the final send is a recorder.
// What it proves: with ASIX_NOTIFY_RECOVERED_MANUAL on, a watchdog alert that a PERSON closed (no ASIX note) is announced to the channels that
// were sent it, only when closed within the last hour; everything else that sends nothing still sends nothing.
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
  const TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rm-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rm-b-' + stamp])).rows[0].id;
  const addCollector = async (tenant, name) => (await db.query(
    "INSERT INTO collectors (tenant_id, name, platform, last_seen, watch_disconnect) VALUES ($1,$2,'linux', localtimestamp - interval '60 minutes', true) RETURNING id", [tenant, name])).rows[0].id;
  const addChannel = async (tenant, name, notifyRecovered = null) => (await db.query(
    "INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc, notify_recovered) VALUES ($1,$2,'webhook',true,'high',$3,$4) RETURNING id", [tenant, name, cfg(), notifyRecovered])).rows[0].id;
  const chA = await addChannel(TENANT, 'rm-a'), chOther = await addChannel(OTHER, 'rm-other');
  const n = (k) => k + '-' + stamp;
  const keys = ['asix', 'hand', 'handold', 'unsent', 'open', 'late', 'never', 'flagoff'];
  const c = {};
  for (const k of keys) c[k] = await addCollector(TENANT, n(k));
  c.foreign = await addCollector(OTHER, n('foreign'));

  const alertOf = async (tenant, name) => (await db.query('SELECT * FROM alerts WHERE tenant_id = $1 AND rule_name = $2 AND title = $3', [tenant, wd.RULE_NAME, 'Collector disconnected: ' + name])).rows[0];
  const byHand = (id, ageMinutes = 0) => db.query("UPDATE alerts SET status = 'closed', updated_at = localtimestamp - ($2 || ' minutes')::interval WHERE id = $1", [id, String(ageMinutes)]);   // what PATCH /v1/alerts/:id does, plus a back-dated clock
  const recRows = async (tenant = TENANT) => (await db.query('SELECT * FROM notification_recoveries WHERE tenant_id = $1 ORDER BY created_at', [tenant])).rows;
  const sent = [];
  const record = async (type, config, msg) => { if (msg.kind === 'recovered') sent.push(msg); };   // only Resolved messages matter here; a retried alert message may pass through too
  const setEnv = (resolved, manual) => {
    if (resolved === null) delete process.env.ASIX_NOTIFY_RECOVERED; else process.env.ASIX_NOTIFY_RECOVERED = resolved;
    if (manual === null) delete process.env.ASIX_NOTIFY_RECOVERED_MANUAL; else process.env.ASIX_NOTIFY_RECOVERED_MANUAL = manual;
  };

  try {
    // ---- raise outages (real watchdog) and announce them (real dispatcher); the "unsent" one never reaches the channel
    setEnv('false', null);
    assert.strictEqual((await wd.runTenant(TENANT)).raised, keys.length);
    assert.strictEqual((await wd.runTenant(OTHER)).raised, 1);
    const failUnsent = async (type, config, msg) => { if (/unsent-/.test(msg.title)) throw new Error('webhook down'); };
    await dispatcher.runTenant(TENANT, { send: failUnsent });
    await dispatcher.runTenant(OTHER, { send: record });
    sent.length = 0;
    const A = {}; for (const k of keys) A[k] = await alertOf(TENANT, n(k));
    const foreignAlert = await alertOf(OTHER, n('foreign'));

    // ---- a detection-rule alert and a merged alert, both closed by hand, both announced before; they must never send
    const rule = (await db.query("INSERT INTO detection_rules (tenant_id, name, severity, definition) VALUES ($1,'rm-rule','high','{}'::jsonb) RETURNING id", [TENANT])).rows[0].id;
    const mkSentAlert = async (ruleId, merged) => {
      const a = (await db.query("INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, status, title, summary, merged_into_id) VALUES ($1,$2,'x','high','closed','t','s',$3) RETURNING id", [TENANT, ruleId, merged])).rows[0].id;
      await db.query("INSERT INTO notification_deliveries (tenant_id, channel_id, alert_id, status) VALUES ($1,$2,$3,'sent')", [TENANT, chA, a]);
      return a;
    };
    const primary = (await db.query("INSERT INTO alerts (tenant_id, rule_name, severity, status, title) VALUES ($1,'x','high','open','p') RETURNING id", [TENANT])).rows[0].id;
    const aRule = await mkSentAlert(rule, null), aMerged = await mkSentAlert(null, primary);

    // ---- people close three of them (one three hours ago); ASIX closes one by itself when its collector comes back
    await db.query('UPDATE collectors SET last_seen = localtimestamp WHERE id = $1', [c.asix]);
    assert.deepStrictEqual(await wd.runTenant(TENANT), { raised: 0, closed: 1 });
    await byHand(A.hand.id); await byHand(A.handold.id, 180); await byHand(A.unsent.id);
    assert.strictEqual((await alertOf(TENANT, n('open'))).status, 'open');

    // ---- manual OFF (the default) with Resolved messages ON: only ASIX's own close is announced; nobody hears about the person's closes
    setEnv('true', null);
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 1);
    assert.strictEqual(sent.length, 1); assert.match(sent[0].title, /asix-/); assert.strictEqual(sent[0].summary, 'The collector is connected again.');
    sent.length = 0;
    assert.strictEqual((await recRows()).length, 1);

    // ---- manual ON: the person's recent close of an announced alert is told; the old one, the never-delivered one, the open one, the rule alert and the merged one are not
    setEnv('true', 'true');
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 1, 'only hand');
    assert.strictEqual(sent.length, 1);
    const m = sent[0];
    assert.strictEqual(m.kind, 'recovered'); assert.strictEqual(m.title, 'Resolved: Collector disconnected: ' + n('hand'));
    assert.strictEqual(m.summary, rec.HAND_NOTE); assert.strictEqual(m.status, 'closed'); assert.strictEqual(m.id, A.hand.id);
    const rows = await recRows();
    assert.strictEqual(rows.length, 2);
    const forAlert = (id) => rows.find((r) => r.alert_id === id);
    assert.strictEqual(forAlert(A.hand.id).status, 'sent');
    for (const [label, id] of [['handold (closed 3 hours ago)', A.handold.id], ['unsent (never delivered)', A.unsent.id], ['open', A.open.id], ['rule alert', aRule], ['merged alert', aMerged]]) assert.ok(!forAlert(id), label + ' sends nothing');
    // never twice
    sent.length = 0;
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 0); assert.strictEqual(sent.length, 0);

    // ---- an alert ASIX closed and a person then reopened and closed again is not announced a second time (unique per channel and alert)
    await db.query("UPDATE alerts SET status = 'open' WHERE id = $1", [A.asix.id]); await byHand(A.asix.id);
    assert.strictEqual(await rec.enqueue(TENANT), 0);

    // ---- Resolved messages must still be wanted by the channel: Never send, or off for a channel that follows the variable
    await db.query('UPDATE notification_channels SET notify_recovered = false WHERE id = $1', [chA]);
    await byHand(A.never.id);
    assert.strictEqual(await rec.enqueue(TENANT), 0, 'a channel set to Never send hears nothing, manual on or not');
    await db.query('UPDATE notification_channels SET notify_recovered = NULL WHERE id = $1', [chA]);
    setEnv('false', 'true');
    await byHand(A.flagoff.id);
    assert.strictEqual(await rec.enqueue(TENANT), 0, 'manual alone does not turn Resolved messages on for a channel that follows the variable');
    await db.query('UPDATE notification_channels SET notify_recovered = true WHERE id = $1', [chA]);
    assert.strictEqual(await rec.enqueue(TENANT), 2, 'a channel set to Always send hears about the two recent closes it was sent (never and flagoff)');
    await db.query('UPDATE notification_channels SET notify_recovered = NULL WHERE id = $1', [chA]);

    // ---- queued while manual was on, switched off before it went out: skipped with the reason, not sent
    await byHand(A.late.id);
    setEnv('true', 'true');
    assert.strictEqual(await rec.enqueue(TENANT), 1);
    setEnv('true', null);
    sent.length = 0;
    await dispatcher.runTenant(TENANT, { send: record });
    assert.ok(!sent.some((x) => /late-/.test(x.title)), 'late is not sent while manual is off');
    const lateRow = (await recRows()).find((r) => r.alert_id === A.late.id);
    assert.strictEqual(lateRow.status, 'skipped'); assert.match(lateRow.last_error, /closed by a person are off/);
    // the ASIX-closed rows queued earlier are never held back by the manual switch
    assert.strictEqual((await recRows()).find((r) => r.alert_id === A.asix.id).status, 'sent');

    // ---- the other tenant is separate: its own person-closed alert goes to its own channel only
    setEnv('true', 'true');
    await byHand(foreignAlert.id);
    sent.length = 0;
    assert.strictEqual((await dispatcher.runTenant(OTHER, { send: record })).resolved, 1);
    assert.strictEqual(sent.length, 1); assert.match(sent[0].title, /foreign-/);
    assert.deepStrictEqual((await recRows(OTHER)).map((r) => r.channel_id), [chOther]);
    assert.ok(!(await recRows()).some((r) => r.alert_id === foreignAlert.id));
    console.log('notify-recovered-manual-db: all checks passed');
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
    delete process.env.ASIX_NOTIFY_RECOVERED; delete process.env.ASIX_NOTIFY_RECOVERED_MANUAL;
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
