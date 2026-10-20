'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/notify-recovered-channel-db.test.js
// Skips itself otherwise. Real queries, the REAL dispatcher and the REAL notifications routes; only the sign-in chain and the final send are replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const dispatcher = require('../src/notifications/dispatcher');
const rec = require('../src/notifications/recovered');
const box = require('../src/notifications/secret-box');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };

const cfg = () => box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' });

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rcc-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rcc-b-' + stamp])).rows[0].id;
  const addChannel = async (tenant, name, setting) => (await db.query(
    "INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc, notify_recovered) VALUES ($1,$2,'webhook',true,'high',$3,$4) RETURNING id", [tenant, name, cfg(), setting])).rows[0].id;
  const chFollow = await addChannel(TENANT, 'rcc-follow', null), chOn = await addChannel(TENANT, 'rcc-on', true), chOff = await addChannel(TENANT, 'rcc-off', false);
  const chOther = await addChannel(OTHER, 'rcc-other', true);
  // an alert that ASIX closed itself, which every channel above was sent (the alert message), in the given tenant
  const closedAlert = async (tenant, title, channels) => {
    const a = (await db.query("INSERT INTO alerts (tenant_id, rule_name, severity, status, title, summary) VALUES ($1,'Collector disconnected','high','closed',$2,'s') RETURNING id", [tenant, title])).rows[0].id;
    await db.query("INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1,$2,NULL,'ASIX','The collector is connected again.')", [tenant, a]);
    for (const c of channels) await db.query("INSERT INTO notification_deliveries (tenant_id, channel_id, alert_id, status, sent_at) VALUES ($1,$2,$3,'sent',localtimestamp)", [tenant, c, a]);
    return a;
  };
  const recRows = async (alertId) => (await db.query('SELECT r.*, c.name AS channel FROM notification_recoveries r JOIN notification_channels c ON c.id = r.channel_id WHERE r.alert_id = $1 ORDER BY c.name', [alertId])).rows;
  const sent = [];
  const record = async (type, config, msg) => { sent.push(msg); };

  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/notifications'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, path, body) => { const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };

  try {
    // ---- variable OFF (the default): only the channel set to "always" is told
    delete process.env.ASIX_NOTIFY_RECOVERED;
    const a1 = await closedAlert(TENANT, 'Collector disconnected: one-' + stamp, [chFollow, chOn, chOff]);
    const r1 = await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(r1.resolved, 1, 'only rcc-on');
    assert.deepStrictEqual((await recRows(a1)).map((r) => r.channel), ['rcc-on']);
    assert.strictEqual(sent.filter((m) => m.kind === 'recovered').length, 1);
    sent.length = 0;

    // ---- variable ON: the channel that follows it joins; the one set to "never" still gets nothing
    process.env.ASIX_NOTIFY_RECOVERED = 'true';
    const r2 = await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(r2.resolved, 1, 'rcc-follow now; rcc-on already had it; rcc-off never');
    assert.deepStrictEqual((await recRows(a1)).map((r) => r.channel), ['rcc-follow', 'rcc-on']);
    assert.strictEqual(sent.length, 1);
    sent.length = 0;
    const a2 = await closedAlert(TENANT, 'Collector disconnected: two-' + stamp, [chFollow, chOn, chOff]);
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: record })).resolved, 2);
    assert.deepStrictEqual((await recRows(a2)).map((r) => r.channel), ['rcc-follow', 'rcc-on']);
    sent.length = 0;

    // ---- queued, then switched off before it goes out: skipped with the reason, not sent
    const a3 = await closedAlert(TENANT, 'Collector disconnected: three-' + stamp, [chFollow, chOn]);
    assert.strictEqual(await rec.enqueue(TENANT), 2);
    await db.query('UPDATE notification_channels SET notify_recovered = false WHERE id = $1', [chOn]);
    process.env.ASIX_NOTIFY_RECOVERED = 'false';       // and the variable that rcc-follow follows goes off too
    await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(sent.length, 0, 'nothing sent');
    const skipped = await recRows(a3);
    assert.deepStrictEqual(skipped.map((r) => r.status), ['skipped', 'skipped']);
    assert.ok(skipped.every((r) => /resolved messages are off/.test(r.last_error)));
    // a channel switched back on does not resend by itself (the row is skipped); a retry by hand does
    await db.query('UPDATE notification_channels SET notify_recovered = true WHERE id = $1', [chOn]);
    await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(sent.length, 0);
    await db.query('UPDATE notification_channels SET notify_recovered = NULL WHERE id = $1', [chFollow]);   // back to following the variable (off)
    delete process.env.ASIX_NOTIFY_RECOVERED;

    // ---- the routes: create, read back, change one thing without losing the setting
    const created = await call('POST', '/v1/notifications/channels', { name: 'rcc-new-' + stamp, type: 'webhook', config: { url: 'https://example.com/h2', format: 'json' }, notify_recovered: true });
    assert.strictEqual(created.status, 201, JSON.stringify(created.body));
    assert.strictEqual(created.body.channel.notify_recovered, true); assert.strictEqual(created.body.channel.recovered_sending, true);
    const id = created.body.channel.id;
    assert.strictEqual((await db.query('SELECT notify_recovered FROM notification_channels WHERE id = $1', [id])).rows[0].notify_recovered, true);
    const dis = await call('PATCH', '/v1/notifications/channels/' + id, { enabled: false });
    assert.strictEqual(dis.status, 200); assert.strictEqual(dis.body.channel.notify_recovered, true, 'Disable did not reset it');
    const off = await call('PATCH', '/v1/notifications/channels/' + id, { notify_recovered: false });
    assert.strictEqual(off.body.channel.notify_recovered, false); assert.strictEqual(off.body.channel.recovered_sending, false);
    const follow = await call('PATCH', '/v1/notifications/channels/' + id, { notify_recovered: null });
    assert.strictEqual(follow.body.channel.notify_recovered, null); assert.strictEqual(follow.body.channel.recovered_sending, false, 'follows the variable, which is off');
    process.env.ASIX_NOTIFY_RECOVERED = 'true';
    const listed = await call('GET', '/v1/notifications/channels');
    const by = Object.fromEntries(listed.body.channels.map((c) => [c.name, c]));
    assert.strictEqual(by['rcc-follow'].recovered_sending, true); assert.strictEqual(by['rcc-on'].recovered_sending, true); assert.strictEqual(by['rcc-off'].recovered_sending, false);
    assert.ok(!by['rcc-other'], 'another tenant\'s channel is not listed');
    delete process.env.ASIX_NOTIFY_RECOVERED;
    const bad = await call('PATCH', '/v1/notifications/channels/' + id, { notify_recovered: 'yes' });
    assert.strictEqual(bad.status, 400); assert.strictEqual(bad.body.error.code, 'INVALID_CONFIG');
    assert.strictEqual((await db.query('SELECT notify_recovered FROM notification_channels WHERE id = $1', [id])).rows[0].notify_recovered, null, 'a refused change changes nothing');

    // ---- the delivery log shows both kinds
    const log = await call('GET', '/v1/notifications/deliveries?limit=200');
    assert.strictEqual(log.status, 200);
    const kinds = log.body.deliveries.reduce((m, d) => ({ ...m, [d.kind]: (m[d.kind] || 0) + 1 }), {});
    assert.strictEqual(kinds.alert, 8, 'a1 x3, a2 x3, a3 x2'); assert.strictEqual(kinds.resolved, 6, 'a1 x2, a2 x2, a3 x2');
    assert.strictEqual(log.body.total, 14);
    assert.ok(log.body.deliveries.every((d) => d.channel_name && d.title && d.severity));
    const onlyResolved = await call('GET', '/v1/notifications/deliveries?kind=resolved&limit=200');
    assert.strictEqual(onlyResolved.body.total, 6); assert.ok(onlyResolved.body.deliveries.every((d) => d.kind === 'resolved'));
    const onlyAlerts = await call('GET', '/v1/notifications/deliveries?kind=alert&limit=200');
    assert.strictEqual(onlyAlerts.body.total, 8); assert.ok(onlyAlerts.body.deliveries.every((d) => d.kind === 'alert'));
    const skippedLog = await call('GET', '/v1/notifications/deliveries?kind=resolved&status=skipped&limit=200');
    assert.strictEqual(skippedLog.body.total, 2); assert.ok(skippedLog.body.deliveries.every((d) => /resolved messages are off/.test(d.last_error)));
    const page1 = await call('GET', '/v1/notifications/deliveries?limit=5&offset=0'), page2 = await call('GET', '/v1/notifications/deliveries?limit=5&offset=5');
    assert.strictEqual(page1.body.deliveries.length, 5); assert.strictEqual(page2.body.total, 14);
    assert.strictEqual(new Set([...page1.body.deliveries, ...page2.body.deliveries].map((d) => d.id)).size, 10, 'pages do not overlap');
    const sortedDesc = log.body.deliveries.every((d, i, all) => i === 0 || new Date(all[i - 1].created_at) >= new Date(d.created_at));
    assert.ok(sortedDesc, 'newest first');
    const foreign = await closedAlert(OTHER, 'Collector disconnected: foreign-' + stamp, [chOther]);
    await dispatcher.runTenant(OTHER, { send: record });
    assert.strictEqual((await recRows(foreign)).length, 1);
    assert.strictEqual((await call('GET', '/v1/notifications/deliveries?limit=200')).body.total, 14, 'another tenant\'s messages are not listed');

    // ---- retry a Resolved message by hand (the same Retry button): it goes back to pending and the dispatcher sends it
    process.env.ASIX_NOTIFY_RECOVERED = 'true';
    const skippedRow = skippedLog.body.deliveries.find((d) => d.channel_name === 'rcc-on');
    assert.ok(skippedRow);
    sent.length = 0;
    const retried = await call('POST', '/v1/notifications/deliveries/' + skippedRow.id + '/retry');
    assert.strictEqual(retried.status, 200);
    assert.strictEqual((await db.query('SELECT status, attempts FROM notification_recoveries WHERE id = $1', [skippedRow.id])).rows[0].status, 'pending');
    await dispatcher.runTenant(TENANT, { send: record });
    assert.strictEqual(sent.length, 1); assert.strictEqual(sent[0].kind, 'recovered');
    assert.strictEqual((await db.query('SELECT status FROM notification_recoveries WHERE id = $1', [skippedRow.id])).rows[0].status, 'sent');
    assert.strictEqual((await call('POST', '/v1/notifications/deliveries/' + skippedRow.id + '/retry')).status, 404, 'a sent message is not retryable');
    assert.strictEqual((await call('POST', '/v1/notifications/deliveries/00000000-0000-4000-8000-000000000000/retry')).status, 404);
    const foreignRow = (await db.query('SELECT id FROM notification_recoveries WHERE channel_id = $1', [chOther])).rows[0];
    await db.query("UPDATE notification_recoveries SET status = 'failed' WHERE id = $1", [foreignRow.id]);
    assert.strictEqual((await call('POST', '/v1/notifications/deliveries/' + foreignRow.id + '/retry')).status, 404, 'another tenant\'s message cannot be retried');
    assert.strictEqual((await call('POST', '/v1/notifications/deliveries/not-an-id/retry')).status, 400);
    delete process.env.ASIX_NOTIFY_RECOVERED;

    // ---- the table is missing (the schema job has not run on a new deploy): the log still lists alert messages, retry still works for them,
    //      and the dispatcher logs one line and carries on
    await db.query('ALTER TABLE notification_recoveries RENAME TO notification_recoveries_away');
    try {
      const noTable = await call('GET', '/v1/notifications/deliveries?limit=200');
      assert.strictEqual(noTable.status, 200); assert.strictEqual(noTable.body.total, 8); assert.ok(noTable.body.deliveries.every((d) => d.kind === 'alert'));
      const onlyRes = await call('GET', '/v1/notifications/deliveries?kind=resolved');
      assert.strictEqual(onlyRes.status, 200); assert.strictEqual(onlyRes.body.total, 0);
      assert.strictEqual((await call('POST', '/v1/notifications/deliveries/' + skippedRow.id + '/retry')).status, 404);
      const errs = []; const origErr = console.error; console.error = (...a) => errs.push(a.join(' '));
      try {
        const x1 = await dispatcher.runTenant(TENANT, { send: record }); await dispatcher.runTenant(TENANT, { send: record });
        assert.strictEqual(x1.resolved, 0);
      } finally { console.error = origErr; }
      assert.strictEqual(errs.filter((l) => /resolved messages failed/.test(l)).length, 1, 'logged once, not every cycle');
    } finally { await db.query('ALTER TABLE notification_recoveries_away RENAME TO notification_recoveries'); }
    // ---- cut-off: a channel set to "always" later is told only about alerts closed AFTER that moment
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const atOf = async (cid) => (await db.query('SELECT notify_recovered_at AS at FROM notification_channels WHERE id = $1', [cid])).rows[0].at;
    const cut = await call('POST', '/v1/notifications/channels', { name: 'rcc-cut-' + stamp, type: 'webhook', config: { url: 'https://example.com/h3', format: 'json' }, notify_recovered: true });
    assert.strictEqual(cut.status, 201); const cutId = cut.body.channel.id;
    const at0 = await atOf(cutId); assert.ok(at0, 'set when created with a setting');
    assert.strictEqual(await atOf(chFollow), null, 'a channel that follows has no cut-off');
    await sleep(30);
    const oldA = await closedAlert(TENANT, 'Collector disconnected: before-' + stamp, [cutId]);
    await db.query("UPDATE alerts SET updated_at = $2::timestamp - interval '1 hour' WHERE id = $1", [oldA, at0]);
    const newA = await closedAlert(TENANT, 'Collector disconnected: after-' + stamp, [cutId]);
    assert.strictEqual(await rec.enqueue(TENANT), 1, 'only the alert closed after the switch');
    assert.deepStrictEqual((await recRows(newA)).map((r) => r.channel), ['rcc-cut-' + stamp]);
    assert.strictEqual((await recRows(oldA)).length, 0, 'closed before the switch: nothing');
    // unrelated changes and the same value keep the cut-off; a new value moves it; null clears it
    await call('PATCH', '/v1/notifications/channels/' + cutId, { enabled: false }); assert.deepStrictEqual(await atOf(cutId), at0);
    await call('PATCH', '/v1/notifications/channels/' + cutId, { enabled: true, notify_recovered: true }); assert.deepStrictEqual(await atOf(cutId), at0, 'same value');
    await sleep(30);
    await call('PATCH', '/v1/notifications/channels/' + cutId, { notify_recovered: false }); const at1 = await atOf(cutId); assert.ok(at1 > at0, 'moved by a new value');
    await sleep(30);
    await call('PATCH', '/v1/notifications/channels/' + cutId, { notify_recovered: true }); const at2 = await atOf(cutId); assert.ok(at2 > at1);
    assert.strictEqual(await rec.enqueue(TENANT), 0, 'the alert from before is still before the cut-off');
    await call('PATCH', '/v1/notifications/channels/' + cutId, { notify_recovered: null }); assert.strictEqual(await atOf(cutId), null);
    process.env.ASIX_NOTIFY_RECOVERED = 'true';
    assert.strictEqual(await rec.enqueue(TENANT), 1, 'following the server setting: no cut-off, the older alert is queued');
    assert.strictEqual((await recRows(oldA)).length, 1);
    delete process.env.ASIX_NOTIFY_RECOVERED;
    console.log('notify-recovered-channel-db: all checks passed');
  } finally {
    srv.close();
    delete process.env.ASIX_NOTIFY_RECOVERED;
    await db.query('ALTER TABLE IF EXISTS notification_recoveries_away RENAME TO notification_recoveries').catch(() => {});
    for (const t of ['notification_recoveries', 'notification_deliveries', 'notification_channels', 'alert_notes', 'alerts']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
