'use strict';
// No database. The switch that also sends "Resolved" messages for watchdog alerts a person closes
// (ASIX_NOTIFY_RECOVERED_MANUAL, src/notifications/recovered.js). The real queueing SQL runs in
// tests/notify-recovered-manual-db.test.js; here: the switch, the message text, the SQL's shape, and what the delivery step does.
process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const rec = require('../src/notifications/recovered');

const alert = {
  id: '11111111-1111-1111-1111-111111111111', title: 'Collector disconnected: broker-1', severity: 'high', rule_name: 'Collector disconnected',
  summary: 'broker-1 has sent nothing for 40 minutes.', status: 'closed', event_count: 0, details: {},
  first_event_at: new Date('2026-10-20T10:00:00Z'), last_event_at: new Date('2026-10-20T10:00:00Z'), created_at: new Date('2026-10-20T10:41:00Z'),
};

test('manualEnabled only for the word true, and independent of ASIX_NOTIFY_RECOVERED', () => {
  assert.strictEqual(rec.manualEnabled({}), false);
  for (const v of ['false', '', '1', 'yes', '0']) assert.strictEqual(rec.manualEnabled({ ASIX_NOTIFY_RECOVERED_MANUAL: v }), false, v);
  for (const v of ['true', 'TRUE', 'True']) assert.strictEqual(rec.manualEnabled({ ASIX_NOTIFY_RECOVERED_MANUAL: v }), true, v);
  assert.strictEqual(rec.manualEnabled({ ASIX_NOTIFY_RECOVERED: 'true' }), false, 'the Resolved switch alone does not turn it on');
  assert.strictEqual(rec.enabled({ ASIX_NOTIFY_RECOVERED_MANUAL: 'true' }), false, 'and this switch alone does not turn Resolved messages on');
});

test('the message for a close by a person says so and does not repeat the original alert text', () => {
  const m = rec.recoveredMessage(alert, rec.HAND_NOTE);
  assert.strictEqual(m.kind, 'recovered');
  assert.strictEqual(m.title, 'Resolved: Collector disconnected: broker-1');
  assert.strictEqual(m.summary, 'An analyst closed this alert in ASIX.');
  assert.notStrictEqual(m.summary, alert.summary);
  assert.strictEqual(m.status, 'closed');
  assert.strictEqual(m.id, alert.id, 'same id, so a PagerDuty dedup key resolves the same incident');
});

test('the queueing SQL: still needs a sent message, no rule, not merged; a person\'s close is gated by the switch and by the last hour', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'notifications', 'recovered.js'), 'utf8');
  const sql = src.slice(src.indexOf('INSERT INTO notification_recoveries'), src.indexOf('RETURNING id'));
  assert.match(sql, /d\.status = 'sent'/);
  assert.match(sql, /a\.rule_id IS NULL/);
  assert.match(sql, /a\.merged_into_id IS NULL/);
  assert.match(sql, /\$\{ASIX_NOTE\} OR \(\$3::boolean AND a\.updated_at > localtimestamp - interval '\$\{MANUAL_WINDOW\}'\)/);
  assert.match(src, /MANUAL_WINDOW = '1 hour'/);
  assert.match(src, /\[tenantId, enabled\(env\), manualEnabled\(env\)\]/);
});

// deliverOne is not exported; runTenant with a fake database drives it. The fake answers the queries by their text.
function withFakeDb(rows, fn) {
  const db = require('../src/db');
  const original = db.withTenant;
  const log = [];
  db.withTenant = async (tenantId, cb) => cb({
    query: async (sql, args) => {
      log.push(sql.trim().slice(0, 60));
      if (/^INSERT INTO notification_recoveries/.test(sql.trim())) return { rowCount: 0, rows: [] };
      if (/^WITH due AS/.test(sql.trim())) return { rows: [{ id: 'r1', channel_id: 'c1', alert_id: alert.id, attempts: 1 }] };
      if (/FROM notification_channels WHERE id/.test(sql)) return { rows: [{ type: 'webhook', enabled: true, notify_recovered: true, config_enc: rows.config }] };
      if (/FROM alerts WHERE id/.test(sql)) return { rows: [alert] };
      if (/FROM tenants WHERE id/.test(sql)) return { rows: [{ name: 'Home' }] };
      if (/FROM alert_notes/.test(sql)) return { rows: rows.note ? [{ body: rows.note }] : [] };
      if (/^UPDATE notification_recoveries/.test(sql.trim())) { log.push('UPDATE:' + (args && args[1] || '') + ':' + sql.match(/status = '(\w+)'/)[1]); return { rows: [] }; }
      throw new Error('unexpected query: ' + sql.slice(0, 80));
    },
  });
  return Promise.resolve(fn(log)).finally(() => { db.withTenant = original; });
}

test('delivery: a row for a person\'s close is sent while the switch is on, with the analyst text', async () => {
  const saved = process.env.ASIX_NOTIFY_RECOVERED_MANUAL; process.env.ASIX_NOTIFY_RECOVERED_MANUAL = 'true';
  try {
    const sent = [];
    await withFakeDb({ note: null, config: require('../src/notifications/secret-box').encrypt({ url: 'https://example.com/h' }) }, async (log) => {
      const r = await rec.runTenant('t1', { send: async (type, cfg, msg) => { sent.push(msg); } });
      assert.strictEqual(r.attempted, 1);
      assert.ok(log.includes('UPDATE:undefined:sent') || log.some((l) => /:sent$/.test(l)), JSON.stringify(log));
    });
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].summary, rec.HAND_NOTE);
  } finally { if (saved === undefined) delete process.env.ASIX_NOTIFY_RECOVERED_MANUAL; else process.env.ASIX_NOTIFY_RECOVERED_MANUAL = saved; }
});

test('delivery: a row queued for a person\'s close is skipped, not sent, once the switch is off; an ASIX close is unaffected', async () => {
  const saved = process.env.ASIX_NOTIFY_RECOVERED_MANUAL; delete process.env.ASIX_NOTIFY_RECOVERED_MANUAL;
  try {
    const box = require('../src/notifications/secret-box');
    const sent = [];
    await withFakeDb({ note: null, config: box.encrypt({ url: 'https://example.com/h' }) }, async (log) => {
      await rec.runTenant('t1', { send: async (t, c, m) => { sent.push(m); } });
      assert.ok(log.some((l) => /:skipped$/.test(l)), JSON.stringify(log));
    });
    assert.strictEqual(sent.length, 0);
    await withFakeDb({ note: 'The collector is connected again.', config: box.encrypt({ url: 'https://example.com/h' }) }, async () => {
      await rec.runTenant('t1', { send: async (t, c, m) => { sent.push(m); } });
    });
    assert.strictEqual(sent.length, 1); assert.strictEqual(sent[0].summary, 'The collector is connected again.');
  } finally { if (saved !== undefined) process.env.ASIX_NOTIFY_RECOVERED_MANUAL = saved; }
});

test('the manifest ships the switch off', () => {
  const y = fs.readFileSync(path.join(__dirname, '..', 'k8s', '30-asix-api.yaml'), 'utf8');
  assert.match(y, /name: ASIX_NOTIFY_RECOVERED_MANUAL\n\s+value: "false"/);
});
