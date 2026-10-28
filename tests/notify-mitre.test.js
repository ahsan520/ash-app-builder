'use strict';
// E4j: ATT&CK in notifications (docs/endpoints.md, "E4j as built"). No real database, no network.
//   1. buildMessage and what each channel type does with the ATT&CK of an alert (Slack, Teams, PagerDuty, generic webhook, email);
//   2. the dispatcher's own delivery with a stand-in database and sender: stored ATT&CK, the event fallback, a failing store, a resolved message.
const test = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { buildMessage, slackPayload, webhookPayload, emailContent } = require('../src/notifications/senders');
const { MemoryEventStore } = require('../src/events/memory-store');
const { setEventStore } = require('../src/events');

const alert = {
  id: '11111111-1111-4111-8111-111111111111', title: 'Endpoint security alert, web-1', severity: 'high', rule_name: 'Endpoint security: high', summary: 'Rule 5763 fired.',
  status: 'open', event_count: 3, details: {}, first_event_at: new Date('2026-10-27T10:00:00Z'), last_event_at: new Date('2026-10-27T10:05:00Z'), created_at: new Date('2026-10-27T10:06:00Z'),
};
const M = { techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'T1078', name: 'Valid Accounts' }], tactics: ['Credential Access'] };
const msg = (mitre) => buildMessage(alert, { tenantName: 'Home', baseUrl: 'https://asix.example', mitre });

test('a message without ATT&CK is exactly as before: mitre is null and no channel mentions it', () => {
  for (const m of [msg(), msg(null), msg({}), msg('oops'), msg({ techniques: 'T1110', tactics: 5 })]) {
    assert.strictEqual(m.mitre, null);
    assert.ok(!/ATT&CK/.test(JSON.stringify(slackPayload(m)))); assert.ok(!/ATT&CK/.test(emailContent(m).text + emailContent(m).html));
    assert.ok(!('mitre' in webhookPayload({ format: 'json' }, m).alert)); assert.ok(!/ATT&CK/.test(JSON.stringify(webhookPayload({ format: 'teams' }, m))));
    assert.ok(!('mitre' in webhookPayload({ format: 'pagerduty', routing_key: 'k' }, m).payload.custom_details));
  }
});

test('the message carries techniques (with a link only for a well-formed id) and tactics through the safe view', () => {
  const m = msg({ techniques: [...M.techniques, { id: 'javascript:alert(1)', name: 'x' }, 5, null], tactics: ['Credential Access', 7] });
  assert.deepStrictEqual(m.mitre.techniques.map((t) => [t.id, t.url]), [['T1110', 'https://attack.mitre.org/techniques/T1110/'], ['T1078', 'https://attack.mitre.org/techniques/T1078/'], ['javascript:alert(1)', null]]);
  assert.deepStrictEqual(m.mitre.tactics, ['Credential Access']); assert.strictEqual(m.mitre.more, 0);
});

test('at most five techniques are named; the rest are counted', () => {
  const ids = ['T1110', 'T1078', 'T1565.001', 'T1059', 'T1021', 'T1548.003', 'T1003'];
  const m = msg({ techniques: ids.map((id) => ({ id, name: 'n' })), tactics: [] });
  assert.strictEqual(m.mitre.techniques.length, 5); assert.strictEqual(m.mitre.more, 2);
  assert.match(emailContent(m).text, /ATT&CK: T1110 n, T1078 n, T1565\.001 n, T1059 n, T1021 n \(\+2 more\)/);
});

test('Slack gets an ATT&CK section, escaped', () => {
  const m = msg({ techniques: [{ id: 'T1110', name: 'Brute <Force> & co' }], tactics: ['Credential Access'] });
  const sec = slackPayload(m).blocks.find((b) => b.text && /ATT&CK/.test(b.text.text));
  assert.strictEqual(sec.text.text, '*ATT&CK*\nT1110 Brute &lt;Force&gt; &amp; co; Credential Access');
});

test('Teams gets an ATT&CK fact; PagerDuty and the generic webhook carry the structure', () => {
  const m = msg(M);
  const facts = webhookPayload({ format: 'teams' }, m).attachments[0].content.body.find((b) => b.type === 'FactSet').facts;
  assert.deepStrictEqual(facts.find((f) => f.title === 'ATT&CK'), { title: 'ATT&CK', value: 'T1110 Brute Force, T1078 Valid Accounts; Credential Access' });
  const pd = webhookPayload({ format: 'pagerduty', routing_key: 'k' }, m).payload.custom_details;
  assert.deepStrictEqual(pd.mitre.tactics, ['Credential Access']); assert.strictEqual(pd.mitre.techniques[0].id, 'T1110');
  const g = webhookPayload({ format: 'json' }, m).alert;
  assert.strictEqual(g.mitre.techniques[1].url, 'https://attack.mitre.org/techniques/T1078/'); assert.deepStrictEqual(g.mitre.tactics, ['Credential Access']);
});

test('email text and html show an ATT&CK row; hostile text stays text', () => {
  const c = emailContent(msg(M));
  assert.match(c.text, /ATT&CK: T1110 Brute Force, T1078 Valid Accounts; Credential Access/);
  assert.match(c.html, /ATT&amp;CK<\/td><td>T1110 Brute Force, T1078 Valid Accounts; Credential Access<\/td>/);
  const bad = emailContent(msg({ techniques: [{ id: 'T1110', name: '<img src=x onerror=alert(1)>\r\nBcc: x@y.z' }], tactics: [] }));
  assert.ok(!/<img/.test(bad.html)); assert.ok(!/\r|\n.*Bcc/.test(bad.text.split('ATT&CK:')[1].split('\n')[0]), 'one line');
});

test('a resolved message and a test message carry no ATT&CK', () => {
  const rec = require('../src/notifications/recovered').recoveredMessage({ ...alert, details: { mitre: M } }, 'Closed by ASIX.', {});
  assert.strictEqual(rec.mitre, null);
  assert.strictEqual(require('../src/notifications/senders').testMessage().mitre, null);
});

// ---- the dispatcher ----------------------------------------------------------------------------
const TENANT = '22222222-2222-4222-8222-222222222222', EV = '44444444-4444-4444-8444-444444444444';
process.env.NOTIFY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
const box = require('../src/notifications/secret-box');
const db = require('../src/db');
const dispatcher = require('../src/notifications/dispatcher');

async function deliver(al) {
  const sent = [];
  const realWith = db.withTenant;
  db.withTenant = async (t, fn) => fn({ query: async (sql) => {
    if (/INSERT INTO notification_deliveries/.test(sql)) return { rowCount: 0, rows: [] };
    if (/WITH due AS/.test(sql)) return { rows: [{ id: 'd1', channel_id: 'c1', alert_id: al.id, attempts: 1 }] };
    if (/FROM notification_channels WHERE id/.test(sql)) return { rows: [{ type: 'webhook', enabled: true, config_enc: box.encrypt({ url: 'https://example.invalid/h' }) }] };
    if (/FROM alerts WHERE id/.test(sql)) return { rows: [al] };
    if (/FROM tenants WHERE id/.test(sql)) return { rows: [{ name: 'Home' }] };
    return { rows: [], rowCount: 0 };
  } });
  const logs = []; const realErr = console.error; console.error = (...a) => logs.push(a.join(' '));
  try { await dispatcher.runTenant(TENANT, { send: async (type, cfg, m) => { sent.push(m); } }); } finally { db.withTenant = realWith; console.error = realErr; }
  return { sent, logs };
}

test('the dispatcher sends the ATT&CK stored on the alert and does not read events for it', async () => {
  const store = new MemoryEventStore(); let reads = 0; const o = store.getByIds.bind(store); store.getByIds = async (...a) => { reads += 1; return o(...a); }; setEventStore(store);
  const { sent } = await deliver({ ...alert, details: { mitre: M, sample_event_ids: [EV] } });
  assert.strictEqual(sent.length, 1); assert.deepStrictEqual(sent[0].mitre.tactics, ['Credential Access']); assert.strictEqual(sent[0].mitre.techniques[0].id, 'T1110'); assert.strictEqual(reads, 0);
});

test('an alert with none stored takes ATT&CK from its sample events', async () => {
  const store = new MemoryEventStore();
  await store.insertBatch(TENANT, [{ id: EV, source_type: 'endpoint-alert', raw: 'x', parsed: { mitre_ids: 'T1548.003', mitre_techniques: 'Sudo', mitre_tactics: 'Privilege Escalation' }, received_at: new Date().toISOString() }]);
  setEventStore(store);
  const { sent } = await deliver({ ...alert, details: { sample_event_ids: [EV] } });
  assert.strictEqual(sent[0].mitre.techniques[0].id, 'T1548.003'); assert.deepStrictEqual(sent[0].mitre.tactics, ['Privilege Escalation']);
});

test('a failing event store or an alert with no details still sends the message, without ATT&CK', async () => {
  const store = new MemoryEventStore(); store.getByIds = async () => { throw new Error('store down'); }; setEventStore(store);
  let r = await deliver({ ...alert, details: { sample_event_ids: [EV] } });
  assert.strictEqual(r.sent.length, 1); assert.strictEqual(r.sent[0].mitre, null);
  r = await deliver({ ...alert, details: null });
  assert.strictEqual(r.sent.length, 1); assert.strictEqual(r.sent[0].mitre, null);
});
