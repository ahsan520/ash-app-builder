'use strict';
// No database. The message a "Resolved" notification carries and what every channel type does with it
// (src/notifications/recovered.js, src/notifications/senders.js). The real HTTP sender runs against a local server.
const test = require('node:test');
const assert = require('assert');
const http = require('http');
const rec = require('../src/notifications/recovered');
const { buildMessage, slackPayload, webhookPayload, emailContent, sendToChannel } = require('../src/notifications/senders');

const alert = {
  id: '11111111-1111-1111-1111-111111111111', title: 'Collector disconnected: broker-1', severity: 'high', rule_name: 'Collector disconnected',
  summary: 'broker-1 has sent nothing for 40 minutes.', status: 'open', event_count: 0, details: { collector: 'broker-1' },
  first_event_at: new Date('2026-10-19T10:00:00Z'), last_event_at: new Date('2026-10-19T10:00:00Z'), created_at: new Date('2026-10-19T10:41:00Z'),
};

test('enabled only for the word true', () => {
  assert.strictEqual(rec.enabled({}), false);
  assert.strictEqual(rec.enabled({ ASIX_NOTIFY_RECOVERED: 'false' }), false);
  assert.strictEqual(rec.enabled({ ASIX_NOTIFY_RECOVERED: '' }), false);
  assert.strictEqual(rec.enabled({ ASIX_NOTIFY_RECOVERED: '1' }), false);
  assert.strictEqual(rec.enabled({ ASIX_NOTIFY_RECOVERED: 'true' }), true);
  assert.strictEqual(rec.enabled({ ASIX_NOTIFY_RECOVERED: 'TRUE' }), true);
});

test('the resolved message: title, ASIX note as summary, closed, kind; the original alert is not changed', () => {
  const m = rec.recoveredMessage(alert, 'The collector is connected again.', { tenantName: 'Home', baseUrl: 'https://asix.example/' });
  assert.strictEqual(m.kind, 'recovered');
  assert.strictEqual(m.title, 'Resolved: Collector disconnected: broker-1');
  assert.strictEqual(m.summary, 'The collector is connected again.');
  assert.strictEqual(m.status, 'closed');
  assert.strictEqual(m.severity, 'high');
  assert.strictEqual(m.id, alert.id);                       // the same id: a PagerDuty dedup key closes the same incident
  assert.strictEqual(m.url, 'https://asix.example/portal/#/incidents');
  assert.strictEqual(alert.status, 'open'); assert.strictEqual(alert.title, 'Collector disconnected: broker-1');
  assert.strictEqual(buildMessage(alert).kind, undefined, 'an ordinary alert message has no kind');
  // no note: falls back to the alert's own summary, then to a plain sentence
  assert.strictEqual(rec.recoveredMessage(alert, null).summary, alert.summary);
  assert.strictEqual(rec.recoveredMessage({ ...alert, summary: null }, null).summary, 'ASIX closed this alert.');
});

test('Slack: RESOLVED tag and a check mark; an alert still says its severity', () => {
  const r = slackPayload(rec.recoveredMessage(alert, 'Back.'));
  assert.strictEqual(r.text, '[RESOLVED] Resolved: Collector disconnected: broker-1');
  assert.match(r.blocks[0].text.text, /^:white_check_mark: Resolved:/);
  const a = slackPayload(buildMessage(alert));
  assert.strictEqual(a.text, '[HIGH] Collector disconnected: broker-1');
  assert.match(a.blocks[0].text.text, /^:red_circle:/);
});

test('generic webhook and Teams', () => {
  const m = rec.recoveredMessage(alert, 'Back.');
  const g = webhookPayload({ format: 'json' }, m);
  assert.strictEqual(g.event, 'alert.resolved'); assert.strictEqual(g.alert.status, 'closed'); assert.strictEqual(g.alert.title, 'Resolved: Collector disconnected: broker-1');
  assert.strictEqual(webhookPayload({ format: 'json' }, buildMessage(alert)).event, 'alert.created');
  const t = webhookPayload({ format: 'teams' }, m);
  assert.match(t.attachments[0].content.body[0].text, /^\[RESOLVED\] Resolved:/);
});

test('PagerDuty payload builder: resolve carries only the key and the dedup key', () => {
  const m = rec.recoveredMessage(alert, 'Back.');
  const p = webhookPayload({ format: 'pagerduty', routing_key: 'rk' }, m, 'resolve');
  assert.deepStrictEqual(p, { routing_key: 'rk', event_action: 'resolve', dedup_key: 'asix-' + alert.id });
  assert.strictEqual(webhookPayload({ format: 'pagerduty', routing_key: 'rk' }, buildMessage(alert)).event_action, 'trigger');
});

test('email: subject tag and body', () => {
  const c = emailContent(rec.recoveredMessage(alert, 'Back.'));
  assert.match(c.text, /^\[RESOLVED\] Resolved: Collector disconnected: broker-1/);
  assert.match(c.text, /Status: closed/);
  assert.match(emailContent(buildMessage(alert)).text, /^\[HIGH\] Collector disconnected/);
});

// the real sender over real HTTP: what a PagerDuty channel receives for an alert and for its resolution
test('sendToChannel: a PagerDuty channel gets trigger for the alert and ONE resolve (same dedup key) for the resolution', async () => {
  const got = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { got.push(JSON.parse(b)); res.statusCode = 202; res.end('{}'); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const cfg = { url: `http://127.0.0.1:${srv.address().port}/enqueue`, format: 'pagerduty', routing_key: 'rk', headers: {}, signing_secret: '' };
  try {
    await sendToChannel('webhook', cfg, buildMessage(alert), { guard: false });
    await sendToChannel('webhook', cfg, rec.recoveredMessage(alert, 'Back.'), { guard: false });
  } finally { srv.close(); }
  assert.strictEqual(got.length, 2, 'one request each, not a trigger plus a resolve for the resolution');
  assert.strictEqual(got[0].event_action, 'trigger'); assert.strictEqual(got[1].event_action, 'resolve');
  assert.strictEqual(got[0].dedup_key, got[1].dedup_key);
  assert.strictEqual(got[1].payload, undefined);
});

test('sendToChannel: a generic webhook gets alert.resolved with the signature headers still applied', async () => {
  const got = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { got.push({ h: req.headers, b: JSON.parse(b) }); res.end('ok'); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    await sendToChannel('webhook', { url: `http://127.0.0.1:${srv.address().port}/h`, format: 'json', headers: {}, signing_secret: 's3cret' }, rec.recoveredMessage(alert, 'Back.'), { guard: false });
  } finally { srv.close(); }
  assert.strictEqual(got[0].b.event, 'alert.resolved'); assert.match(got[0].h['x-asix-signature'], /^sha256=[0-9a-f]{64}$/);
});
