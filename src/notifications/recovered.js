'use strict';
// "Resolved" notifications. When ASIX itself closes one of its own alerts because the problem went away (collector
// connected again, events arriving again, key rotated, unparsed events stopped, ...), the people who were told about
// the alert get one short message saying so. PagerDuty channels get a real `resolve`, so the incident closes by itself.
//
//   enqueue  - a closed alert gets one row in notification_recoveries per channel that was SENT its original message
//              (a channel that never heard about the alert is not told it is over), UNIQUE per channel+alert
//   deliver  - due rows are claimed, sent outside any DB transaction, then marked sent / retried (same schedule as
//              src/notifications/dispatcher.js)
//
// Which alerts count: closed, no detection rule behind them (watchdog alerts only), not merged into another alert, and
// carrying a note written by ASIX itself (author_id NULL, author_name 'ASIX', not the "Merged ..." note of the dedupe
// tool). An alert an analyst closed by hand has no such note, so it sends nothing - unless ASIX_NOTIFY_RECOVERED_MANUAL is
// "true", which also counts a watchdog alert that a person closed within the last hour (see manualEnabled). Called from the
// dispatcher cycle.
//
// Off until ASIX_NOTIFY_RECOVERED is "true" (k8s/30-asix-api.yaml), so deploying this changes nothing by itself. A channel can
// override that: notification_channels.notify_recovered is NULL (follow the variable), true (always) or false (never); a channel
// set to true or false is only told about alerts closed after that setting was made (notify_recovered_at).

const db = require('../db');
const box = require('./secret-box');
const { buildMessage, sendToChannel } = require('./senders');

const MAX_ATTEMPTS = 5;
const BACKOFF_SECONDS = [60, 300, 900, 3600];
const BATCH = 50;
const CONCURRENCY = 5;

const enabled = (env = process.env) => String(env.ASIX_NOTIFY_RECOVERED || '').toLowerCase() === 'true';

// Off by default: an alert a person closes sends nothing. With ASIX_NOTIFY_RECOVERED_MANUAL = "true", a watchdog alert that a
// person closed (no ASIX note on it) also gets the Resolved message, so a channel that was told "broker-1 is down" hears that
// someone dealt with it and a PagerDuty incident closes. It only widens WHICH alerts count; a channel still has to want
// Resolved messages (channelWants) and to have been sent the original alert.
const manualEnabled = (env = process.env) => String(env.ASIX_NOTIFY_RECOVERED_MANUAL || '').toLowerCase() === 'true';

// A person's close is only announced shortly after it happens, so switching the setting on does not send a day of old closes.
const MANUAL_WINDOW = '1 hour';
const HAND_NOTE = 'An analyst closed this alert in ASIX.';

// Does a channel get Resolved messages? Its own setting wins; with none (NULL) the server-wide variable decides.
const channelWants = (setting, env = process.env) => (setting === true || setting === false ? setting : enabled(env));

// The message a channel gets. Same shape as an alert message (so every sender keeps working) with kind 'recovered':
// the title says Resolved, the summary is ASIX's own closing note, and the status is closed.
function recoveredMessage(alert, note, ctx = {}) {
  const m = buildMessage({ ...alert, title: `Resolved: ${alert.title}`, summary: note || alert.summary || 'ASIX closed this alert.', status: 'closed' }, ctx);
  m.kind = 'recovered';
  return m;
}

const ASIX_NOTE = `EXISTS (SELECT 1 FROM alert_notes n WHERE n.alert_id = a.id AND n.author_id IS NULL AND n.author_name = 'ASIX' AND n.body NOT LIKE 'Merged %')`;

async function enqueue(tenantId, env = process.env) {
  return db.withTenant(tenantId, async (client) => (await client.query(
    `INSERT INTO notification_recoveries (tenant_id, channel_id, alert_id)
     SELECT d.tenant_id, d.channel_id, a.id
     FROM alerts a
     JOIN notification_deliveries d ON d.alert_id = a.id AND d.tenant_id = a.tenant_id AND d.status = 'sent'
     JOIN notification_channels c ON c.id = d.channel_id AND c.enabled AND COALESCE(c.notify_recovered, $2::boolean)
       AND (c.notify_recovered_at IS NULL OR a.updated_at >= c.notify_recovered_at)   -- a channel switched on later hears only about alerts closed after that
     WHERE a.tenant_id = $1 AND a.status = 'closed' AND a.rule_id IS NULL AND a.merged_into_id IS NULL
       AND a.updated_at > localtimestamp - interval '1 day'
       AND (${ASIX_NOTE} OR ($3::boolean AND a.updated_at > localtimestamp - interval '${MANUAL_WINDOW}'))   -- closed by a person: only when switched on, and only if recent
     ON CONFLICT (channel_id, alert_id) DO NOTHING
     RETURNING id`, [tenantId, enabled(env), manualEnabled(env)])).rowCount);
}

async function claim(tenantId) {
  return db.withTenant(tenantId, async (client) => (await client.query(
    `WITH due AS (
       SELECT id FROM notification_recoveries
       WHERE tenant_id = $1 AND status = 'pending' AND next_attempt_at <= localtimestamp
       ORDER BY next_attempt_at LIMIT ${BATCH} FOR UPDATE SKIP LOCKED)
     UPDATE notification_recoveries d
        SET attempts = d.attempts + 1, next_attempt_at = localtimestamp + interval '2 minutes'   -- lease: a crash mid-send is retried later
       FROM due WHERE d.id = due.id
     RETURNING d.id, d.channel_id, d.alert_id, d.attempts`, [tenantId])).rows);
}

async function load(tenantId, d) {
  return db.withTenant(tenantId, async (client) => {
    const ch = (await client.query('SELECT type, enabled, notify_recovered, config_enc FROM notification_channels WHERE id = $1', [d.channel_id])).rows[0];
    const al = (await client.query('SELECT * FROM alerts WHERE id = $1', [d.alert_id])).rows[0];
    const tn = (await client.query('SELECT name FROM tenants WHERE id = $1', [tenantId])).rows[0];
    const note = (await client.query(
      `SELECT body FROM alert_notes WHERE alert_id = $1 AND author_id IS NULL AND author_name = 'ASIX' AND body NOT LIKE 'Merged %' ORDER BY created_at DESC LIMIT 1`, [d.alert_id])).rows[0];
    return { ch, al, note: note && note.body, tenantName: tn && tn.name };
  });
}

const finish = (tenantId, id, sql, args) => db.withTenant(tenantId, (client) => client.query(sql, [id, ...args]));

async function deliverOne(tenantId, d, deps) {
  try {
    const { ch, al, note, tenantName } = await load(tenantId, d);
    if (!ch || !al || !ch.enabled) return finish(tenantId, d.id, "UPDATE notification_recoveries SET status = 'skipped', last_error = $2 WHERE id = $1", [ch ? 'channel disabled' : 'channel or alert removed']);
    // Switched off after the row was queued (the channel's own setting, or the variable it follows): not sent.
    if (!channelWants(ch.notify_recovered, deps.env)) return finish(tenantId, d.id, "UPDATE notification_recoveries SET status = 'skipped', last_error = $2 WHERE id = $1", ['resolved messages are off for this channel']);
    // No ASIX note means a person closed it; if that is switched off now (it was on when the row was queued), do not send.
    if (!note && !manualEnabled(deps.env)) return finish(tenantId, d.id, "UPDATE notification_recoveries SET status = 'skipped', last_error = $2 WHERE id = $1", ['resolved messages for alerts closed by a person are off']);
    const message = recoveredMessage(al, note || HAND_NOTE, { tenantName, baseUrl: process.env.ASIX_PUBLIC_URL });
    await (deps.send || sendToChannel)(ch.type, box.decrypt(ch.config_enc), message, deps.sendDeps);
    return finish(tenantId, d.id, "UPDATE notification_recoveries SET status = 'sent', sent_at = localtimestamp, last_error = NULL WHERE id = $1", []);
  } catch (err) {
    const msg = String(err && err.message || err).slice(0, 300);
    if (d.attempts >= MAX_ATTEMPTS) return finish(tenantId, d.id, "UPDATE notification_recoveries SET status = 'failed', last_error = $2 WHERE id = $1", [msg]);
    const wait = BACKOFF_SECONDS[Math.min(d.attempts - 1, BACKOFF_SECONDS.length - 1)];
    return finish(tenantId, d.id, 'UPDATE notification_recoveries SET last_error = $2, next_attempt_at = localtimestamp + ($3 * interval \'1 second\') WHERE id = $1', [msg, wait]);
  }
}

async function runTenant(tenantId, deps = {}) {
  const queued = await enqueue(tenantId, deps.env);
  const due = await claim(tenantId);
  for (let i = 0; i < due.length; i += CONCURRENCY) await Promise.all(due.slice(i, i + CONCURRENCY).map((d) => deliverOne(tenantId, d, deps)));
  return { queued, attempted: due.length };
}

module.exports = { enabled, manualEnabled, channelWants, recoveredMessage, enqueue, runTenant, MAX_ATTEMPTS, HAND_NOTE };
