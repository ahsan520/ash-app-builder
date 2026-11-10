'use strict';
// License notices (docs/licensing.md). A security product must not lose protection quietly, so when a license is about to expire, enters its grace period, is nearly out of grace, and
// when it has lapsed, ASIX sends ONE message per stage through every notification channel every tenant has set up (Slack, e-mail, webhook, ...), whether or not the notifications
// feature is licensed: it is sent here directly, not through the alert queue. Each stage is recorded (stage + expiry date) so it is sent once; a renewal starts the series again.
// If every send fails the stage is not recorded and the next cycle tries again; a failure never stops the platform.
const db = require('../db');
const modules = require('../modules');
const box = require('../notifications/secret-box');
const { buildMessage, sendToChannel } = require('../notifications/senders');

const EVERY_MS = 60 * 60 * 1000;

// The stage a license is in, or null when nothing needs saying. key = stage + expiry date, so a renewed license starts the series again.
function stageOf(lic) {
  if (!lic || !lic.expires_at) return null;
  const day = String(lic.expires_at).slice(0, 10), who = lic.customer ? ' for ' + lic.customer : '';
  if (lic.status === 'valid' && lic.expiring) {
    const d = lic.days_left, step = d <= 1 ? 1 : d <= 7 ? 7 : 14;
    return { key: 'expiring-' + step + '|' + day, severity: step === 1 ? 'high' : 'medium', title: 'ASIX license expires in ' + Math.max(d, 0) + ' day' + (d === 1 ? '' : 's'),
      summary: 'The ASIX license' + who + ' expires on ' + day + '. After a 30 day grace period search, reports and alerts stop; data collection continues. Ask your supplier for a renewal.' };
  }
  if (lic.status === 'grace') {
    const used = (lic.grace_days || 30) - lic.grace_days_left, week = Math.floor(used / 7), last = lic.grace_days_left <= 1;
    return { key: (last ? 'grace-last' : 'grace-w' + week) + '|' + day, severity: 'high', title: 'ASIX license has expired: ' + lic.grace_days_left + ' day' + (lic.grace_days_left === 1 ? '' : 's') + ' of grace left',
      summary: 'The ASIX license' + who + ' expired on ' + day + '. Everything still works for ' + lic.grace_days_left + ' more day' + (lic.grace_days_left === 1 ? '' : 's') + '. After that search, reports and alerts STOP and you will not be alerted to attacks; data collection continues and nothing is deleted. Renew now.' };
  }
  if (lic.status === 'expired') {
    return { key: 'lapsed|' + day, severity: 'critical', title: 'ASIX license lapsed: search, reports and alerts have stopped',
      summary: 'The ASIX license' + who + ' expired on ' + day + ' and its grace period is over. Search, reports, detections and alerts are OFF: you are not being alerted to attacks. Data collection continues and nothing is deleted. Install a renewed license to switch everything back on at once.' };
  }
  return null;
}

async function channels() {
  const out = [];
  for (const t of (await db.query("SELECT id, name FROM tenants WHERE status = 'active'")).rows) {
    const rows = await db.withTenant(t.id, async (c) => (await c.query('SELECT type, config_enc FROM notification_channels WHERE enabled')).rows);
    for (const ch of rows) out.push({ tenant: t.name, type: ch.type, config_enc: ch.config_enc });
  }
  return out;
}

// deps: { snapshot, channels, send, now } for tests.
async function runOnce(deps = {}) {
  const snap = await (deps.snapshot || (() => modules.snapshot()))();
  const st = stageOf(snap.license); if (!st) return { stage: null };
  const done = (await db.query('SELECT 1 FROM license_notices WHERE stage = $1', [st.key])).rows.length > 0;
  if (done) return { stage: st.key, sent: 0, skipped: 'already sent' };
  const list = await (deps.channels || channels)();
  let sent = 0, failed = 0;
  for (const ch of list) {
    try {
      const msg = buildMessage({ id: st.key, title: st.title, severity: st.severity, rule_name: 'ASIX license', summary: st.summary, status: 'open', event_count: 1, first_event_at: new Date(), last_event_at: new Date(), created_at: new Date(), details: {} }, { tenantName: ch.tenant, baseUrl: process.env.ASIX_PUBLIC_URL });
      await (deps.send || sendToChannel)(ch.type, deps.plain ? ch.config_enc : box.decrypt(ch.config_enc), msg, deps.sendDeps); sent += 1;
    } catch (e) { failed += 1; console.error('[license] notice not delivered:', String(e && e.message || e).slice(0, 200)); }
  }
  if (list.length === 0 || sent > 0) { await db.query('INSERT INTO license_notices (stage, detail) VALUES ($1, $2) ON CONFLICT DO NOTHING', [st.key, st.title + ' (' + sent + ' sent, ' + failed + ' failed)']); }
  return { stage: st.key, sent, failed };
}

let timer = null, running = false;
function start() {
  if (timer || process.env.LICENSE_NOTICES_ENABLED === 'false') return;
  const tick = async () => { if (running || !box.configured()) return; running = true; try { const r = await runOnce(); if (r.sent || r.failed) console.log('[license] notice', JSON.stringify(r)); } catch (e) { console.error('[license] notice cycle failed:', e.message); } finally { running = false; } };
  setTimeout(tick, 60000).unref(); timer = setInterval(tick, EVERY_MS); timer.unref();
}

module.exports = { start, runOnce, stageOf, EVERY_MS };
