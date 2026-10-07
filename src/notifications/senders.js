'use strict';
// Delivery of one alert to one channel: Slack, generic webhook (json / Teams / PagerDuty) or email.
// `deps.guard === false` exists for tests only (lets them target 127.0.0.1); the API never sets it.

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const net = require('net');
const nodemailer = require('nodemailer');
const { guardedLookup, resolveAllowed, checkUrl } = require('./net-guard');

const iso = (v) => (v ? new Date(v).toISOString() : null);
const one = (s, n = 200) => String(s ?? '').replace(/[\r\n\t]+/g, ' ').slice(0, n);

function buildMessage(alert, { tenantName, baseUrl, isTest } = {}) {
  const base = baseUrl && !String(baseUrl).startsWith('__') ? String(baseUrl).replace(/\/$/, '') : null;
  let details = alert.details || {};
  if (JSON.stringify(details).length > 4000) details = { truncated: true };
  return {
    id: alert.id, title: one(alert.title, 300), severity: alert.severity, rule: one(alert.rule_name, 255), summary: one(alert.summary, 1500),
    status: alert.status, eventCount: alert.event_count, firstEventAt: iso(alert.first_event_at), lastEventAt: iso(alert.last_event_at),
    createdAt: iso(alert.created_at), details, tenant: tenantName || '', url: base ? `${base}/portal/#/incidents` : null, isTest: !!isTest,
  };
}
const testMessage = (opts) => buildMessage({ id: crypto.randomUUID(), title: 'ASIX test notification', severity: 'low', rule_name: 'Notification test',
  summary: 'This is a test message sent from ASIX Settings > Notification channels. No action is needed.', status: 'open', event_count: 1,
  first_event_at: new Date(), last_event_at: new Date(), created_at: new Date(), details: {} }, { ...opts, isTest: true });

// ---- HTTP ----------------------------------------------------------------------------
function post(urlStr, headers, body, deps = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = deps.guard === false ? new URL(urlStr) : checkUrl(urlStr); } catch (e) { return reject(e); }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: u.pathname + u.search, method: 'POST',
      headers: { 'User-Agent': 'ASIX-Notifier/1.0', ...headers, 'Content-Length': Buffer.byteLength(body) },
      timeout: 10000, agent: false, lookup: deps.guard === false ? undefined : guardedLookup,
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (data.length < 2000) data += c; });
      res.on('end', () => (res.statusCode >= 200 && res.statusCode < 300
        ? resolve({ status: res.statusCode })
        : reject(new Error(`HTTP ${res.statusCode}${data ? ': ' + one(data, 160) : ''}`))));   // redirects are not followed
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('Request timed out after 10s'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.end(body);
  });
}

// ---- Slack ---------------------------------------------------------------------------
const mrkdwn = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const EMOJI = { critical: ':rotating_light:', high: ':red_circle:', medium: ':large_orange_circle:', low: ':large_blue_circle:' };
function slackPayload(m) {
  return {
    text: `[${m.severity.toUpperCase()}] ${m.title}`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: `${EMOJI[m.severity] || ''} ${m.title}`.slice(0, 150), emoji: true } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Severity*\n${m.severity}` }, { type: 'mrkdwn', text: `*Rule*\n${mrkdwn(m.rule)}` },
        { type: 'mrkdwn', text: `*Events*\n${m.eventCount}` }, { type: 'mrkdwn', text: `*Status*\n${m.status}` }] },
      ...(m.summary ? [{ type: 'section', text: { type: 'mrkdwn', text: mrkdwn(m.summary).slice(0, 2900) } }] : []),
      ...(m.url ? [{ type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Open in ASIX' }, url: m.url }] }] : []),
    ],
  };
}
const sendSlack = (cfg, m, deps) => post(cfg.webhook_url, { 'Content-Type': 'application/json' }, JSON.stringify(slackPayload(m)), deps);

// ---- Generic webhook -----------------------------------------------------------------
const PD_SEV = { critical: 'critical', high: 'error', medium: 'warning', low: 'info' };
function webhookPayload(cfg, m, action = 'trigger') {
  if (cfg.format === 'teams') {
    return { type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', contentUrl: null, content: {
      $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4',
      body: [
        { type: 'TextBlock', size: 'Large', weight: 'Bolder', wrap: true, text: `[${m.severity.toUpperCase()}] ${m.title}` },
        { type: 'FactSet', facts: [{ title: 'Severity', value: m.severity }, { title: 'Rule', value: m.rule }, { title: 'Events', value: String(m.eventCount) },
          { title: 'Status', value: m.status }, ...(m.tenant ? [{ title: 'Tenant', value: m.tenant }] : [])] },
        ...(m.summary ? [{ type: 'TextBlock', wrap: true, text: m.summary }] : []),
      ],
      actions: m.url ? [{ type: 'Action.OpenUrl', title: 'Open in ASIX', url: m.url }] : [],
    } }] };
  }
  if (cfg.format === 'pagerduty') {
    const p = { routing_key: cfg.routing_key, event_action: action, dedup_key: `asix-${m.id}` };
    if (action === 'trigger') {
      p.payload = { summary: `[${m.severity.toUpperCase()}] ${m.title}`.slice(0, 1024), source: m.tenant ? `ASIX (${m.tenant})` : 'ASIX', severity: PD_SEV[m.severity] || 'info',
        component: m.rule, custom_details: { summary: m.summary, event_count: m.eventCount, first_event_at: m.firstEventAt, last_event_at: m.lastEventAt, details: m.details } };
      if (m.url) p.links = [{ href: m.url, text: 'Open in ASIX' }];
    }
    return p;
  }
  return { event: 'alert.created', sent_at: new Date().toISOString(), test: m.isTest || undefined, tenant: { name: m.tenant },
    alert: { id: m.id, title: m.title, severity: m.severity, status: m.status, rule_name: m.rule, summary: m.summary, event_count: m.eventCount,
      first_event_at: m.firstEventAt, last_event_at: m.lastEventAt, url: m.url, details: m.details } };
}
async function sendWebhook(cfg, m, deps) {
  const send = (payload) => {
    const body = JSON.stringify(payload), headers = { ...(cfg.headers || {}), 'Content-Type': 'application/json' };
    if (cfg.signing_secret) {
      const ts = String(Math.floor(Date.now() / 1000));
      headers['X-ASIX-Timestamp'] = ts;
      headers['X-ASIX-Signature'] = 'sha256=' + crypto.createHmac('sha256', cfg.signing_secret).update(`${ts}.${body}`).digest('hex');
    }
    return post(cfg.url, headers, body, deps);
  };
  await send(webhookPayload(cfg, m));
  if (cfg.format === 'pagerduty' && m.isTest) await send(webhookPayload(cfg, m, 'resolve'));   // a test must not leave an open incident
}

// ---- Email ---------------------------------------------------------------------------
const h = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const SEV_COLOR = { critical: '#d1242f', high: '#e16f24', medium: '#bf8700', low: '#0969da' };
function emailContent(m) {
  const rows = [['Severity', m.severity], ['Rule', m.rule], ['Events', m.eventCount], ['Status', m.status], ['First event (UTC)', m.firstEventAt], ['Last event (UTC)', m.lastEventAt], ['Tenant', m.tenant]].filter((r) => r[1] !== '' && r[1] != null);
  const text = [`[${m.severity.toUpperCase()}] ${m.title}`, '', m.summary, '', ...rows.map(([k, v]) => `${k}: ${v}`), ...(m.url ? ['', `Open in ASIX: ${m.url}`] : [])].join('\n');
  const html = `<div style="font-family:system-ui,Arial,sans-serif;max-width:640px"><div style="border-left:6px solid ${SEV_COLOR[m.severity] || '#555'};padding:6px 14px"><h2 style="margin:0 0 4px">${h(m.title)}</h2><div style="color:#555">${h(m.summary)}</div></div>`
    + `<table style="border-collapse:collapse;margin-top:12px">${rows.map(([k, v]) => `<tr><td style="padding:3px 14px 3px 0;color:#666">${h(k)}</td><td>${h(v)}</td></tr>`).join('')}</table>`
    + (m.url ? `<p><a href="${h(m.url)}">Open in ASIX</a></p>` : '') + '</div>';
  return { text, html };
}
async function sendEmail(cfg, m, deps = {}) {
  const addr = deps.guard === false ? cfg.host : await resolveAllowed(cfg.host);     // connect to the vetted IP, verify TLS against the name
  const transport = nodemailer.createTransport({
    host: addr, port: cfg.port, secure: cfg.security === 'tls', requireTLS: cfg.security === 'starttls', ignoreTLS: cfg.security === 'none',
    auth: cfg.username ? { user: cfg.username, pass: cfg.password } : undefined, name: 'asix',
    tls: { servername: net.isIP(cfg.host) ? undefined : cfg.host, rejectUnauthorized: !cfg.allow_self_signed },
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 20000,
  });
  const c = emailContent(m);
  try {
    await transport.sendMail({ from: cfg.from, to: cfg.to, subject: one(`[ASIX][${m.severity.toUpperCase()}] ${m.title}`, 200), text: c.text, html: c.html });
  } finally { transport.close(); }
}

function sendToChannel(type, cfg, message, deps = {}) {
  if (type === 'slack') return sendSlack(cfg, message, deps);
  if (type === 'webhook') return sendWebhook(cfg, message, deps);
  if (type === 'email') return sendEmail(cfg, message, deps);
  return Promise.reject(new Error('Unknown channel type ' + type));
}

module.exports = { buildMessage, testMessage, sendToChannel, slackPayload, webhookPayload, emailContent };
