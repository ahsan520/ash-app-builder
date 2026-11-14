'use strict';
// Starting a workflow on the automation engine (task SR3, docs/engine-callback.md): one POST to the workflow's webhook address with the run's token in the body.
// The address is a secret (it is the only credential the engine's webhook has): it is never stored in a run, never logged and never part of an error message.
// Outbound rules, like src/notifications/net-guard.js but with its OWN switch, because the engine usually lives on the private network and this must not loosen the notification rules:
//   always refused  : loopback, link-local (cloud metadata), unspecified, multicast, reserved
//   refused unless ASIX_ENGINE_ALLOW_PRIVATE=true : RFC1918, CGNAT, ULA, documentation ranges
//   https only, except http to a private address when ASIX_ENGINE_ALLOW_PRIVATE=true. The address is checked when the run is started and again at connect time (DNS rebinding).
// TLS: the engine's certificate is checked. A lab engine with its own certificate: ASIX_ENGINE_CA_FILE (a PEM file); or, lab only, ASIX_ENGINE_TLS_INSECURE=true (certificate not checked).
const dns = require('dns');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const netGuard = require('../notifications/net-guard');

const allowPrivate = () => process.env.ASIX_ENGINE_ALLOW_PRIVATE === 'true';
const TIMEOUT_MS = 15000;
const MAX_ANSWER = 4096;

const bad = (code, message) => Object.assign(new Error(message), { code });
// Whether an address is one ASIX may call. `loopback` is for the tests of this file only: it is an argument, never read from the environment.
const addressOk = (ip, loopback) => { const c = netGuard.classify(ip); return c === 'ok' || (c === 'private' && allowPrivate()) || (loopback === true && /^127\./.test(ip)); };

// Static checks (no DNS). Returns the parsed URL or throws { code: 'EBADURL' | 'EBLOCKED' } with a message that never repeats the address.
function checkTarget(raw, loopback) {
  let u; try { u = new URL(String(raw)); } catch (_) { throw bad('EBADURL', 'The webhook address is not a valid URL'); }
  if (u.username || u.password) throw bad('EBADURL', 'The webhook address must not carry a user name or password');
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (allowPrivate() || loopback === true))) throw bad('EBADURL', allowPrivate() ? 'The webhook address must start with http:// or https://' : 'The webhook address must start with https://');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (/^localhost$/i.test(host) && loopback !== true) throw bad('EBLOCKED', 'The webhook address points at a blocked network');
  if (net.isIP(host) && !addressOk(host, loopback)) throw bad('EBLOCKED', 'The webhook address points at a blocked network');
  return u;
}

const lookupFor = (loopback) => (hostname, options, cb) => {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (e, addrs) => {
    if (e) return cb(e);
    if (!addrs.length || addrs.some((a) => !addressOk(a.address, loopback))) return cb(bad('EBLOCKED', 'The webhook address points at a blocked network'));
    return options && options.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
  });
};

let warnedInsecure = false;
function tlsOptions() {
  if (process.env.ASIX_ENGINE_TLS_INSECURE === 'true') {
    if (!warnedInsecure) { warnedInsecure = true; console.error('Engine: ASIX_ENGINE_TLS_INSECURE=true, the engine certificate is NOT checked (lab only)'); }
    return { rejectUnauthorized: false };
  }
  if (process.env.ASIX_ENGINE_CA_FILE) return { ca: fs.readFileSync(process.env.ASIX_ENGINE_CA_FILE) };
  return {};
}

// POST the body to the webhook. Never throws and never rejects: { ok, status, engineRef, error }. `error` is a short fixed phrase, never the address.
// opts.loopback (tests only) lets the check pass for 127.x.
function postHook(url, body, opts) {
  const loopback = !!(opts && opts.loopback);
  return new Promise((resolve) => {
    let u;
    try { u = checkTarget(url, loopback); } catch (e) { return resolve({ ok: false, status: 0, error: e.message }); }
    let tls = {};
    try { tls = u.protocol === 'https:' ? tlsOptions() : {}; } catch (_) { return resolve({ ok: false, status: 0, error: 'The engine certificate file (ASIX_ENGINE_CA_FILE) could not be read' }); }
    const data = Buffer.from(JSON.stringify(body));
    const lib = u.protocol === 'https:' ? https : http;
    let done = false; const finish = (r) => { if (!done) { done = true; resolve(r); } };
    const req = lib.request({ protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: u.pathname + u.search, method: 'POST', lookup: lookupFor(loopback), timeout: TIMEOUT_MS, ...tls,
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length, 'User-Agent': 'asix-engine/1' } }, (res) => {
      const chunks = []; let n = 0;
      res.on('data', (c) => { n += c.length; if (n <= MAX_ANSWER) chunks.push(c); });
      res.on('end', () => {
        let ref = null;
        try { const j = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (j && typeof j.wf_exec_id === 'string') ref = j.wf_exec_id.slice(0, 200); } catch (_) { /* the answer is not JSON: no reference */ }
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        finish({ ok, status: res.statusCode, engineRef: ref, error: ok ? null : `The engine answered HTTP ${res.statusCode}` });
      });
      res.on('error', () => finish({ ok: false, status: res.statusCode || 0, error: 'The engine answer was cut off' }));
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, status: 0, error: 'The engine did not answer in time' }); });
    req.on('error', (e) => finish({ ok: false, status: 0, error: e.code === 'EBLOCKED' ? 'The webhook address points at a blocked network' : `The engine could not be reached (${String(e.code || 'error').slice(0, 30)})` }));
    req.end(data);
  });
}

module.exports = { checkTarget, postHook, addressOk, lookupFor };
