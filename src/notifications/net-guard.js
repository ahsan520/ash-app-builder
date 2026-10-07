'use strict';
// SSRF protection for outbound notifications. Admins choose the target of a webhook / SMTP
// host, so the API must not be usable to reach the cluster's internals or cloud metadata.
//   always blocked : loopback, link-local (incl. 169.254.169.254), unspecified, multicast, reserved
//   blocked unless NOTIFY_ALLOW_PRIVATE_TARGETS=true : RFC1918, CGNAT, ULA, documentation ranges
// Checked when a channel is saved, again before sending, and at connect time (DNS-rebinding safe).

const dns = require('dns');
const net = require('net');

const allowPrivate = () => process.env.NOTIFY_ALLOW_PRIVATE_TARGETS === 'true';

const ip4 = (s) => s.split('.').reduce((a, o) => a * 256 + Number(o), 0);
const in4 = (n, base, bits) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(ip4(base) / 2 ** (32 - bits));
const V4_ALWAYS = [['0.0.0.0', 8], ['127.0.0.0', 8], ['169.254.0.0', 16], ['192.0.0.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]];
const V4_PRIVATE = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10], ['198.18.0.0', 15], ['192.0.2.0', 24], ['198.51.100.0', 24], ['203.0.113.0', 24]];

function expandV6(ip) {
  let s = ip.split('%')[0].toLowerCase(), tail = [];
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) { const n = ip4(m[2]); tail = [(n >>> 16).toString(16), (n & 0xffff).toString(16)]; s = m[1] + '0:0'; }
  const [head, rest] = s.split('::');
  const h = head ? head.split(':') : [], r = rest !== undefined ? (rest ? rest.split(':') : []) : null;
  const parts = r === null ? h : [...h, ...Array(8 - h.length - r.length).fill('0'), ...r];
  const out = parts.map((x) => parseInt(x || '0', 16));
  if (tail.length) { out[6] = parseInt(tail[0], 16); out[7] = parseInt(tail[1], 16); }
  return out;
}

// -> 'ok' | 'private' | 'blocked'
function classify(ip) {
  if (net.isIPv4(ip)) {
    const n = ip4(ip);
    if (V4_ALWAYS.some(([b, bits]) => in4(n, b, bits))) return 'blocked';
    if (V4_PRIVATE.some(([b, bits]) => in4(n, b, bits))) return 'private';
    return 'ok';
  }
  if (net.isIPv6(ip)) {
    const g = expandV6(ip);
    if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return classify(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`); // ::ffff:a.b.c.d
    if (g.every((x) => x === 0) || (g.slice(0, 7).every((x) => x === 0) && g[7] === 1)) return 'blocked';  // :: and ::1
    if ((g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xff00) === 0xff00) return 'blocked';                          // fe80::/10, ff00::/8
    if (g[0] === 0x64 && g[1] === 0xff9b) return 'blocked';                                                  // NAT64
    if ((g[0] & 0xfe00) === 0xfc00) return 'private';                                                        // fc00::/7
    return 'ok';
  }
  return 'blocked';
}
const addressAllowed = (ip) => { const c = classify(ip); return c === 'ok' || (c === 'private' && allowPrivate()); };

const blockedError = (what) => Object.assign(new Error(`${what} resolves to a blocked address (internal/loopback/link-local targets are not allowed)`), { code: 'EBLOCKED' });

// Resolve a hostname and return an allowed address (throws EBLOCKED otherwise).
async function resolveAllowed(host) {
  if (net.isIP(host)) { if (!addressAllowed(host)) throw blockedError(host); return host; }
  const all = await dns.promises.lookup(host, { all: true });
  if (!all.length || all.some((a) => !addressAllowed(a.address))) throw blockedError(host);
  return all[0].address;
}

// net/http `lookup` hook: validates at connect time, so DNS rebinding cannot swap in an internal IP.
function guardedLookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!addrs.length || addrs.some((a) => !addressAllowed(a.address))) return cb(blockedError(hostname));
    return options && options.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
  });
}

// Static URL checks (no DNS): scheme, credentials, literal IPs.
function checkUrl(raw, { requireHttps = true } = {}) {
  let u;
  try { u = new URL(String(raw)); } catch { throw Object.assign(new Error('Not a valid URL'), { code: 'EBADURL' }); }
  if (u.username || u.password) throw Object.assign(new Error('URLs with embedded credentials are not allowed'), { code: 'EBADURL' });
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (!requireHttps || allowPrivate()))) {
    throw Object.assign(new Error(allowPrivate() || !requireHttps ? 'URL must start with http:// or https://' : 'URL must start with https://'), { code: 'EBADURL' });
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !addressAllowed(host)) throw blockedError(host);
  if (/^localhost$/i.test(host)) throw blockedError(host);
  return u;
}

module.exports = { classify, addressAllowed, resolveAllowed, guardedLookup, checkUrl };
