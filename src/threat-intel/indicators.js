'use strict';
// Parsing/normalising threat indicators, and pulling candidate indicators out of log lines.
// Pure functions - no database access - so they are easy to test.

const OCT = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)';
const IPV4_SRC = `\\b${OCT}(?:\\.${OCT}){3}\\b`;
const HASH_TYPE = { 32: 'md5', 40: 'sha1', 64: 'sha256' };
const DOMAIN_SRC = '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}';
const EMAIL_SRC = '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}';

const TYPES = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'];

// "hxxp://evil[.]com" -> "http://evil.com"
function refang(s) {
  return String(s || '').trim()
    .replace(/^hxxp/i, 'http')
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[@\]|\(at\)/gi, '@');
}

// -> { type, value } (value lower-cased) or null when it is not a recognised indicator
function classify(input) {
  const v = refang(input).toLowerCase();
  if (!v || v.length > 2048) return null;
  if (/^https?:\/\/\S+$/.test(v)) return { type: 'url', value: v };
  if (/^[a-f0-9]+$/.test(v) && HASH_TYPE[v.length]) return { type: HASH_TYPE[v.length], value: v };
  if (new RegExp(`^${IPV4_SRC}$`).test(v)) return { type: 'ip', value: v };
  if (new RegExp(`^${EMAIL_SRC}$`).test(v)) return { type: 'email', value: v };
  if (new RegExp(`^${DOMAIN_SRC}$`).test(v)) return { type: 'domain', value: v };
  return null;
}

// Every indicator-looking token in a log line, as a Set of "type:value".
// Domains also yield their parent domains, so an indicator "evil.com" matches "a.b.evil.com".
function extractCandidates(raw) {
  const s = String(raw || '').toLowerCase();
  const out = new Set();
  for (const m of s.matchAll(new RegExp(IPV4_SRC, 'g'))) out.add('ip:' + m[0]);
  for (const m of s.matchAll(/\b[a-f0-9]{32,64}\b/g)) {
    const t = HASH_TYPE[m[0].length];
    if (t) out.add(t + ':' + m[0]);
  }
  for (const m of s.matchAll(/\bhttps?:\/\/[^\s"'<>]+/g)) {
    const url = m[0].replace(/[.,;)\]]+$/, '');
    out.add('url:' + url);
    // Also the URL without query/fragment and every path prefix, so an indicator
    // "http://host/path" matches "http://host/path?x=1" and "http://host/" matches anything under it.
    const bare = url.split(/[?#]/)[0];
    out.add('url:' + bare);
    const origin = bare.match(/^https?:\/\/[^/]+/)[0];
    let acc = origin;
    out.add('url:' + origin);
    for (const seg of bare.slice(origin.length).split('/').filter(Boolean)) { acc += '/' + seg; out.add('url:' + acc); }
    out.add('url:' + origin + '/');
  }
  for (const m of s.matchAll(new RegExp(`\\b${EMAIL_SRC}`, 'g'))) out.add('email:' + m[0]);
  for (const m of s.matchAll(new RegExp(`\\b${DOMAIN_SRC}\\b`, 'g'))) {
    const labels = m[0].split('.');
    for (let i = 0; i <= labels.length - 2; i++) out.add('domain:' + labels.slice(i).join('.'));
  }
  return out;
}

module.exports = { TYPES, classify, extractCandidates, refang };
