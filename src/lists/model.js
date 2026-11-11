'use strict';
// Lists (task L1, docs/lists.md): the rules that need no database. A list is a tenant object that holds values of one type (addresses, domain
// names, URLs, file hashes) and has a purpose: block (a firewall should drop these), allow (never block these) or watch (only look out for these).
// A list can publish itself as plain text at a secret address that a firewall polls (src/lists/feed.js). This file checks every value, decides what a
// block list refuses, and builds the text; src/lists/service.js does the SQL and src/gateway/routes/lists.js the HTTP.
// Every parse function returns { value } or { error: { code, message } } and never throws.
const crypto = require('crypto');

const KINDS = ['block', 'allow', 'watch'];
const ITEM_TYPES = ['ip', 'domain', 'url', 'hash'];
const EXPIRES = { never: null, '1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000, '90d': 7776000 };   // seconds
const SOURCES = ['manual', 'action'];
const LIMITS = { nameMax: 100, descMax: 500, noteMax: 200, valueMax: 2048, entriesPerList: 50000, listsPerTenant: 100, batchMax: 1000, textMax: 400000, pageMax: 200, pageDefault: 50, offsetMax: 1000000, searchMax: 100 };
// A block list refuses anything wider than this: one wrong line (0.0.0.0/0) must never reach a firewall.
const MIN_PREFIX = { 4: 8, 6: 32 };
const TOKEN_PREFIX = 'asix_lt_';
const EXPIRES_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/;   // the database clock (UTC), no zone: the form the server itself writes (see service.js)

const bad = (message, code = 'INVALID_BODY') => ({ error: { code, message } });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// ---- addresses --------------------------------------------------------------------------------------------------------------------
// Addresses are BigInts of 32 (IPv4) or 128 (IPv6) bits, so one set of functions does both families.
function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let n = 0n;
  for (let i = 1; i <= 4; i++) {
    if (m[i].length > 1 && m[i][0] === '0') return null;   // 010.1.1.1 means different things to different tools: refuse it
    const o = Number(m[i]); if (o > 255) return null;
    n = (n << 8n) | BigInt(o);
  }
  return n;
}
function parseV6(s) {
  if (!/^[0-9a-f:]+$/i.test(s) || s.includes(':::')) return null;   // no dotted-quad tail: ::ffff:1.2.3.4 is written as an IPv4 address
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const groups = (h) => (h === '' ? [] : h.split(':'));
  const head = groups(halves[0]); const tail = halves.length === 2 ? groups(halves[1]) : [];
  if ([...head, ...tail].some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  if (halves.length === 1 ? head.length !== 8 : head.length + tail.length > 7) return null;
  const all = halves.length === 1 ? head : [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  return all.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
}
function v6String(n) {
  const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = { at: -1, len: 0 };
  for (let i = 0; i < 8;) { if (g[i] !== 0) { i++; continue; } let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > best.len) best = { at: i, len: j - i }; i = j; }
  const hex = (a) => a.map((x) => x.toString(16)).join(':');
  if (best.len < 2) return hex(g);
  return hex(g.slice(0, best.at)) + '::' + hex(g.slice(best.at + best.len));
}
const v4String = (n) => [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join('.');

// "1.2.3.4", "10.0.0.0/8", "2001:db8::/32" -> { family, bits, start, end, prefix, text } or an error. Host bits of a network are cleared (10.0.0.5/24 is 10.0.0.0/24);
// a /32 or /128 is the plain address.
function parseIp(raw) {
  const s = String(raw).trim().toLowerCase();
  const slash = s.indexOf('/');
  const addr = slash === -1 ? s : s.slice(0, slash);
  const pfx = slash === -1 ? null : s.slice(slash + 1);
  const fam = addr.includes(':') ? 6 : 4;
  const n = fam === 4 ? parseV4(addr) : parseV6(addr);
  if (n === null) return bad(`${String(raw).trim().slice(0, 60)} is not an IP address or a network such as 10.1.2.0/24`, 'INVALID_VALUE');
  if (fam === 6 && n >> 32n === 0xffffn) return bad('An IPv4-mapped IPv6 address: write it as the IPv4 address', 'INVALID_VALUE');
  const bits = fam === 4 ? 32 : 128;
  let prefix = bits;
  if (pfx !== null) {
    if (!/^\d{1,3}$/.test(pfx) || Number(pfx) > bits) return bad(`The network size /${pfx.slice(0, 5)} is not valid for an IPv${fam} address`, 'INVALID_VALUE');
    prefix = Number(pfx);
  }
  const host = BigInt(bits - prefix);
  const start = (n >> host) << host;
  const end = start | ((1n << host) - 1n);
  const base = fam === 4 ? v4String(start) : v6String(start);
  return { value: { family: fam, bits, start, end, prefix, text: prefix === bits ? base : `${base}/${prefix}` } };
}

const range = (s) => { const r = parseIp(s).value; return { start: r.start, end: r.end, family: r.family }; };
// Addresses that never belong on any list (nothing can be meant by blocking them), and the private ones a block list refuses unless its owner says otherwise.
const NEVER = [range('0.0.0.0/8'), range('127.0.0.0/8'), range('224.0.0.0/4'), range('240.0.0.0/4'), range('::/128'), range('::1/128'), range('ff00::/8')];
const PRIVATE = [range('10.0.0.0/8'), range('172.16.0.0/12'), range('192.168.0.0/16'), range('169.254.0.0/16'), range('100.64.0.0/10'), range('fc00::/7'), range('fe80::/10')];
const overlaps = (a, b) => a.family === b.family && a.start <= b.end && b.start <= a.end;

// ---- names, URLs, hashes -----------------------------------------------------------------------------------------------------------
function parseDomain(raw) {
  let s = String(raw).trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (/[^\x21-\x7e]/.test(s)) return bad('A domain name uses ASCII letters only: write an international name in its xn-- form', 'INVALID_VALUE');
  if (s.includes('*')) return bad('Write the name without a star (example.com); whether subdomains are covered depends on the firewall', 'INVALID_VALUE');
  const labels = s.split('.');
  if (s.length > 253 || labels.length < 2 || labels.some((l) => !/^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l))) return bad(`${s.slice(0, 80)} is not a full domain name such as example.com`, 'INVALID_VALUE');
  if (/^\d+$/.test(labels[labels.length - 1])) return bad('That looks like an IP address: use a list of addresses for it', 'INVALID_VALUE');
  return { value: { text: s } };
}
function parseUrl(raw) {
  const s = String(raw).trim();
  if (!/^https?:\/\//i.test(s) || /[\s\x00-\x1f\x7f]/.test(s)) return bad('A URL starts with http:// or https:// and has no spaces', 'INVALID_VALUE');
  let u; try { u = new URL(s); } catch { return bad('That is not a valid URL', 'INVALID_VALUE'); }
  if (u.username || u.password) return bad('A URL with a user name or password is refused (it would publish the secret)', 'INVALID_VALUE');
  if (!u.hostname) return bad('That URL has no host name', 'INVALID_VALUE');
  u.hash = '';
  return { value: { text: u.href } };
}
function parseHash(raw) {
  const s = String(raw).trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(s) || ![32, 40, 64].includes(s.length)) return bad('A file hash is 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hexadecimal characters', 'INVALID_VALUE');
  return { value: { text: s } };
}

// One value of a list, checked and written in its one normal form. `list` is { kind, item_type, allow_private }.
// Returns { value: { text, ip? } } or an error; a block list refuses what could cut the network off (docs/lists.md, "What a block list refuses").
function normalizeValue(list, raw) {
  if (typeof raw !== 'string') return bad('A value must be text', 'INVALID_VALUE');
  const t = raw.trim();
  if (!t) return bad('A value cannot be empty', 'INVALID_VALUE');
  if (t.length > LIMITS.valueMax) return bad(`A value can be at most ${LIMITS.valueMax} characters`, 'INVALID_VALUE');
  switch (list.item_type) {
    case 'ip': {
      const r = parseIp(t); if (r.error) return r;
      const ip = r.value;
      if (list.kind === 'block' && ip.prefix < MIN_PREFIX[ip.family]) return bad(`${ip.text} is too wide for a block list (the widest is /${MIN_PREFIX[ip.family]} for IPv${ip.family}): one wrong line would cut off a large part of the internet`, 'TOO_WIDE');
      if (NEVER.some((n) => overlaps(ip, n))) return bad(`${ip.text} is a loopback, unspecified, multicast or reserved address: it cannot go on a list`, 'NOT_LISTABLE');
      if (list.kind === 'block') {
        if (!list.allow_private && PRIVATE.some((p) => overlaps(ip, p))) return bad(`${ip.text} is a private address. A block list refuses those unless it is set to allow private addresses`, 'PRIVATE_ADDRESS');
      }
      return { value: { text: ip.text, ip } };
    }
    case 'domain': { const r = parseDomain(t); return r.error ? r : { value: { text: r.value.text } }; }
    case 'url': { const r = parseUrl(t); return r.error ? r : { value: { text: r.value.text } }; }
    case 'hash': { const r = parseHash(t); return r.error ? r : { value: { text: r.value.text } }; }
    default: return bad('Unknown item type', 'INVALID_VALUE');
  }
}

// Do two values of the same type cover each other? Addresses: the ranges overlap. Names: equal, or one is a subdomain of the other (an allowed name covers
// its subdomains, and a blocked parent would include an allowed subdomain). URLs and hashes: equal only. Used to keep a block list from taking in
// something an allow list protects.
function covers(itemType, a, b) {
  if (itemType === 'ip') { const x = parseIp(a).value; const y = parseIp(b).value; return !!x && !!y && overlaps(x, y); }
  if (itemType === 'domain') return a === b || a.endsWith('.' + b) || b.endsWith('.' + a);
  return a === b;
}

// A matcher for one allow set: makeAllowMatcher('ip', [{ list_name, value }]) -> (value) => the row that covers it, or null. Built once per request, so a batch of
// 1000 values against a large allow set parses each allow entry once.
function makeAllowMatcher(itemType, rows) {
  if (itemType === 'ip') {
    const parsed = rows.map((r) => ({ r, ip: parseIp(r.value).value })).filter((x) => x.ip);
    return (value) => { const v = parseIp(value).value; if (!v) return null; const hit = parsed.find((x) => overlaps(v, x.ip)); return hit ? hit.r : null; };
  }
  if (itemType === 'domain') {
    const by = new Map(rows.map((r) => [r.value, r]));
    return (value) => {
      for (let d = value; ; ) { if (by.has(d)) return by.get(d); const i = d.indexOf('.'); if (i === -1) break; d = d.slice(i + 1); }   // the value, or a parent of it, is allowed
      return rows.find((r) => r.value.endsWith('.' + value)) || null;                                                        // or an allowed subdomain of it
    };
  }
  const by = new Map(rows.map((r) => [r.value, r]));
  return (value) => by.get(value) || null;
}

// ---- list bodies -------------------------------------------------------------------------------------------------------------------
function parseName(v) {
  if (typeof v !== 'string' || !v.trim() || v.trim().length > LIMITS.nameMax || /[\x00-\x1f\x7f]/.test(v)) return bad(`The name must be 1 to ${LIMITS.nameMax} characters`);
  return { value: v.trim() };
}
function parseDescription(v) {
  if (v === null || v === '') return { value: null };
  if (typeof v !== 'string' || v.trim().length > LIMITS.descMax || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(v)) return bad(`The description can be at most ${LIMITS.descMax} characters`);
  return { value: v.trim() || null };
}
function parseCreate(body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const known = ['name', 'kind', 'item_type', 'description', 'allow_private'];
  const extra = Object.keys(body).find((k) => !known.includes(k));
  if (extra) return bad(`Unknown field: ${extra.slice(0, 40)}`);
  const name = parseName(body.name); if (name.error) return name;
  if (!KINDS.includes(body.kind)) return bad(`kind must be one of ${KINDS.join(', ')}`);
  if (!ITEM_TYPES.includes(body.item_type)) return bad(`item_type must be one of ${ITEM_TYPES.join(', ')}`);
  const description = parseDescription(has(body, 'description') ? body.description : null); if (description.error) return description;
  if (has(body, 'allow_private') && typeof body.allow_private !== 'boolean') return bad('allow_private must be true or false');
  if (body.allow_private && body.item_type !== 'ip') return bad('allow_private only applies to a list of IP addresses');
  return { value: { name: name.value, kind: body.kind, item_type: body.item_type, description: description.value, allow_private: !!body.allow_private } };
}
// kind and item_type never change after creation (entries were checked against them); name, description and allow_private may.
function parsePatch(body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['name', 'description', 'allow_private'].includes(k));
  if (extra) return bad(`${extra.slice(0, 40)} cannot be changed`);
  const out = {};
  if (has(body, 'name')) { const r = parseName(body.name); if (r.error) return r; out.name = r.value; }
  if (has(body, 'description')) { const r = parseDescription(body.description); if (r.error) return r; out.description = r.value; }
  if (has(body, 'allow_private')) { if (typeof body.allow_private !== 'boolean') return bad('allow_private must be true or false'); out.allow_private = body.allow_private; }
  return Object.keys(out).length ? { value: out } : bad('Nothing to change');
}

// body: { values: [text...] } or { text: "one per line" }, plus note and expires (a key of EXPIRES) or expires_at (an exact time, used by undo).
function parseEntriesBody(body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['values', 'text', 'note', 'expires', 'expires_at'].includes(k));
  if (extra) return bad(`Unknown field: ${extra.slice(0, 40)}`);
  let values;
  if (has(body, 'values') && has(body, 'text')) return bad('Send values or text, not both');
  if (has(body, 'values')) {
    if (!Array.isArray(body.values) || !body.values.length || body.values.length > LIMITS.batchMax || body.values.some((x) => typeof x !== 'string')) return bad(`values must be a list of 1 to ${LIMITS.batchMax} texts`);
    values = body.values;
  } else if (has(body, 'text')) {
    if (typeof body.text !== 'string' || body.text.length > LIMITS.textMax) return bad('text must be text of one value per line');
    values = splitLines(body.text);
    if (!values.length) return bad('There is no value in the text');
    if (values.length > LIMITS.batchMax) return bad(`At most ${LIMITS.batchMax} values at a time`);
  } else return bad('Send values (a list) or text (one value per line)');
  const note = parseNote(has(body, 'note') ? body.note : null); if (note.error) return note;
  if (has(body, 'expires') && has(body, 'expires_at')) return bad('Send expires or expires_at, not both');
  let expires = { never: true };
  if (has(body, 'expires_at')) { const r = parseExpiresAt(body.expires_at); if (r.error) return r; expires = { at: r.value }; }
  else if (has(body, 'expires')) { const r = parseExpires(body.expires); if (r.error) return r; expires = r.value; }
  return { value: { values: [...new Set(values.map((x) => x.trim()).filter(Boolean))], note: note.value, expires } };
}
function splitLines(text) {
  return text.split(/\r?\n/).map((l) => l.replace(/\s+#.*$/, '').trim()).filter((l) => l && !l.startsWith('#') && !l.startsWith(';'));
}
function parseNote(v) {
  if (v === null || v === '') return { value: null };
  if (typeof v !== 'string' || v.trim().length > LIMITS.noteMax || /[\x00-\x1f\x7f]/.test(v)) return bad(`The note can be at most ${LIMITS.noteMax} characters on one line`);
  return { value: v.trim() || null };
}
// -> { value: { never: true } | { seconds } }
function parseExpires(v) {
  if (typeof v !== 'string' || !has(EXPIRES, v)) return bad(`expires must be one of ${Object.keys(EXPIRES).join(', ')}`);
  return { value: EXPIRES[v] === null ? { never: true } : { seconds: EXPIRES[v] } };
}
function parseExpiresAt(v) {
  if (typeof v !== 'string' || !EXPIRES_AT_RE.test(v) || Number.isNaN(Date.parse(v + 'Z'))) return bad('expires_at must look like 2026-12-31T23:59:59 (server clock, UTC)');
  return { value: v };
}
function parseRemoveBody(body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  if (Object.keys(body).some((k) => k !== 'values')) return bad('Only values can be sent');
  if (!Array.isArray(body.values) || !body.values.length || body.values.length > LIMITS.batchMax || body.values.some((x) => typeof x !== 'string' || !x.trim())) return bad(`values must be a list of 1 to ${LIMITS.batchMax} texts`);
  return { value: { values: [...new Set(body.values.map((x) => x.trim()))] } };
}
function parseEntriesQuery(q) {
  const out = { q: null, limit: LIMITS.pageDefault, offset: 0, expired: false };
  if (q.q !== undefined) { if (typeof q.q !== 'string' || q.q.length > LIMITS.searchMax) return bad(`q can be at most ${LIMITS.searchMax} characters`, 'INVALID_QUERY'); out.q = q.q.trim() || null; }
  if (q.limit !== undefined) { const n = Number(q.limit); if (!Number.isInteger(n) || n < 1 || n > LIMITS.pageMax) return bad(`limit must be 1 to ${LIMITS.pageMax}`, 'INVALID_QUERY'); out.limit = n; }
  if (q.offset !== undefined) { const n = Number(q.offset); if (!Number.isInteger(n) || n < 0 || n > LIMITS.offsetMax) return bad('offset is not valid', 'INVALID_QUERY'); out.offset = n; }
  if (q.expired !== undefined) { if (q.expired !== 'true' && q.expired !== 'false') return bad('expired must be true or false', 'INVALID_QUERY'); out.expired = q.expired === 'true'; }
  return { value: out };
}

// ---- the published text ------------------------------------------------------------------------------------------------------------
// One value per line, sorted, no comments (a firewall reads every line as a value), a final newline when there is anything.
function feedText(values) {
  if (!values.length) return '';
  return [...values].sort().join('\n') + '\n';
}
const etagOf = (body) => '"' + crypto.createHash('sha256').update(body).digest('hex').slice(0, 32) + '"';

const newToken = () => TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');
const tokenShape = (t) => typeof t === 'string' && t.startsWith(TOKEN_PREFIX) && /^[A-Za-z0-9_-]{43}$/.test(t.slice(TOKEN_PREFIX.length));

module.exports = {
  KINDS, ITEM_TYPES, EXPIRES, SOURCES, LIMITS, MIN_PREFIX, TOKEN_PREFIX,
  parseIp, normalizeValue, covers, makeAllowMatcher, parseCreate, parsePatch, parseEntriesBody, parseRemoveBody, parseEntriesQuery, parseExpires, parseExpiresAt, parseNote, splitLines,
  feedText, etagOf, newToken, hashToken, tokenShape,
};
