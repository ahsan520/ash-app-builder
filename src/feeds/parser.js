'use strict';
// Reading what a feed returned (docs/ioc-feeds.md). Pure functions: text in, indicators out. A value is accepted only when the existing IOC classifier
// (src/threat-intel/indicators.js) recognises it (address, domain, URL, hash, e-mail), written in its normal form; "hxxp://evil[.]com" is un-defanged.
// Everything else is counted as invalid and never stored. A feed with more than MAX_ITEMS indicators is refused whole rather than cut: a cut list would
// make the "expire what the feed no longer lists" step expire the wrong things.
const { classify } = require('../threat-intel/indicators');

const MAX_ITEMS = 50000;
const MAX_LINES = 400000;
const JSON_LISTS = ['indicators', 'iocs', 'data', 'items', 'results', 'values', 'observables'];
const JSON_FIELDS = ['value', 'indicator', 'ioc', 'observable', 'ip', 'ip_address', 'domain', 'hostname', 'url', 'hash', 'sha256', 'sha1', 'md5', 'email'];

const stripComment = (l) => l.replace(/^\s*(#|;|\/\/).*$/, '').replace(/\s+(#|;|\/\/)\s.*$/, '').trim();

function splitCsv(line) {
  const out = []; let cur = ''; let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',' || c === ';' || c === '\t') { out.push(cur.trim()); cur = ''; }
    else cur += c;
  }
  out.push(cur.trim());
  return out;
}

// -> { items: [{ type, value }], invalid, lines } or throws { code, message }
function parseFeed(format, body) {
  const seen = new Set(); const items = []; let invalid = 0; let lines = 0;
  const add = (raw) => {
    const c = typeof raw === 'string' ? classify(raw) : null;
    if (!c) { invalid++; return false; }
    const k = c.type + ':' + c.value;
    if (!seen.has(k)) { seen.add(k); items.push(c); if (items.length > MAX_ITEMS) throw Object.assign(new Error(`The feed has more than ${MAX_ITEMS} indicators`), { code: 'TOO_MANY_ITEMS' }); }
    return true;
  };
  if (format === 'json') {
    let data; try { data = JSON.parse(body); } catch { throw Object.assign(new Error('The feed is not valid JSON'), { code: 'BAD_FORMAT' }); }
    let list = Array.isArray(data) ? data : null;
    if (!list && data && typeof data === 'object') { for (const k of JSON_LISTS) if (Array.isArray(data[k])) { list = data[k]; break; } }
    if (!list) throw Object.assign(new Error('The JSON feed has no list of indicators (an array, or one of: ' + JSON_LISTS.join(', ') + ')'), { code: 'BAD_FORMAT' });
    for (const el of list) {
      lines++;
      if (typeof el === 'string') { add(el); continue; }
      if (el && typeof el === 'object') { const f = JSON_FIELDS.find((k) => typeof el[k] === 'string' && classify(el[k])); if (f) add(el[f]); else invalid++; continue; }
      invalid++;
    }
    return { items, invalid, lines };
  }
  const raw = String(body).split(/\r?\n/);
  if (raw.length > MAX_LINES) throw Object.assign(new Error('The feed has too many lines'), { code: 'TOO_MANY_ITEMS' });
  let first = true;
  for (const l of raw) {
    const line = stripComment(l); if (!line) continue;
    lines++;
    if (format === 'csv') {
      const cells = splitCsv(line); const hit = cells.find((c) => classify(c));
      if (hit) add(hit); else if (!first) invalid++;   // a first line with no indicator is the header
    } else add(line.split(/\s+/)[0]);
    first = false;
  }
  return { items, invalid, lines };
}

module.exports = { parseFeed, MAX_ITEMS };
