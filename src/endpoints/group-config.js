'use strict';
// Monitored folders of an agent GROUP (docs/endpoints.md, task E10): the one part of a group's agent.conf that ASIX writes. Pure functions, no I/O.
//
// ASIX never rewrites a group's agent.conf as a whole. It owns ONE block between two marker comments and leaves every other byte alone:
//
//   <!-- ASIX:monitored-folders:begin v1 -->
//   <agent_config os="Linux"> <syscheck> <directories realtime="yes">/srv/data</directories> ... </syscheck> </agent_config>
//   <agent_config os="Windows"> ... </agent_config>
//   <!-- ASIX:monitored-folders:end -->
//
// A file whose markers are damaged or whose block was edited by hand is refused (state `broken` / `edited`) instead of guessed at. Every entry is checked against a strict alphabet
// before it can reach XML, so nothing a person types can add an element, an attribute or a second path.
const crypto = require('crypto');

const BEGIN = '<!-- ASIX:monitored-folders:begin v1 -->';
const END = '<!-- ASIX:monitored-folders:end -->';
const BEGIN_RE = /<!-- ASIX:monitored-folders:begin[^>]*-->/g;
const END_RE = /<!-- ASIX:monitored-folders:end -->/g;
const MAX_ENTRIES = 50, MAX_REALTIME = 10, MAX_PATH = 255, MAX_FILE_BYTES = 256 * 1024;
const GROUP_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const SYSTEMS = { linux: 'Linux', windows: 'Windows' };

const sha256 = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const validGroup = (g) => typeof g === 'string' && GROUP_RE.test(g) && g !== '.' && g !== '..';

// Pseudo file systems and whole drives: watching them is how an agent is brought to its knees, so they are refused rather than warned about.
const LINUX_REFUSED = ['/proc', '/sys', '/dev', '/run'];
function checkPath(system, p) {
  if (typeof p !== 'string' || !p.length) return 'A path is empty';
  if (p.length > MAX_PATH) return 'A path is longer than ' + MAX_PATH + ' characters';
  if (/[\u0000-\u001f\u007f<>&"'`$*?|;{}\[\]!#^]/.test(p)) return 'The path "' + p.slice(0, 60) + '" has a character that is not allowed (no wildcards, quotes or shell characters)';
  if (/(^|[\\/])\.\.([\\/]|$)/.test(p)) return 'The path "' + p.slice(0, 60) + '" has a ".." part';
  if (/\s$|^\s/.test(p)) return 'The path "' + p.slice(0, 60) + '" starts or ends with a space';
  if (system === 'linux') {
    if (!/^\/[A-Za-z0-9._\-+@=,~ \/]*$/.test(p)) return 'The Linux path "' + p.slice(0, 60) + '" must start with / and use letters, digits and . _ - + @ = , ~ space /';
    const norm = p.replace(/\/+$/, '') || '/';
    if (norm === '/') return 'The whole file system (/) cannot be watched';
    if (/\/\//.test(p)) return 'The path "' + p.slice(0, 60) + '" has an empty part (//)';
    for (const bad of LINUX_REFUSED) if (norm === bad || norm.startsWith(bad + '/')) return norm + ' is a system file system and cannot be watched';
    return null;
  }
  if (system === 'windows') {
    if (!/^(?:[A-Za-z]:|%[A-Za-z0-9_()]{1,40}%)(?:\\[A-Za-z0-9._\-+@=,~ ()]+)*\\?$/.test(p)) return 'The Windows path "' + p.slice(0, 60) + '" must start with a drive (C:\\) or a variable (%ProgramFiles%) and use letters, digits and . _ - + @ = , ~ space ( ) \\';
    if (/^[A-Za-z]:\\?$/.test(p)) return 'A whole drive (' + p.slice(0, 3) + ') cannot be watched';
    return null;
  }
  return 'The system must be linux or windows';
}

// entries: [{ system: 'linux'|'windows', path, realtime?: bool }] -> { ok, errors, entries } with a normalised, ordered copy (Linux first, then Windows, each by path).
function validate(input) {
  const errors = [];
  if (!Array.isArray(input)) return { ok: false, errors: ['entries must be a list'], entries: [] };
  if (input.length > MAX_ENTRIES) return { ok: false, errors: ['At most ' + MAX_ENTRIES + ' folders per group'], entries: [] };
  const out = [], seen = new Set();
  for (const e of input) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) { errors.push('Each folder must be an object { system, path, realtime? }'); continue; }
    const extra = Object.keys(e).filter((k) => !['system', 'path', 'realtime'].includes(k));
    if (extra.length) { errors.push('Unknown field "' + String(extra[0]).slice(0, 30) + '"'); continue; }
    const system = typeof e.system === 'string' ? e.system.toLowerCase() : '';
    if (!SYSTEMS[system]) { errors.push('The system of "' + String(e.path).slice(0, 40) + '" must be linux or windows'); continue; }
    if (e.realtime !== undefined && typeof e.realtime !== 'boolean') { errors.push('realtime must be true or false'); continue; }
    const bad = checkPath(system, e.path); if (bad) { errors.push(bad); continue; }
    const path = system === 'linux' ? (e.path.length > 1 ? e.path.replace(/\/+$/, '') : e.path) : e.path.replace(/\\+$/, '');
    const key = system + ':' + (system === 'windows' ? path.toLowerCase() : path);
    if (seen.has(key)) { errors.push('The folder ' + path + ' is listed twice for ' + SYSTEMS[system]); continue; }
    seen.add(key); out.push({ system, path, realtime: e.realtime === true });
  }
  if (out.filter((x) => x.realtime).length > MAX_REALTIME) errors.push('At most ' + MAX_REALTIME + ' folders can be watched in real time per group');
  out.sort((a, b) => (a.system === b.system ? (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) : a.system === 'linux' ? -1 : 1));
  return { ok: errors.length === 0, errors, entries: out };
}

function blockText(entries) {
  const lines = [BEGIN];
  for (const sys of ['linux', 'windows']) {
    const list = entries.filter((e) => e.system === sys); if (!list.length) continue;
    lines.push('<agent_config os="' + SYSTEMS[sys] + '">', '  <syscheck>');
    for (const e of list) lines.push('    <directories' + (e.realtime ? ' realtime="yes"' : '') + '>' + e.path + '</directories>');
    lines.push('  </syscheck>', '</agent_config>');
  }
  lines.push(END);
  return lines.join('\n');
}

// Finds the block in a file. { state: 'none' | 'ok' | 'broken' | 'edited', entries, start, end, text }.
function find(xml) {
  const s = String(xml || '');
  const begins = [...s.matchAll(BEGIN_RE)], ends = [...s.matchAll(END_RE)];
  if (!begins.length && !ends.length) return { state: 'none', entries: [] };
  if (begins.length !== 1 || ends.length !== 1 || ends[0].index < begins[0].index) return { state: 'broken', entries: [] };
  const start = begins[0].index, end = ends[0].index + END.length, raw = s.slice(start, end), text = raw.replace(/\r\n/g, '\n');   // a manager or an editor may have changed the line ends; the words are what count
  if (begins[0][0] !== BEGIN) return { state: 'edited', entries: [], start, end, text: raw };
  const entries = [];
  const inner = text.slice(BEGIN.length, text.length - END.length);
  const re = /\s*<agent_config os="(Linux|Windows)">\s*<syscheck>((?:\s*<directories(?: realtime="yes")?>[^<>&"']+<\/directories>)+)\s*<\/syscheck>\s*<\/agent_config>/y;
  let pos = 0;
  while (pos < inner.length && inner.slice(pos).trim() !== '') {
    re.lastIndex = pos; const m = re.exec(inner); if (!m) return { state: 'edited', entries: [], start, end, text: raw };
    for (const d of m[2].matchAll(/<directories( realtime="yes")?>([^<>&"']+)<\/directories>/g)) entries.push({ system: m[1].toLowerCase(), path: d[2], realtime: !!d[1] });
    pos = re.lastIndex;
  }
  const v = validate(entries);
  if (!v.ok || blockText(v.entries) !== text) return { state: 'edited', entries: [], start, end, text: raw };   // what we would write is not what is there: somebody changed it
  return { state: 'ok', entries: v.entries, start, end, text: raw };
}

// The file with the block set to `entries` (an empty list removes it). Everything outside the block is kept byte for byte. { ok, xml, changed } or { ok: false, code, message }.
function compose(xml, entries) {
  const cur = String(xml || '');
  if (Buffer.byteLength(cur, 'utf8') > MAX_FILE_BYTES) return { ok: false, code: 'TOO_LARGE', message: 'The group configuration is larger than ' + MAX_FILE_BYTES / 1024 + ' kB' };
  if (/\u0000/.test(cur)) return { ok: false, code: 'BAD_FILE', message: 'The group configuration has a NUL character' };
  const f = find(cur);
  if (f.state === 'broken') return { ok: false, code: 'MARKERS_BROKEN', message: 'The ASIX markers in this group\u2019s configuration are damaged (one missing, repeated or out of order). Fix or remove them on the manager first.' };
  if (f.state === 'edited') return { ok: false, code: 'BLOCK_EDITED', message: 'The ASIX block in this group\u2019s configuration was changed by hand. ASIX will not overwrite it: remove the block on the manager, or put it back as ASIX wrote it.' };
  const v = validate(entries); if (!v.ok) return { ok: false, code: 'INVALID', message: v.errors[0], errors: v.errors };
  let out;
  if (!v.entries.length) {
    if (f.state === 'none') return { ok: true, xml: cur, changed: false };
    // The reverse of adding: take away the block, the newline after it and the one blank line that adding put before it, so add then remove gives back the same file.
    let a = cur.slice(0, f.start), b = cur.slice(f.end);
    b = b.replace(/^\r?\n/, ''); if (/\n\n$/.test(a)) a = a.slice(0, -1);
    out = a + b;
  } else if (f.state === 'none') {
    out = cur + (cur.length && !/\n$/.test(cur) ? '\n' : '') + (cur.trim().length ? '\n' : '') + blockText(v.entries) + '\n';
  } else out = cur.slice(0, f.start) + blockText(v.entries) + cur.slice(f.end);
  if (Buffer.byteLength(out, 'utf8') > MAX_FILE_BYTES) return { ok: false, code: 'TOO_LARGE', message: 'The result would be larger than ' + MAX_FILE_BYTES / 1024 + ' kB' };
  return { ok: true, xml: out, changed: out !== cur };
}

// A readable difference between two lists of entries (what a person is shown before pressing Apply). Lines are the ones ASIX would write.
function diff(beforeEntries, afterEntries) {
  const a = blockText(validate(beforeEntries).entries).split('\n').filter((l) => /directories/.test(l)).map((l) => l.trim());
  const b = blockText(validate(afterEntries).entries).split('\n').filter((l) => /directories/.test(l)).map((l) => l.trim());
  const name = (entries) => entries.map((e) => ({ k: e.system + '|' + e.path, t: SYSTEMS[e.system] + ' ' + e.path + (e.realtime ? ' (real time)' : '') }));
  const A = name(validate(beforeEntries).entries), B = name(validate(afterEntries).entries), ka = new Map(A.map((x) => [x.k, x.t])), kb = new Map(B.map((x) => [x.k, x.t]));
  const added = B.filter((x) => !ka.has(x.k)).map((x) => x.t), removed = A.filter((x) => !kb.has(x.k)).map((x) => x.t);
  const changed = B.filter((x) => ka.has(x.k) && ka.get(x.k) !== x.t).map((x) => ka.get(x.k) + '  ->  ' + x.t);
  const same = B.filter((x) => ka.has(x.k) && ka.get(x.k) === x.t).length;
  return { added, removed, changed, same, lines_before: a.length, lines_after: b.length };
}

module.exports = { BEGIN, END, MAX_ENTRIES, MAX_REALTIME, MAX_PATH, MAX_FILE_BYTES, GROUP_RE, validGroup, checkPath, validate, blockText, find, compose, diff, sha256 };
