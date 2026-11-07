'use strict';
// Linux log files and the systemd journal of an agent GROUP (docs/endpoints.md, task E13): the third block ASIX writes into a group's agent.conf, next to the monitored folders (E10)
// and the Windows event channels (E11). Pure functions, no I/O; the calls to the manager are in group-linuxlog-service.js.
//
//   <!-- ASIX:linux-logs:begin v1 -->
//   <agent_config os="Linux">
//     <localfile> <log_format>syslog</log_format> <location>/var/log/app/*.log</location> </localfile>
//     <localfile> <log_format>journald</log_format> <location>journald</location> </localfile>
//   </agent_config>
//   <!-- ASIX:linux-logs:end -->
//
// Entries: { type: 'file', path } (a log file or a glob, read as plain text lines) and { type: 'journald' } (the whole journal, at most one). The markers are different from the other
// two blocks, so none of them sees another. A path is checked hard: it is written into a file that tells every Linux machine of a group what to read as root.
const crypto = require('crypto');

const BEGIN = '<!-- ASIX:linux-logs:begin v1 -->';
const END = '<!-- ASIX:linux-logs:end -->';
const BEGIN_RE = /<!-- ASIX:linux-logs:begin[^>]*-->/g;
const END_RE = /<!-- ASIX:linux-logs:end -->/g;
const MAX_ENTRIES = 20, MAX_FILE_BYTES = 256 * 1024, MAX_PATH = 200;
const PATH_RE = /^\/[A-Za-z0-9._\/*?[\]-]{1,199}$/;   // absolute; plain characters and the glob characters * ? [ ]
// Places that are never log files, and files that hold secrets: refused even though they are absolute plain paths.
const DENY = [/^\/(proc|sys|dev|boot|run\/secrets)(\/|$)/, /^\/etc\/(shadow|gshadow|sudoers|ssh\/ssh_host)/, /(^|\/)\.ssh(\/|$)/, /(^|\/)id_(rsa|dsa|ecdsa|ed25519)/, /\.(pem|key|p12|pfx|kdbx)$/i, /(^|\/)\.(bash_history|netrc|pgpass)$/, /^\/root\/\./];

const sha256 = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const unesc = (s) => String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

function pathProblem(p) {
  if (typeof p !== 'string') return 'A path must be text';
  if (!PATH_RE.test(p) || p.length > MAX_PATH) return 'The path \u201c' + p.slice(0, 40) + '\u201d is not valid (absolute, letters, digits and . _ / - * ? [ ], up to ' + MAX_PATH + ')';
  if (p.split('/').some((x) => x === '..' || x === '.')) return 'The path \u201c' + p.slice(0, 40) + '\u201d has a . or .. part';
  if (p.includes('//') || p === '/' || p.endsWith('/')) return 'The path \u201c' + p.slice(0, 40) + '\u201d must name files, not a folder (end it with a file name or a pattern such as *.log)';
  if (DENY.some((re) => re.test(p))) return 'The path \u201c' + p.slice(0, 40) + '\u201d is not a place logs are read from here (system, secrets and key files are refused)';
  return null;
}

// entries -> { ok, errors, entries } normalised: files sorted and each once, the journal at most once and first.
function validateEntries(input) {
  if (!Array.isArray(input)) return { ok: false, errors: ['entries must be a list'], entries: [] };
  if (input.length > MAX_ENTRIES) return { ok: false, errors: ['At most ' + MAX_ENTRIES + ' entries per group'], entries: [] };
  const errors = [], files = new Set(); let journal = false;
  for (const e of input) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) { errors.push('Each entry must be an object'); continue; }
    const extra = Object.keys(e).filter((k) => k !== 'type' && k !== 'path'); if (extra.length) { errors.push('Unknown field \u201c' + extra[0].slice(0, 20) + '\u201d in an entry'); continue; }
    if (e.type === 'journald') { if (e.path !== undefined) errors.push('The journal has no path'); journal = true; continue; }
    if (e.type !== 'file') { errors.push('An entry type is file or journald'); continue; }
    const bad = pathProblem(e.path); if (bad) { errors.push(bad); continue; }
    files.add(e.path);
  }
  const out = [...(journal ? [{ type: 'journald' }] : []), ...[...files].sort().map((path) => ({ type: 'file', path }))];
  if (out.length > MAX_ENTRIES) errors.push('At most ' + MAX_ENTRIES + ' entries per group');
  return { ok: errors.length === 0, errors, entries: out };
}

function blockText(entries) {
  const lines = [BEGIN, '<agent_config os="Linux">'];
  for (const e of entries) lines.push('  <localfile>', e.type === 'journald' ? '    <log_format>journald</log_format>\n    <location>journald</location>' : '    <log_format>syslog</log_format>\n    <location>' + esc(e.path) + '</location>', '  </localfile>');
  lines.push('</agent_config>', END);
  return lines.join('\n');
}

// { state: 'none' | 'ok' | 'broken' | 'edited', entries, start, end, text }; `ok` means exactly the shape ASIX writes (read by its words, so a manager's re-indenting is fine).
function find(xml) {
  const s = String(xml || ''), begins = [...s.matchAll(BEGIN_RE)], ends = [...s.matchAll(END_RE)];
  if (!begins.length && !ends.length) return { state: 'none', entries: [] };
  if (begins.length !== 1 || ends.length !== 1 || ends[0].index < begins[0].index) return { state: 'broken', entries: [] };
  const start = begins[0].index, end = ends[0].index + END.length, raw = s.slice(start, end), text = raw.replace(/\r\n/g, '\n');
  const edited = { state: 'edited', entries: [], start, end, text: raw };
  if (begins[0][0] !== BEGIN) return edited;
  const wrap = /^\s*<agent_config os="Linux">([\s\S]*)<\/agent_config>\s*$/.exec(text.slice(BEGIN.length, text.length - END.length)); if (!wrap) return edited;
  const one = /\s*<localfile>\s*<log_format>(syslog|journald)<\/log_format>\s*<location>([^<>]*)<\/location>\s*<\/localfile>/y;
  const entries = []; let pos = 0; const body = wrap[1];
  while (pos < body.length && body.slice(pos).trim() !== '') {
    one.lastIndex = pos; const m = one.exec(body); if (!m) return edited;
    const loc = unesc(m[2]);
    if (m[1] === 'journald') { if (loc !== 'journald') return edited; entries.push({ type: 'journald' }); }
    else { if (pathProblem(loc)) return edited; entries.push({ type: 'file', path: loc }); }
    pos = one.lastIndex;
  }
  const keys = entries.map((e) => e.type + ':' + (e.path || ''));
  if (!entries.length || entries.length > MAX_ENTRIES || new Set(keys).size !== keys.length || entries.filter((e) => e.type === 'journald').length > 1) return edited;
  return { state: 'ok', entries, start, end, text: raw };
}

// The file with the block set to `entriesIn` (an empty list removes it); every byte outside the block is kept. { ok, xml, changed } or { ok: false, code, message }.
function compose(xml, entriesIn) {
  const cur = String(xml || '');
  if (Buffer.byteLength(cur, 'utf8') > MAX_FILE_BYTES) return { ok: false, code: 'TOO_LARGE', message: 'The group configuration is larger than ' + MAX_FILE_BYTES / 1024 + ' kB' };
  if (/\u0000/.test(cur)) return { ok: false, code: 'BAD_FILE', message: 'The group configuration has a NUL character' };
  const f = find(cur);
  if (f.state === 'broken') return { ok: false, code: 'MARKERS_BROKEN', message: 'The ASIX markers for Linux logs in this group\u2019s configuration are damaged (one missing, repeated or out of order). Fix or remove them on the manager first.' };
  if (f.state === 'edited') return { ok: false, code: 'BLOCK_EDITED', message: 'The ASIX block for Linux logs in this group\u2019s configuration was changed by hand. ASIX will not overwrite it: remove the block on the manager, or put it back as ASIX wrote it.' };
  const v = validateEntries(entriesIn); if (!v.ok) return { ok: false, code: 'INVALID', message: v.errors[0], errors: v.errors };
  let out;
  if (!v.entries.length) {
    if (f.state === 'none') return { ok: true, xml: cur, changed: false };
    let a = cur.slice(0, f.start).replace(/[ \t]+$/, ''), b = cur.slice(f.end).replace(/^\r?\n/, ''); if (/\n\n$/.test(a)) a = a.slice(0, -1);
    out = a + b;
  } else if (f.state === 'none') out = cur + (cur.length && !/\n$/.test(cur) ? '\n' : '') + (cur.trim().length ? '\n' : '') + blockText(v.entries) + '\n';
  else out = cur.slice(0, f.start).replace(/[ \t]+$/, '') + blockText(v.entries) + cur.slice(f.end);
  if (Buffer.byteLength(out, 'utf8') > MAX_FILE_BYTES) return { ok: false, code: 'TOO_LARGE', message: 'The result would be larger than ' + MAX_FILE_BYTES / 1024 + ' kB' };
  return { ok: true, xml: out, changed: out !== cur };
}

const label = (e) => (e.type === 'journald' ? 'the systemd journal' : e.path);
function diff(foundBefore, entriesAfter) {
  const before = (foundBefore && foundBefore.state === 'ok' ? foundBefore.entries : []).map(label), after = entriesAfter.map(label);
  return { added: after.filter((x) => !before.includes(x)), removed: before.filter((x) => !after.includes(x)), same: after.filter((x) => before.includes(x)).length };
}

module.exports = { BEGIN, END, MAX_ENTRIES, MAX_FILE_BYTES, PATH_RE, sha256, pathProblem, validateEntries, blockText, find, compose, diff, label };
