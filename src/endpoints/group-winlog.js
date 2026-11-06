'use strict';
// Windows event channels of an agent GROUP (docs/endpoints.md, task E11): the second part of a group's agent.conf that ASIX writes, next to the monitored folders of E10.
// Pure functions, no I/O. The rules for the text are here; the calls to the manager are in group-winlog-service.js.
//
// ASIX owns ONE block between two marker comments and leaves every other byte alone:
//
//   <!-- ASIX:windows-events:begin v1 -->
//   <agent_config os="Windows">
//     <localfile> <location>Security</location> <log_format>eventchannel</log_format> <query>Event/System[EventID != 4656 and ...]</query> </localfile>
//   </agent_config>
//   <!-- ASIX:windows-events:end -->
//
// The block is made from two things: the channels a person chose for the group and the tenant's Windows filter policy (win-filter.js). The policy decides the query of each channel
// (win-filter.js toXPath: only an all-event-ID, one-action policy for a channel can be said in XPath; anything else stays at the broker and the channel is read whole). The
// markers are different from E10's, so the two blocks never see each other. A file whose markers are damaged, or whose block does not have exactly this shape, is refused.
const crypto = require('crypto');
const wf = require('./win-filter');

const BEGIN = '<!-- ASIX:windows-events:begin v1 -->';
const END = '<!-- ASIX:windows-events:end -->';
const BEGIN_RE = /<!-- ASIX:windows-events:begin[^>]*-->/g;
const END_RE = /<!-- ASIX:windows-events:end -->/g;
const MAX_CHANNELS = 20, MAX_FILE_BYTES = 256 * 1024;
const CHANNEL_RE = /^[A-Za-z0-9 _/.-]{1,64}$/;   // the same alphabet win-filter.js allows for a channel name (a test keeps the two together)

const sha256 = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const unesc = (s) => String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

// channels: a list of names -> { ok, errors, channels } with a normalised copy: trimmed names must match the alphabet, a name repeated in another letter case counts once
// (Windows channel names are not case sensitive), sorted so that the same set always gives the same file.
function validateChannels(input) {
  const errors = [];
  if (!Array.isArray(input)) return { ok: false, errors: ['channels must be a list'], channels: [] };
  if (input.length > MAX_CHANNELS) return { ok: false, errors: ['At most ' + MAX_CHANNELS + ' channels per group'], channels: [] };
  const out = [], seen = new Set();
  for (const c of input) {
    if (typeof c !== 'string') { errors.push('Each channel must be text'); continue; }
    const name = c.trim();
    if (!CHANNEL_RE.test(name)) { errors.push('The channel \u201c' + String(c).slice(0, 40) + '\u201d is not valid (letters, digits, space and _ / . - , up to 64)'); continue; }
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key); out.push(name);
  }
  out.sort((a, b) => { const x = a.toLowerCase(), y = b.toLowerCase(); return x < y ? -1 : x > y ? 1 : 0; });
  return { ok: errors.length === 0, errors, channels: out };
}

// What the policy says for each channel: [{ channel, query, reason }]; query is null when the channel is read whole (and reason says why).
function desired(policy, channels) {
  return channels.map((c) => { const x = wf.toXPath(policy, c); return { channel: c, query: x.query || null, reason: x.query ? null : x.reason }; });
}

function blockText(policy, channels) {
  const lines = [BEGIN, '<agent_config os="Windows">'];
  for (const d of desired(policy, channels)) {
    lines.push('  <localfile>', '    <location>' + esc(d.channel) + '</location>', '    <log_format>eventchannel</log_format>');
    if (d.query) lines.push('    <query>' + esc(d.query) + '</query>');
    lines.push('  </localfile>');
  }
  lines.push('</agent_config>', END);
  return lines.join('\n');
}

// Finds the block in a file. { state: 'none' | 'ok' | 'broken' | 'edited', items: [{ channel, query }], channels, start, end, text }.
// `ok` means the block has exactly the shape ASIX writes, whatever policy it was written from: whether it still matches the CURRENT policy is `status()`.
function find(xml) {
  const s = String(xml || '');
  const begins = [...s.matchAll(BEGIN_RE)], ends = [...s.matchAll(END_RE)];
  if (!begins.length && !ends.length) return { state: 'none', items: [], channels: [] };
  if (begins.length !== 1 || ends.length !== 1 || ends[0].index < begins[0].index) return { state: 'broken', items: [], channels: [] };
  const start = begins[0].index, end = ends[0].index + END.length, raw = s.slice(start, end), text = raw.replace(/\r\n/g, '\n');   // a manager or an editor may change the line ends
  const edited = { state: 'edited', items: [], channels: [], start, end, text: raw };
  if (begins[0][0] !== BEGIN) return edited;
  const inner = text.slice(BEGIN.length, text.length - END.length);
  const wrap = /^\s*<agent_config os="Windows">([\s\S]*)<\/agent_config>\s*$/.exec(inner);
  if (!wrap) return edited;
  // A manager re-indents what it is given and may write > as is: the block is read by its words, with the standard entities taken out of the text.
  const one = /\s*<localfile>\s*<location>([^<>]*)<\/location>\s*<log_format>eventchannel<\/log_format>(?:\s*<query>([^<]*)<\/query>)?\s*<\/localfile>/y;
  const items = []; let pos = 0; const body = wrap[1];
  while (pos < body.length && body.slice(pos).trim() !== '') {
    one.lastIndex = pos; const m = one.exec(body); if (!m) return edited;
    const channel = unesc(m[1]), query = m[2] === undefined ? null : unesc(m[2]);
    if (!CHANNEL_RE.test(channel) || /^\s|\s$/.test(channel)) return edited;
    if (query !== null && (!query.length || query.length > wf.MAX_XPATH || /[\u0000-\u001f\u007f]/.test(query) || /&/.test(query))) return edited;
    items.push({ channel, query }); pos = one.lastIndex;
  }
  if (!items.length || items.length > MAX_CHANNELS) return edited;
  if (new Set(items.map((i) => i.channel.toLowerCase())).size !== items.length) return edited;
  return { state: 'ok', items, channels: items.map((i) => i.channel), start, end, text: raw };
}

// How a block that is `ok` compares with what the CURRENT policy gives for its channels: one row per channel with the query in the file and the query now.
function status(found, policy) {
  if (!found || found.state !== 'ok') return { in_step: null, rows: [] };
  const now = new Map(desired(policy, found.channels).map((d) => [d.channel, d]));
  const rows = found.items.map((i) => { const n = now.get(i.channel); return { channel: i.channel, in_file: i.query, now: n.query, reason: n.reason, same: i.query === n.query }; });
  return { in_step: rows.every((r) => r.same), rows };
}

// The file with the block set to `channels` under `policy` (an empty list removes it). Everything outside the block is kept byte for byte.
// { ok, xml, changed } or { ok: false, code, message }.
function compose(xml, policy, channelsIn) {
  const cur = String(xml || '');
  if (Buffer.byteLength(cur, 'utf8') > MAX_FILE_BYTES) return { ok: false, code: 'TOO_LARGE', message: 'The group configuration is larger than ' + MAX_FILE_BYTES / 1024 + ' kB' };
  if (/\u0000/.test(cur)) return { ok: false, code: 'BAD_FILE', message: 'The group configuration has a NUL character' };
  const f = find(cur);
  if (f.state === 'broken') return { ok: false, code: 'MARKERS_BROKEN', message: 'The ASIX markers for Windows events in this group\u2019s configuration are damaged (one missing, repeated or out of order). Fix or remove them on the manager first.' };
  if (f.state === 'edited') return { ok: false, code: 'BLOCK_EDITED', message: 'The ASIX block for Windows events in this group\u2019s configuration was changed by hand. ASIX will not overwrite it: remove the block on the manager, or put it back as ASIX wrote it.' };
  const v = validateChannels(channelsIn); if (!v.ok) return { ok: false, code: 'INVALID', message: v.errors[0], errors: v.errors };
  let out;
  if (!v.channels.length) {
    if (f.state === 'none') return { ok: true, xml: cur, changed: false };
    // The reverse of adding: take away the block, the newline after it and the one blank line that adding put before it, so add then remove gives back the same file.
    let a = cur.slice(0, f.start).replace(/[ \t]+$/, ''), b = cur.slice(f.end);
    b = b.replace(/^\r?\n/, ''); if (/\n\n$/.test(a)) a = a.slice(0, -1);
    out = a + b;
  } else if (f.state === 'none') {
    out = cur + (cur.length && !/\n$/.test(cur) ? '\n' : '') + (cur.trim().length ? '\n' : '') + blockText(policy, v.channels) + '\n';
  } else out = cur.slice(0, f.start).replace(/[ \t]+$/, '') + blockText(policy, v.channels) + cur.slice(f.end);
  if (Buffer.byteLength(out, 'utf8') > MAX_FILE_BYTES) return { ok: false, code: 'TOO_LARGE', message: 'The result would be larger than ' + MAX_FILE_BYTES / 1024 + ' kB' };
  return { ok: true, xml: out, changed: out !== cur };
}

// What a person is shown before pressing Apply: channels added, removed, and channels whose query changes (the policy changed since the block was written).
function diff(foundBefore, policy, channelsAfter) {
  const before = new Map((foundBefore && foundBefore.state === 'ok' ? foundBefore.items : []).map((i) => [i.channel, i.query]));
  const after = desired(policy, channelsAfter), names = new Set(after.map((d) => d.channel));
  const q = (x) => (x === null ? 'the whole channel' : x);
  const added = after.filter((d) => !before.has(d.channel)).map((d) => d.channel + ': ' + q(d.query));
  const removed = [...before.keys()].filter((c) => !names.has(c));
  const changed = after.filter((d) => before.has(d.channel) && before.get(d.channel) !== d.query).map((d) => d.channel + ': ' + q(before.get(d.channel)) + '  ->  ' + q(d.query));
  const same = after.filter((d) => before.has(d.channel) && before.get(d.channel) === d.query).length;
  return { added, removed, changed, same };
}

module.exports = { BEGIN, END, MAX_CHANNELS, MAX_FILE_BYTES, CHANNEL_RE, sha256, validateChannels, desired, blockText, find, status, compose, diff };
