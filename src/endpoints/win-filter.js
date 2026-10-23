'use strict';
// The Windows event filter policy (docs/endpoints.md, task E1). One policy says which Windows events to keep or drop and which explanatory text to remove from the
// ones that are kept. It is written like a Splunk Universal Forwarder allow/deny list (by channel and event ID, with an optional regex on a field or on the
// rendered message) and is enforced in two places:
//   - the broker (Vector, toVrl / toVectorTransform) enforces ALL of it: this is the authoritative copy;
//   - the Wazuh agent group (toXPath / toAgentConf) gets only the part an XPath query can say (event IDs, no regex), as an optimisation that saves agent-to-manager
//     traffic. The broker still applies the whole policy, so an event the agent let through that the policy drops is dropped there.
// The long text many Windows events end with is not part of the event: Windows adds it when it renders the message. `strip_message` removes the rendered message
// and `message_strip` removes what a regex matches from it; the structured EventData fields are never touched.
//
// Regexes run in Vector (Rust regex) and in evaluate() here (JavaScript, for previews and tests). Only the syntax both read the same way is accepted (see
// checkRegex); two differences remain and are documented in docs/endpoints.md: `.` also matches \r in Rust but not in JavaScript, and \d \w \s are Unicode in Rust but
// ASCII in JavaScript. Use [^\n] and explicit classes where it matters. Pure functions, no I/O.

const MAX_RULES = 200, MAX_STRIPS = 50, MAX_REGEX = 300, MAX_XPATH = 1024;
const ID_RE = /^[a-z0-9_-]{1,40}$/, CHANNEL_RE = /^[A-Za-z0-9 _/.-]{1,64}$/, FIELD_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const ACTIONS = ['keep', 'drop'];

// What a Wazuh archive/alert line looks like for a Windows event (data.win.system.*, data.win.eventdata.*). Wazuh lower-cases the first letter of each EventData name.
const WAZUH_PATHS = { channel: ['data', 'win', 'system', 'channel'], event_id: ['data', 'win', 'system', 'eventID'], message: ['data', 'win', 'system', 'message'], fields: ['data', 'win', 'eventdata'], lowerFirst: true };

// ---- parsing ----
// "4624", 4624 or "4700-4710" -> [lo, hi]; null when it is not one.
function parseId(x) {
  const s = String(x).trim(), m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(s);
  if (!m) return null;
  const lo = Number(m[1]), hi = m[2] === undefined ? lo : Number(m[2]);
  return lo <= 65535 && hi <= 65535 && lo <= hi ? [lo, hi] : null;
}

// The regex subset Rust and JavaScript read the same way: no lookaround, back-references, named groups, inline flags (only (?:...) groups), \p \P \k \c, \A \z \Z \G,
// no single quote (it ends a VRL regex literal; write \x27) and no control characters. Returns an error text or null.
function checkRegex(re) {
  if (typeof re !== 'string' || re === '') return 'must be a non-empty text';
  if (re.length > MAX_REGEX) return 'is longer than ' + MAX_REGEX + ' characters';
  if (/[\u0000-\u001f\u007f]/.test(re)) return 'has a control character (write \\n or \\t instead)';
  if (re.includes("'")) return "has a single quote (write \\x27)";
  if (/\(\?(?!:)/.test(re)) return 'uses (? syntax other than (?: ): lookaround, named groups and inline flags are not supported';
  if (/\\[1-9kpPcAzZG]/.test(re.replace(/\\\\/g, ''))) return 'uses back-references or an escape (\\1-\\9 \\k \\p \\P \\c \\A \\z \\Z \\G) that Rust and JavaScript read differently';
  // Character classes and braces Rust and JavaScript read differently: [^] and [] (JavaScript only), a [ inside a class (nested class in Rust), && ~~ -- in a class (set
  // operations in Rust), and a { that is not a quantifier like {2} {2,} {2,5} (Rust refuses it, JavaScript takes it literally).
  let inClass = false;
  for (let i = 0; i < re.length; i++) {
    const c = re[i];
    if (c === '\\') { i++; continue; }
    if (inClass) {
      if (c === '[') return 'has a [ inside a character class (write \\[)';
      if (c === ']') inClass = false;
      else if (/^(&&|~~|--)/.test(re.slice(i, i + 2))) return 'has && ~~ or -- inside a character class, which Rust treats as set operations';
    } else if (c === '[') {
      if (re[i + 1] === ']' || re.startsWith('[^]', i)) return 'has an empty character class ([] or [^]); write [\\s\\S] for "anything"';
      inClass = true; if (re[i + 1] === '^') i++; if (re[i + 1] === ']') i++;
    } else if (c === '{' && !/^\{\d+(,\d*)?\}/.test(re.slice(i))) return 'has a { that is not a quantifier like {2}, {2,} or {2,5} (write \\{)';
  }
  if (inClass) return 'has a [ that is never closed';
  try { new RegExp(re); } catch (e) { return 'is not a valid regular expression (' + e.message.replace(/^Invalid regular expression: /, '') + ')'; }
  return null;
}

// ---- validation ----
// Returns { ok, errors: [text], policy } where policy is the normalised copy (ids as [lo,hi] pairs, defaults filled in). Never throws.
function validate(input) {
  const errors = [], p = input && typeof input === 'object' && !Array.isArray(input) ? input : null;
  const out = { version: 1, default: 'keep', channels: {}, rules: [], strip_message: false, message_strip: [] };
  if (!p) return { ok: false, errors: ['the policy must be an object'], policy: out };
  if (p.version !== undefined && p.version !== 1) errors.push('version must be 1');
  if (p.default !== undefined) { if (ACTIONS.includes(p.default)) out.default = p.default; else errors.push('default must be "keep" or "drop"'); }
  if (p.strip_message !== undefined) { if (typeof p.strip_message === 'boolean') out.strip_message = p.strip_message; else errors.push('strip_message must be true or false'); }
  if (p.channels !== undefined) {
    if (!p.channels || typeof p.channels !== 'object' || Array.isArray(p.channels)) errors.push('channels must be an object');
    else for (const [name, c] of Object.entries(p.channels)) {
      if (!CHANNEL_RE.test(name)) { errors.push('channel name "' + name + '" is not valid'); continue; }
      if (!c || !ACTIONS.includes(c.default)) { errors.push('channels.' + name + '.default must be "keep" or "drop"'); continue; }
      out.channels[name] = { default: c.default };
    }
  }
  const scope = (x, where) => {   // channel + event_ids shared by rules and strips
    const s = {};
    if (x.channel !== undefined) { if (typeof x.channel === 'string' && CHANNEL_RE.test(x.channel)) s.channel = x.channel; else errors.push(where + ': channel is not valid'); }
    if (x.event_ids !== undefined) {
      if (!Array.isArray(x.event_ids) || !x.event_ids.length || x.event_ids.length > 100) errors.push(where + ': event_ids must be a list of 1 to 100 event IDs');
      else { const ids = x.event_ids.map(parseId); if (ids.includes(null)) errors.push(where + ': every event ID must be 0-65535 or a range like "4700-4710"'); else s.ids = ids; }
    }
    return s;
  };
  if (p.rules !== undefined) {
    if (!Array.isArray(p.rules)) errors.push('rules must be a list');
    else {
      if (p.rules.length > MAX_RULES) errors.push('more than ' + MAX_RULES + ' rules');
      const seen = new Set();
      p.rules.slice(0, MAX_RULES).forEach((r, i) => {
        const where = 'rule ' + (i + 1);
        if (!r || typeof r !== 'object') return errors.push(where + ' must be an object');
        if (typeof r.id !== 'string' || !ID_RE.test(r.id)) errors.push(where + ': id must be 1-40 characters of a-z 0-9 _ -');
        else if (seen.has(r.id)) errors.push(where + ': id "' + r.id + '" is used twice'); else seen.add(r.id);
        if (!ACTIONS.includes(r.action)) errors.push(where + ': action must be "keep" or "drop"');
        const rule = { id: r.id, action: r.action, ...scope(r, where) };
        if (r.match !== undefined) {
          const m = r.match;
          if (!m || typeof m !== 'object') errors.push(where + ': match must be an object { field, regex }');
          else {
            const field = m.field === undefined ? 'message' : m.field;
            if (field !== 'message' && !(typeof field === 'string' && FIELD_RE.test(field))) errors.push(where + ': match.field must be "message" or an EventData name');
            const e = checkRegex(m.regex); if (e) errors.push(where + ': match.regex ' + e);
            rule.match = { field, regex: m.regex };
          }
        }
        if (typeof r.note === 'string') rule.note = r.note.slice(0, 200);
        out.rules.push(rule);
      });
    }
  }
  if (p.message_strip !== undefined) {
    if (!Array.isArray(p.message_strip)) errors.push('message_strip must be a list');
    else {
      if (p.message_strip.length > MAX_STRIPS) errors.push('more than ' + MAX_STRIPS + ' message_strip entries');
      p.message_strip.slice(0, MAX_STRIPS).forEach((s, i) => {
        const where = 'message_strip ' + (i + 1);
        if (!s || typeof s !== 'object') return errors.push(where + ' must be an object');
        const e = checkRegex(s.regex); if (e) errors.push(where + ': regex ' + e);
        out.message_strip.push({ ...scope(s, where), regex: s.regex });
      });
    }
  }
  return { ok: errors.length === 0, errors, policy: out };
}

// ---- evaluation (reference behaviour; the generated Vector code must agree with it) ----
const inScope = (s, ev) => (s.channel === undefined || String(ev.channel || '').toLowerCase() === s.channel.toLowerCase())
  && (s.ids === undefined || s.ids.some(([lo, hi]) => ev.event_id >= lo && ev.event_id <= hi));
const fieldOf = (ev, name) => {
  if (name === 'message') return typeof ev.message === 'string' ? ev.message : '';
  const f = ev.fields || {}, k = Object.keys(f).find((x) => x.toLowerCase() === name.toLowerCase());
  return k === undefined || f[k] === null || f[k] === undefined ? '' : String(f[k]);
};
// ev = { channel, event_id (number), fields: { Name: value }, message }. Takes a validated policy (validate().policy). First matching rule wins; none matching falls back
// to the channel's default, then the policy default. A kept event's message is removed (strip_message) or has each matching message_strip regex removed in order.
function evaluate(policy, ev) {
  let keep = null, rule = null;
  for (const r of policy.rules) {
    if (!inScope(r, ev)) continue;
    if (r.match && !new RegExp(r.match.regex).test(fieldOf(ev, r.match.field))) continue;
    keep = r.action === 'keep'; rule = r.id; break;
  }
  if (keep === null) {
    const name = Object.keys(policy.channels).find((c) => c.toLowerCase() === String(ev.channel || '').toLowerCase());
    keep = (name ? policy.channels[name].default : policy.default) === 'keep';
  }
  if (!keep) return { keep: false, rule_id: rule, message: null };
  let message = typeof ev.message === 'string' ? ev.message : null;
  if (message !== null) {
    if (policy.strip_message) message = null;
    else for (const s of policy.message_strip) if (inScope(s, ev)) message = message.replace(new RegExp(s.regex, 'g'), '');
  }
  return { keep: true, rule_id: rule, message };
}

// ---- Vector (the authoritative enforcement) ----
const lowerFirst = (s) => s.charAt(0).toLowerCase() + s.slice(1);
const vrlPath = (arr) => '.' + arr.join('.');
const idCond = (ids) => '(' + ids.map(([lo, hi]) => (lo === hi ? 'id == ' + lo : '(id >= ' + lo + ' && id <= ' + hi + ')')).join(' || ') + ')';
const scopeCond = (s) => [s.channel !== undefined ? 'ch == "' + s.channel.toLowerCase() + '"' : null, s.ids !== undefined ? idCond(s.ids) : null].filter(Boolean);

// The VRL program (a `remap` transform with drop_on_abort) for a validated policy. `paths` says where the fields are in the event (default: a Wazuh Windows event).
function toVrl(policy, paths = WAZUH_PATHS) {
  const key = (n) => (paths.lowerFirst ? lowerFirst(n) : n), pMsg = vrlPath(paths.message);
  const fieldExpr = (name) => (name === 'message' ? 'msg' : '(to_string(' + vrlPath([...paths.fields, key(name)]) + ') ?? "")');
  const L = [];
  // Only the variables the program reads are defined: Vector warns about an unused one.
  const scopes = [...policy.rules, ...policy.message_strip], hasCh = scopes.some((x) => x.channel !== undefined) || Object.keys(policy.channels).length > 0;
  const hasId = scopes.some((x) => x.ids !== undefined), hasMsg = policy.rules.some((r) => r.match && r.match.field === 'message');
  if (hasCh) L.push('ch = downcase(to_string(' + vrlPath(paths.channel) + ') ?? "")');
  if (hasId) L.push('id = to_int(' + vrlPath(paths.event_id) + ') ?? -1');
  if (hasMsg) L.push('msg = to_string(' + pMsg + ') ?? ""');
  L.push('decided = false', 'keep = true');
  for (const r of policy.rules) {
    const c = [...scopeCond(r), ...(r.match ? ['match(' + fieldExpr(r.match.field) + ", r'" + r.match.regex + "')"] : [])];
    L.push('if !decided' + c.map((x) => ' && ' + x).join('') + ' {', '  decided = true', '  keep = ' + (r.action === 'keep'), '}');
  }
  L.push('if !decided {', '  keep = ' + (policy.default === 'keep'));
  for (const [name, c] of Object.entries(policy.channels)) L.push('  if ch == "' + name.toLowerCase() + '" { keep = ' + (c.default === 'keep') + ' }');
  L.push('}', 'if !keep { abort }');
  if (policy.strip_message) L.push('if is_string(' + pMsg + ') { del(' + pMsg + ') }');
  else if (policy.message_strip.length) {
    L.push('if is_string(' + pMsg + ') {');
    for (const s of policy.message_strip) { const c = scopeCond(s); L.push('  ' + (c.length ? 'if ' + c.join(' && ') + ' { ' : '{ ') + pMsg + " = replace(string!(" + pMsg + "), r'" + s.regex + "', \"\") }"); }
    L.push('}');
  }
  return L.join('\n');
}
// A complete Vector transform block (TOML) to drop into a broker config. name/inputs are checked: they end up unquoted in the file.
function toVectorTransform(policy, { name = 'asix_win_filter', inputs = ['wazuh_events'], paths } = {}) {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name)) throw new Error('transform name is not valid');
  if (!Array.isArray(inputs) || !inputs.length || inputs.some((i) => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(i))) throw new Error('transform inputs are not valid');
  return '[transforms.' + name + ']\ntype = "remap"\ninputs = [' + inputs.map((i) => '"' + i + '"').join(', ') + ']\ndrop_on_abort = true\nsource = \'\'\'\n' + toVrl(policy, paths) + '\n\'\'\'\n';
}

// ---- Wazuh agent group (optimisation only) ----
// The XPath query for ONE channel, or { query: null, reason } when XPath cannot say what the policy says for it. Only a channel whose rules are all event-ID rules (no
// regex) with one action, opposite to the channel's default, can be pushed: "drop these IDs, keep the rest" or "keep these IDs, drop the rest". Anything else stays at the broker.
function toXPath(policy, channel) {
  const lc = String(channel).toLowerCase(), name = Object.keys(policy.channels).find((c) => c.toLowerCase() === lc);
  const def = name ? policy.channels[name].default : policy.default;
  const rules = policy.rules.filter((r) => r.channel === undefined || r.channel.toLowerCase() === lc);
  const no = (reason) => ({ query: null, reason });
  if (!rules.length) return no(def === 'keep' ? 'nothing to filter on this channel' : 'the channel default is drop with no keep rule: leave the channel out of the agent group instead');
  if (rules.some((r) => r.match)) return no('a rule uses a regex, which XPath cannot say: it stays at the broker');
  if (rules.some((r) => r.ids === undefined)) return no('a rule covers the whole channel: set the channel default instead');
  const actions = new Set(rules.map((r) => r.action));
  if (actions.size > 1) return no('allow and deny rules are mixed: they stay at the broker');
  const action = [...actions][0];
  if (action === def) return no('the rules do not change what the channel default does');
  const ids = rules.flatMap((r) => r.ids), term = ([lo, hi], neg) => (lo === hi ? 'EventID ' + (neg ? '!=' : '=') + ' ' + lo : neg ? '(EventID < ' + lo + ' or EventID > ' + hi + ')' : '(EventID >= ' + lo + ' and EventID <= ' + hi + ')');
  const query = 'Event/System[' + ids.map((x) => term(x, action === 'drop')).join(action === 'drop' ? ' and ' : ' or ') + ']';
  return query.length > MAX_XPATH ? no('the query would be longer than ' + MAX_XPATH + ' characters: it stays at the broker') : { query, reason: null };
}
const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// The <localfile> blocks for an agent group's agent.conf: one per channel to collect, with the query where the policy allows one.
function toAgentConf(policy, channels) {
  return channels.map((c) => {
    if (!CHANNEL_RE.test(c)) throw new Error('channel name "' + c + '" is not valid');
    const q = toXPath(policy, c).query;
    return '<localfile>\n  <location>' + xml(c) + '</location>\n  <log_format>eventchannel</log_format>' + (q ? '\n  <query>' + xml(q) + '</query>' : '') + '\n</localfile>';
  }).join('\n');
}

// A suggested starting point, never applied by itself: the Security events that are mostly noise on a typical server (handle requests and closes, file share access, Windows
// Filtering Platform connections), plus removal of the rendered message. Review it before use; some environments need them.
function presetNoisySecurity() {
  return { version: 1, default: 'keep', channels: {}, strip_message: true, message_strip: [],
    rules: [{ id: 'noisy-security', action: 'drop', channel: 'Security', event_ids: [4656, 4658, 4690, 5145, 5156, 5158], note: 'handle requests/closes, share access, filtering platform connections' }] };
}

// A validated policy back in the shape validate() accepts (event IDs as numbers or "lo-hi" text): what is stored and shown, so reading it back and validating again
// gives the same policy.
function toInput(policy) {
  const ids = (a) => a.map(([lo, hi]) => (lo === hi ? lo : lo + '-' + hi));
  const scope = (x) => ({ ...(x.channel !== undefined ? { channel: x.channel } : {}), ...(x.ids !== undefined ? { event_ids: ids(x.ids) } : {}) });
  return { version: 1, default: policy.default, channels: { ...policy.channels }, strip_message: policy.strip_message,
    rules: policy.rules.map((r) => ({ id: r.id, action: r.action, ...scope(r), ...(r.match ? { match: { field: r.match.field, regex: r.match.regex } } : {}), ...(r.note ? { note: r.note } : {}) })),
    message_strip: policy.message_strip.map((m) => ({ ...scope(m), regex: m.regex })) };
}

module.exports = { toInput, validate, evaluate, checkRegex, parseId, toVrl, toVectorTransform, toXPath, toAgentConf, presetNoisySecurity, WAZUH_PATHS, MAX_RULES, MAX_STRIPS, MAX_REGEX, MAX_XPATH };
