'use strict';
// Parsing rules: an XSIAM-style language that runs on every event at ingest.
//
//   [INGEST:vendor="linux", product="sshd", target_dataset="linux_auth_raw", no_hit=keep, content_id="linux_sshd"]
//   filter app_name = "sshd" and message ~= "^Failed"
//   | alter user = arrayindex(regextract(message, "for (\S+) from"), 0),
//           event_outcome = "failure"
//   | fields -tmp_*;
//
// A rule is a header plus one or more pipelines, each ending in ";". The first pipeline whose
// filter stages all pass is applied; later pipelines and rules are skipped. Stages: filter, alter,
// fields. Nothing is evaluated as code: the text is parsed to a small AST and interpreted.
//
// Fields visible to a rule: everything in the event's parsed object (host, app_name, message ...)
// plus _raw (read-only), _time (assignable), source_type (read-only).

class RuleError extends Error { constructor(message, pos) { super(message); this.pos = pos == null ? 0 : pos; } }

const SOURCE_RE = /^[A-Za-z0-9._-]{1,50}$/;
const HEADER_KEYS = ['vendor', 'product', 'target_dataset', 'no_hit', 'content_id', 'source_type'];
const READONLY = new Set(['_raw', 'source_type', 'collector_id', '_id']);
const MAX_SRC = 60000, MAX_REGEX = 300, MAX_VAL = 8192, MAX_KEYS = 200;
const KW = new Set(['and', 'or', 'not', 'contains', 'in', 'null', 'true', 'false']);

// ---- tokenizer ------------------------------------------------------------------------
function tokenize(src) {
  const out = []; let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '/' && src[i + 1] === '*') { const j = src.indexOf('*/', i + 2); if (j < 0) throw new RuleError('Unterminated /* comment', i); i = j + 2; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '"') {
      let j = i + 1, v = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && src[j + 1] === '"') { v += '"'; j += 2; continue; }
        if (src[j] === '\\' && src[j + 1] === '\\') { v += '\\\\'; j += 2; continue; }   // keep regex escapes verbatim
        v += src[j++];
      }
      if (j >= src.length) throw new RuleError('Unterminated string', i);
      out.push({ t: 'str', v, pos: i }); i = j + 1; continue;
    }
    let m;
    if ((m = /^\d+(\.\d+)?/.exec(src.slice(i, i + 40)))) { out.push({ t: 'num', v: Number(m[0]), pos: i }); i += m[0].length; continue; }
    if ((m = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(src.slice(i, i + 120)))) { out.push({ t: 'id', v: m[0], l: m[0].toLowerCase(), pos: i }); i += m[0].length; continue; }
    const two = src.slice(i, i + 2);
    if (['!=', '~=', '>=', '<='].includes(two)) { out.push({ t: 'op', v: two, pos: i }); i += 2; continue; }
    if ('[]:,;|()=<>*-'.includes(c)) { out.push({ t: 'op', v: c, pos: i }); i++; continue; }
    throw new RuleError(`Unexpected character "${c}"`, i);
  }
  return out;
}

// ---- regex helpers (RE2-like: no backtracking bombs, optional leading (?i)) -------------
const reCache = new Map();
function toRegex(pattern, flags) {
  const key = flags + '\u0000' + pattern;
  if (reCache.has(key)) return reCache.get(key);
  let p = String(pattern), f = flags;
  if (p.startsWith('(?i)')) { p = p.slice(4); f += 'i'; }
  if (p.length > MAX_REGEX) throw new RuleError(`Regex longer than ${MAX_REGEX} characters`);
  if (/\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/.test(p)) throw new RuleError('Regex has a nested quantifier such as (a+)+ which can hang the parser; simplify it');
  let re;
  try { re = new RegExp(p, f); } catch (e) { throw new RuleError('Invalid regular expression: ' + e.message); }
  if (reCache.size > 500) reCache.clear();
  reCache.set(key, re);
  return re;
}

// ---- strftime-style timestamp parsing -----------------------------------------------------
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
function parseTimestamp(fmt, input) {
  if (input == null || fmt == null) return null;
  const order = [];
  const pat = String(fmt).replace(/%F/g, '%Y-%m-%d').replace(/%T/g, '%H:%M:%S').replace(/%E\*S/g, '%f').replace(/%Ez|%z/g, '%Z')
    .replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&').replace(/%([YmdeHMSbfZ])/g, (_, k) => {
      order.push(k);
      return { Y: '(\\d{4})', m: '(\\d{1,2})', d: '(\\d{1,2})', e: '\\s*(\\d{1,2})', H: '(\\d{2})', M: '(\\d{2})', S: '(\\d{2})', b: '([A-Za-z]{3})', f: '(\\d{2}(?:\\.\\d+)?)', Z: '(Z|[+-]\\d{2}:?\\d{2})' }[k];
    });
  const m = new RegExp('^\\s*' + pat + '\\s*$').exec(String(input));
  if (!m) return null;
  const v = { Y: new Date().getUTCFullYear(), m: 1, d: 1, H: 0, M: 0, S: 0, Z: 'Z' };
  order.forEach((k, i) => {
    const x = m[i + 1];
    if (k === 'b') v.m = MONTHS.indexOf(x.toLowerCase()) + 1;
    else if (k === 'f') v.S = Number(x);
    else if (k === 'e') v.d = Number(x);
    else if (k === 'Z') v.Z = x;
    else v[k] = Number(x);
  });
  if (!(v.m >= 1 && v.m <= 12 && v.d >= 1 && v.d <= 31)) return null;
  const z = v.Z === 'Z' ? 'Z' : v.Z.replace(/^([+-]\d{2}):?(\d{2})$/, '$1:$2');
  const sec = String(Math.floor(v.S)).padStart(2, '0') + (v.S % 1 ? '.' + String(v.S).split('.')[1].slice(0, 3) : '');
  const iso = `${String(v.Y).padStart(4, '0')}-${String(v.m).padStart(2, '0')}-${String(v.d).padStart(2, '0')}T${String(v.H).padStart(2, '0')}:${String(v.M).padStart(2, '0')}:${sec}${z}`;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

// ---- parser -------------------------------------------------------------------------------
const FUNCS = {
  if: 3, to_string: 1, to_integer: 1, lowercase: 1, uppercase: 1, trim: 1, len: 1, regextract: 2, arrayindex: 2,
  parse_timestamp: 2, replace: 3, concat: -1, coalesce: -1, array_length: 1,
};

class Parser {
  constructor(tokens) { this.t = tokens; this.i = 0; }
  get cur() { return this.t[this.i]; }
  done() { return this.i >= this.t.length; }
  op(v) { const c = this.cur; return c && c.t === 'op' && c.v === v; }
  kw(l) { const c = this.cur; return c && c.t === 'id' && c.l === l; }
  fail(msg, tok) { const c = tok || this.cur; throw new RuleError(msg + (c ? '' : ' (reached end of rules)'), c ? c.pos : undefined); }
  eatOp(v) { if (!this.op(v)) this.fail(`Expected "${v}"`); return this.t[this.i++]; }

  // --- header + pipelines
  ruleset() {
    const rules = [], seen = new Set();
    while (!this.done()) {
      const start = this.cur;
      this.eatOp('[');
      if (!this.kw('ingest')) this.fail('Rule header must start with [INGEST:');
      this.i++; this.eatOp(':');
      const params = {};
      do {
        const k = this.cur; if (!k || k.t !== 'id') this.fail('Expected a header option such as content_id="..."');
        const key = k.l; if (!HEADER_KEYS.includes(key)) this.fail(`Unknown header option "${k.v}" (use ${HEADER_KEYS.join(', ')})`);
        this.i++; this.eatOp('=');
        const v = this.cur; if (!v || (v.t !== 'str' && v.t !== 'id' && v.t !== 'num')) this.fail('Expected a value');
        this.i++; params[key] = v.t === 'id' ? v.l : String(v.v);
      } while (this.op(',') && ++this.i);
      this.eatOp(']');
      if (!params.content_id) this.fail('Header needs content_id="..." (a unique name for the rule)', start);
      if (seen.has(params.content_id)) this.fail(`Duplicate content_id "${params.content_id}"`, start);
      seen.add(params.content_id);
      if (params.no_hit && !['keep', 'drop'].includes(params.no_hit)) this.fail('no_hit must be keep or drop', start);
      if (params.target_dataset && !SOURCE_RE.test(params.target_dataset)) this.fail('target_dataset: 1-50 chars of letters, digits . _ -', start);
      if (params.source_type && !SOURCE_RE.test(params.source_type)) this.fail('source_type: 1-50 chars of letters, digits . _ -', start);
      const pipelines = [];
      while (!this.done() && !this.op('[')) pipelines.push(this.pipeline());
      if (!pipelines.length) this.fail('Rule has no filter / alter stages', start);
      rules.push({ params, pipelines, pos: start.pos });
    }
    return rules;
  }
  pipeline() {
    const stages = [];
    do { stages.push(this.stage()); } while (this.op('|') && ++this.i);
    if (!this.op(';')) this.fail('Expected ";" at the end of the pipeline');
    this.i++;
    return stages;
  }
  stage() {
    const c = this.cur;
    if (!c || c.t !== 'id') this.fail('Expected filter, alter or fields');
    if (c.l === 'filter') { this.i++; return { k: 'filter', e: this.or() }; }
    if (c.l === 'alter') {
      this.i++; const sets = [];
      do {
        const n = this.cur; if (!n || n.t !== 'id' || KW.has(n.l)) this.fail('Expected a field name to assign');
        if (READONLY.has(n.v)) this.fail(`"${n.v}" is read-only`);
        this.i++; this.eatOp('='); sets.push({ name: n.v, e: this.or() });
      } while (this.op(',') && ++this.i);
      return { k: 'alter', sets };
    }
    if (c.l === 'fields') {
      this.i++; const items = [];
      do {
        const neg = this.op('-') && ++this.i > 0;
        const n = this.cur; if (!n || n.t !== 'id') this.fail('Expected a field name');
        this.i++; let pat = n.v;
        if (this.op('*') && this.cur.pos === n.pos + n.v.length) { this.i++; pat += '*'; }
        items.push({ neg, pat });
      } while (this.op(',') && ++this.i);
      if (items.some((x) => x.neg) && items.some((x) => !x.neg)) this.fail('Do not mix "-field" (remove) and "field" (keep only) in one fields stage');
      return { k: 'fields', items };
    }
    this.fail(`Unknown stage "${c.v}" (use filter, alter, fields)`);
  }

  // --- expressions
  or() { let l = this.and(); while (this.kw('or')) { this.i++; l = { k: 'or', l, r: this.and() }; } return l; }
  and() { let l = this.not(); while (this.kw('and')) { this.i++; l = { k: 'and', l, r: this.not() }; } return l; }
  not() { if (this.kw('not')) { this.i++; return { k: 'not', e: this.not() }; } return this.cmp(); }
  cmp() {
    const l = this.primary(); let neg = false;
    if (this.kw('not')) { const n = this.t[this.i + 1]; if (n && n.t === 'id' && (n.l === 'contains' || n.l === 'in')) { this.i++; neg = true; } }
    if (this.kw('contains')) { this.i++; const r = this.primary(); return { k: 'cmp', op: 'contains', neg, l, r }; }
    if (this.kw('in')) {
      this.i++; this.eatOp('('); const list = [];
      do { list.push(this.primary()); } while (this.op(',') && ++this.i);
      this.eatOp(')'); return { k: 'in', neg, l, list };
    }
    const c = this.cur;
    if (c && c.t === 'op' && ['=', '!=', '~=', '<', '>', '<=', '>='].includes(c.v)) {
      this.i++; const r = this.primary();
      if (c.v === '~=' && r.k === 'lit') toRegex(String(r.v), '');   // validate at save time
      return { k: 'cmp', op: c.v, neg: false, l, r };
    }
    return l;
  }
  primary() {
    const c = this.cur; if (!c) this.fail('Unexpected end of expression');
    if (c.t === 'str') { this.i++; return { k: 'lit', v: c.v }; }
    if (c.t === 'num') { this.i++; return { k: 'lit', v: c.v }; }
    if (c.t === 'op' && c.v === '(') { this.i++; const e = this.or(); this.eatOp(')'); return e; }
    if (c.t === 'op' && c.v === '-' && this.t[this.i + 1] && this.t[this.i + 1].t === 'num') { this.i += 2; return { k: 'lit', v: -this.t[this.i - 1].v }; }
    if (c.t === 'id') {
      if (c.l === 'null') { this.i++; return { k: 'lit', v: null }; }
      if (c.l === 'true' || c.l === 'false') { this.i++; return { k: 'lit', v: c.l === 'true' }; }
      if (KW.has(c.l)) this.fail(`Unexpected "${c.v}"`);
      this.i++;
      if (this.op('(')) {
        const name = c.l; if (!(name in FUNCS)) this.fail(`Unknown function "${c.v}"`, c);
        this.i++; const args = [];
        if (!this.op(')')) { do { args.push(this.or()); } while (this.op(',') && ++this.i); }
        this.eatOp(')');
        const want = FUNCS[name];
        if (want >= 0 && args.length !== want) this.fail(`${c.v}() takes ${want} argument${want === 1 ? '' : 's'}`, c);
        if (want < 0 && !args.length) this.fail(`${c.v}() needs at least one argument`, c);
        if (name === 'regextract' && args[1].k === 'lit') toRegex(String(args[1].v), 'g');
        return { k: 'fn', n: name, a: args };
      }
      return { k: 'field', n: c.v };
    }
    this.fail(`Unexpected "${c.v}"`);
  }
}

// ---- evaluator ----------------------------------------------------------------------------
const truthy = (v) => v !== null && v !== undefined && v !== false && v !== '' && v !== 0;
const str = (v) => (v === null || v === undefined ? null : typeof v === 'object' ? JSON.stringify(v) : String(v));
const isNum = (v) => typeof v === 'number' || (typeof v === 'string' && /^-?\d+(\.\d+)?$/.test(v));

function compare(op, a, b) {
  if (op === '=') return a === null || a === undefined ? (b === null || b === undefined) : (b === null || b === undefined) ? false : (isNum(a) && isNum(b) ? Number(a) === Number(b) : str(a) === str(b));
  if (op === '!=') return !compare('=', a, b);
  if (a === null || a === undefined || b === null || b === undefined) return false;
  if (op === '~=') return toRegex(String(b), '').test(str(a));
  if (op === 'contains') return str(a).toLowerCase().includes(str(b).toLowerCase());
  const [x, y] = isNum(a) && isNum(b) ? [Number(a), Number(b)] : [str(a), str(b)];
  return op === '<' ? x < y : op === '>' ? x > y : op === '<=' ? x <= y : x >= y;
}

function evaluate(n, rec) {
  switch (n.k) {
    case 'lit': return n.v;
    case 'field': { const v = rec[n.n]; return v === undefined ? null : v; }
    case 'and': return truthy(evaluate(n.l, rec)) && truthy(evaluate(n.r, rec));
    case 'or': return truthy(evaluate(n.l, rec)) || truthy(evaluate(n.r, rec));
    case 'not': return !truthy(evaluate(n.e, rec));
    case 'cmp': { const r = compare(n.op, evaluate(n.l, rec), evaluate(n.r, rec)); return n.neg ? !r : r; }
    case 'in': { const l = evaluate(n.l, rec); const hit = n.list.some((x) => compare('=', l, evaluate(x, rec))); return n.neg ? !hit : hit; }
    case 'fn': return callFn(n, rec);
    default: return null;
  }
}

function callFn(n, rec) {
  const a = n.a;
  if (n.n === 'if') return truthy(evaluate(a[0], rec)) ? evaluate(a[1], rec) : evaluate(a[2], rec);
  if (n.n === 'coalesce') { for (const x of a) { const v = evaluate(x, rec); if (v !== null && v !== undefined && v !== '') return v; } return null; }
  const v = a.map((x) => evaluate(x, rec));
  switch (n.n) {
    case 'to_string': return str(v[0]);
    case 'to_integer': { if (v[0] === null) return null; const x = Math.trunc(Number(v[0])); return Number.isFinite(x) ? x : null; }
    case 'lowercase': return v[0] === null ? null : str(v[0]).toLowerCase();
    case 'uppercase': return v[0] === null ? null : str(v[0]).toUpperCase();
    case 'trim': return v[0] === null ? null : str(v[0]).trim();
    case 'len': return v[0] === null ? null : (Array.isArray(v[0]) ? v[0].length : str(v[0]).length);
    case 'array_length': return Array.isArray(v[0]) ? v[0].length : null;
    case 'concat': return v.some((x) => x === null) ? null : v.map(str).join('');
    case 'replace': return v[0] === null || v[1] === null ? null : str(v[0]).split(str(v[1])).join(str(v[2] ?? ''));
    case 'arrayindex': { if (!Array.isArray(v[0])) return null; const i = Number(v[1]); const x = v[0][i < 0 ? v[0].length + i : i]; return x === undefined ? null : x; }
    case 'parse_timestamp': return parseTimestamp(v[0], v[1]);
    case 'regextract': {
      if (v[0] === null || v[1] === null) return null;
      const re = toRegex(String(v[1]), 'g'), s = str(v[0]); const out = []; let m; re.lastIndex = 0;
      while ((m = re.exec(s)) && out.length < 20) { out.push(m[1] !== undefined ? m[1] : m[0]); if (m[0] === '') re.lastIndex++; }
      return out;
    }
    default: return null;
  }
}

const globToRe = (g) => new RegExp('^' + g.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');

// Run one pipeline on a copy of the record; null = a filter failed.
function runPipeline(stages, base) {
  const rec = { ...base };
  for (const s of stages) {
    if (s.k === 'filter') { if (!truthy(evaluate(s.e, rec))) return null; }
    else if (s.k === 'alter') { for (const a of s.sets) rec[a.name] = evaluate(a.e, rec); }
    else {
      const res = s.items.map((x) => globToRe(x.pat));
      for (const key of Object.keys(rec)) {
        if (key === '_raw' || key === '_time' || key === 'source_type') continue;
        const hit = res.some((r) => r.test(key));
        if (s.items[0].neg ? hit : !hit) delete rec[key];
      }
    }
  }
  return rec;
}

// ---- public API ---------------------------------------------------------------------------
// compile(src) -> { rules, info } or throws RuleError carrying line/column.
function compile(src) {
  if (typeof src !== 'string') throw new RuleError('Rules must be text');
  if (src.length > MAX_SRC) throw new RuleError(`Rules are too long (max ${MAX_SRC} characters)`);
  try {
    const rules = new Parser(tokenize(src)).ruleset();
    return { rules, info: rules.map((r) => ({ content_id: r.params.content_id, vendor: r.params.vendor || null, product: r.params.product || null, target_dataset: r.params.target_dataset || null, source_type: r.params.source_type || null, no_hit: r.params.no_hit || 'keep', pipelines: r.pipelines.length })) };
  } catch (e) {
    if (!(e instanceof RuleError)) throw e;
    const before = src.slice(0, e.pos), line = before.split('\n').length, column = e.pos - before.lastIndexOf('\n');
    const out = new RuleError(e.message, e.pos); out.line = line; out.column = column; throw out;
  }
}

// apply(compiledSets, event) where event = { source_type, raw, time (ISO|null), parsed }.
// compiledSets is an array of rule arrays in priority order (user rules first).
function apply(sets, ev) {
  const base = { ...ev.parsed, _raw: ev.raw, _time: ev.time || null, source_type: ev.source_type };
  const out = { dropped: false, matched: null, source_type: ev.source_type, time: ev.time || null, parsed: ev.parsed, errors: [] };
  let applicable = 0, keepers = 0;
  for (const set of sets) {
    for (const rule of set) {
      const p = rule.params;
      if (p.source_type && p.source_type.toLowerCase() !== String(ev.source_type).toLowerCase()) continue;
      applicable++; if (p.no_hit !== 'drop') keepers++;
      for (const stages of rule.pipelines) {
        let rec;
        try { rec = runPipeline(stages, base); } catch (e) { out.errors.push(`${p.content_id}: ${e.message}`); continue; }
        if (!rec) continue;
        const parsed = {}; let n = 0;
        for (const [k, v] of Object.entries(rec)) {
          if (k === '_raw' || k === '_time' || k === 'source_type' || v === null || v === undefined || ++n > MAX_KEYS) continue;
          parsed[k] = typeof v === 'string' ? v.slice(0, MAX_VAL) : v;
        }
        parsed._content_id = p.content_id;
        if (p.vendor) parsed._vendor = p.vendor;
        if (p.product) parsed._product = p.product;
        const t = typeof rec._time === 'string' && !Number.isNaN(new Date(rec._time).getTime()) ? new Date(rec._time).toISOString() : out.time;
        return { ...out, parsed, time: t, source_type: p.target_dataset || ev.source_type, matched: { content_id: p.content_id, vendor: p.vendor || null, product: p.product || null } };
      }
    }
  }
  if (applicable && !keepers) out.dropped = true;
  return out;
}

module.exports = { compile, apply, RuleError, parseTimestamp };
