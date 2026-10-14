'use strict';
// Regex safety for user-supplied patterns (parsing rules, detection rules, XQL `~=`).
//
// Two engines see user patterns, and they fail differently:
//   * 'js'  - V8's backtracking engine, run in-process on the ingest path. A bad pattern can
//             freeze the event loop (ReDoS), and a timeout is not possible, so patterns are
//             rejected up front by structural analysis (see analyze()).
//   * 'pg'  - PostgreSQL's engine (`~*`). It is not exponential on ordinary patterns and every
//             query already runs under statement_timeout, but back-references can still blow up,
//             so only length and back-references are checked.
//
// The JS check is deliberately conservative: it may refuse a harmless pattern, never the
// other way round for the classic shapes (nested quantifiers, overlapping alternation under a
// repeat, adjacent overlapping repeats, back-references).

const MAX_LEN = { js: 300, pg: 500 };
const MAX_UNBOUNDED = 4;          // `.*`, `\S+`, `{2,}` ... per pattern (js mode)
const HIGH = 100;                 // {n,m} with m above this counts as unbounded
const HI_SAMPLE = ['\u0100', '\u2028', '\u4e2d', '\u{1F600}'];

class RegexSafetyError extends Error {}

// ---- tokenizer / parser (just enough structure to reason about repetition) -----------------
function parse(src) {
  let i = 0;
  const fail = (m) => { throw new RegexSafetyError(m); };

  function atomEnd() { // returns source text of an escape starting at src[i] === '\\'
    const start = i; i++;
    if (i >= src.length) fail('Regex ends with a lone backslash');
    const c = src[i];
    if (/[1-9]/.test(c)) fail('Regex uses a back-reference (\\' + c + '), which is not allowed');
    if (c === 'k' && src[i + 1] === '<') fail('Regex uses a named back-reference, which is not allowed');
    i++;
    if (c === 'x') i += 2; else if (c === 'u') { if (src[i] === '{') i = src.indexOf('}', i) + 1 || src.length; else i += 4; } else if (c === 'c') i++;
    return src.slice(start, i);
  }

  function parseClass() {
    const start = i; i++;
    if (src[i] === '^') i++;
    if (src[i] === ']') i++;
    while (i < src.length && src[i] !== ']') { if (src[i] === '\\') i += 2; else i++; }
    if (src[i] !== ']') fail('Unterminated [...] in regex');
    i++;
    return src.slice(start, i);
  }

  function parseQuant() {
    const c = src[i];
    let min, max;
    if (c === '*') { min = 0; max = Infinity; i++; }
    else if (c === '+') { min = 1; max = Infinity; i++; }
    else if (c === '?') { min = 0; max = 1; i++; }
    else if (c === '{') {
      const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(src.slice(i));
      if (!m) return null;                     // a literal "{" in non-unicode JS
      min = Number(m[1]); max = m[2] ? (m[3] === '' ? Infinity : Number(m[3])) : min;
      i += m[0].length;
    } else return null;
    if (src[i] === '?') i++;                   // lazy
    return { min, max };
  }

  function parseAlt(depth) {
    if (depth > 20) fail('Regex groups are nested too deeply');
    const branches = [parseSeq(depth)];
    while (src[i] === '|') { i++; branches.push(parseSeq(depth)); }
    return branches;
  }

  function parseSeq(depth) {
    const items = [];
    while (i < src.length && src[i] !== '|' && src[i] !== ')') {
      const c = src[i];
      let item;
      if (c === '(') {
        i++;
        let look = false;
        if (src[i] === '?') {
          const m = /^\?(?::|=|!|<=|<!|<[A-Za-z_]\w*>)/.exec(src.slice(i));
          if (!m) fail('Unsupported group syntax in regex');
          look = /^\?(=|!|<=|<!)$/.test(m[0]); i += m[0].length;
        }
        const branches = parseAlt(depth + 1);
        if (src[i] !== ')') fail('Unbalanced parentheses in regex');
        i++;
        item = { kind: 'group', branches, look };
      } else if (c === '[') item = { kind: 'atom', src: parseClass() };
      else if (c === '\\') item = { kind: 'atom', src: atomEnd() };
      else if (c === '^' || c === '$') { i++; item = { kind: 'assert' }; }
      else { i++; item = { kind: 'atom', src: c === '.' ? '.' : c }; }
      const q = parseQuant();
      item.min = q ? q.min : 1; item.max = q ? q.max : 1;
      items.push(item);
    }
    return items;
  }

  const branches = parseAlt(0);
  if (i < src.length) fail('Unbalanced parentheses in regex');
  return branches;
}

// ---- character-set helpers -----------------------------------------------------------------
const setCache = new Map();
function atomSet(srcText, flags) {
  const key = flags + '\u0000' + srcText;
  if (setCache.has(key)) return setCache.get(key);
  const out = { codes: new Set(), hi: false };
  if (srcText.length === 1 && srcText !== '.') {
    const code = srcText.codePointAt(0);
    if (code < 256) { out.codes.add(code); if (flags.includes('i')) { out.codes.add(srcText.toLowerCase().charCodeAt(0)); out.codes.add(srcText.toUpperCase().charCodeAt(0)); } } else out.hi = true;
  } else {
    let re;
    try { re = new RegExp('^(?:' + srcText + ')$', flags + 's'); } catch { re = null; }
    if (!re) { for (let c = 0; c < 256; c++) out.codes.add(c); out.hi = true; }   // unknown: assume everything
    else {
      for (let c = 0; c < 256; c++) if (re.test(String.fromCharCode(c))) out.codes.add(c);
      out.hi = HI_SAMPLE.some((ch) => re.test(ch));
    }
  }
  setCache.set(key, out);
  return out;
}
const overlaps = (a, b) => (a.hi && b.hi) || [...a.codes].some((c) => b.codes.has(c));
const union = (a, b) => ({ codes: new Set([...a.codes, ...b.codes]), hi: a.hi || b.hi });
const EMPTY = () => ({ codes: new Set(), hi: false });

const nullableItem = (it) => it.min === 0 || it.kind === 'assert' || (it.kind === 'group' && it.branches.some(nullableSeq));
const nullableSeq = (items) => items.every(nullableItem);

function firstOfItem(it, flags) {
  if (it.kind === 'assert') return EMPTY();
  if (it.kind === 'atom') return atomSet(it.src, flags);
  return it.branches.reduce((acc, b) => union(acc, firstOfSeq(b, flags)), EMPTY());
}
function firstOfSeq(items, flags) {
  let acc = EMPTY();
  for (const it of items) { acc = union(acc, firstOfItem(it, flags)); if (!nullableItem(it)) break; }
  return acc;
}

const isUnbounded = (it) => it.max === Infinity || it.max > HIGH;
function containsUnbounded(items) {
  return items.some((it) => it.kind === 'group' ? (isUnbounded(it) || it.branches.some(containsUnbounded)) : isUnbounded(it));
}
function countUnbounded(items) {
  return items.reduce((n, it) => n + (isUnbounded(it) ? 1 : 0) + (it.kind === 'group' ? it.branches.reduce((m, b) => m + countUnbounded(b), 0) : 0), 0);
}

function walk(branches, flags) {
  for (const seq of branches) {
    for (let k = 0; k < seq.length; k++) {
      const it = seq[k];
      if (it.kind === 'group') {
        if (isUnbounded(it) && !it.look) {
          if (it.branches.some(containsUnbounded)) throw new RegexSafetyError('Regex has a nested quantifier such as (a+)+ which can hang the parser; simplify it');
          if (it.branches.some(nullableSeq)) throw new RegexSafetyError('Regex repeats a group that can match nothing, such as (a|)* ; simplify it');
          for (let x = 0; x < it.branches.length; x++) for (let y = x + 1; y < it.branches.length; y++) {
            if (overlaps(firstOfSeq(it.branches[x], flags), firstOfSeq(it.branches[y], flags))) {
              throw new RegexSafetyError('Regex repeats alternatives that start the same way, such as (a|ab)+ ; make the alternatives distinct');
            }
          }
        }
        walk(it.branches, flags);
      }
      const nx = seq[k + 1];
      if (it.kind === 'atom' && nx && nx.kind === 'atom' && isUnbounded(it) && isUnbounded(nx) && overlaps(atomSet(it.src, flags), atomSet(nx.src, flags))) {
        throw new RegexSafetyError('Regex has two adjacent repeats that match the same characters, such as \\d+\\d+ or .*.* ; merge them');
      }
    }
  }
}

// ---- public API ----------------------------------------------------------------------------
// Throws RegexSafetyError with a user-readable message. Returns { source, flags } on success
// (a leading "(?i)" is converted to the i flag, as the parsing-rule language has always done).
function assertSafeRegex(pattern, { mode = 'js', flags = '' } = {}) {
  let p = String(pattern), f = flags;
  if (p.startsWith('(?i)')) { p = p.slice(4); if (!f.includes('i')) f += 'i'; }
  const max = MAX_LEN[mode];
  if (!max) throw new Error('assertSafeRegex: unknown mode ' + mode);
  if (p.length > max) throw new RegexSafetyError(`Regex longer than ${max} characters`);
  if (mode === 'pg') {
    for (let i = 0; i < p.length; i++) {
      if (p[i] !== '\\') continue;
      const c = p[i + 1];
      if (c !== undefined && /[1-9]/.test(c)) throw new RegexSafetyError('Regex uses a back-reference (\\' + c + '), which is not allowed');
      i++;
    }
    return { source: p, flags: f };
  }
  const tree = parse(p);
  if (countUnbounded(tree.flat()) > MAX_UNBOUNDED) throw new RegexSafetyError(`Regex has more than ${MAX_UNBOUNDED} open-ended repeats (*, +, {n,}); simplify it`);
  walk(tree, f.replace(/[^i]/g, ''));
  return { source: p, flags: f };
}

// Cap on how much of a value a user regex is run against (bounds the cost of any pattern
// the analysis lets through).
const MAX_SUBJECT = 4096;
const clampSubject = (s) => (s.length > MAX_SUBJECT ? s.slice(0, MAX_SUBJECT) : s);

module.exports = { assertSafeRegex, RegexSafetyError, clampSubject, MAX_SUBJECT };
