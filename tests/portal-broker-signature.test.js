'use strict';
// The "Config check" cell and the summary on the signing line of the Brokers page (src/portal/index.html). The page has no build step, so the two functions
// are cut out of the file and run here with small stand-ins for el(), pill() and when().
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../src/brokers/config');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, attrs, ...kids) => ({ tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
const pill = (text, cls) => ({ pill: text, cls });
const when = (t) => 'T' + (t ? '' : '?');
const copyBtn = () => ({ copy: true });
const { brokerSignatureCell, brokerSigningLine } = new Function('el', 'pill', 'when', 'copyBtn', cut('brokerSignatureCell') + '\n' + cut('brokerSigningLine') + '\nreturn { brokerSignatureCell, brokerSigningLine };')(el, pill, when, copyBtn);
const texts = (n) => (n && typeof n === 'object' ? [n.pill, n.attrs && n.attrs.textContent, n.attrs && n.attrs.title, ...(n.kids || []).flatMap(texts)] : [n]).filter((x) => typeof x === 'string' && x);
const pills = (n) => (n && typeof n === 'object' ? [...(n.pill ? [{ text: n.pill, cls: n.cls }] : []), ...(n.kids || []).flatMap(pills)] : []);

describe('Brokers page: Config check cell', () => {
  const cell = (g) => brokerSignatureCell({ signature: g });
  it('one pill per state, the right colour, and a tooltip that says what to do', () => {
    assert.deepStrictEqual(pills(cell({ state: 'verifying', reported_at: 1 })), [{ text: 'Checks', cls: 'ok' }]);
    assert.deepStrictEqual(pills(cell({ state: 'waiting' })), [{ text: 'Waiting', cls: 'off' }]);
    assert.deepStrictEqual(pills(cell({ state: 'stale', reported_at: 1 })), [{ text: 'Not asking', cls: 'off' }]);
    assert.deepStrictEqual(pills(cell({ state: 'not_verifying', signing_on: false })), [{ text: 'Not checking', cls: 'off' }]);
    assert.deepStrictEqual(pills(cell({ state: 'unknown' })), [{ text: 'Not reporting', cls: 'off' }]);
    assert.deepStrictEqual(pills(cell(undefined)), [{ text: 'Not reporting', cls: 'off' }], 'a broker object without the field does not throw');
    assert.match(texts(cell({ state: 'unknown' })).join(' '), /--accept-config/);
  });
  it('a refusal shows its reason in words, in the bad colour, with the help text and the fact that nothing changed', () => {
    for (const p of config.SIGNATURE_PROBLEMS) {
      const c = cell({ state: 'refused', problem: p, help: config.SIGNATURE_HELP[p], reported_at: 1 });
      assert.deepStrictEqual(pills(c), [{ text: 'Refused: ' + p.replace(/_/g, ' '), cls: 'bad' }], p);
      assert.ok(texts(c).join(' ').includes(config.SIGNATURE_HELP[p]) && /changed nothing/.test(texts(c).join(' ')), p);
    }
  });
  it('a broker that does not check says whether ASIX signs, so the gap is visible', () => {
    const on = texts(cell({ state: 'not_verifying', signing_on: true })).join(' '), off = texts(cell({ state: 'not_verifying', signing_on: false })).join(' ');
    assert.match(on, /ASIX signs/); assert.match(on, /--config-pubkey/); assert.match(off, /does not sign/); assert.ok(!/\(ASIX signs\)/.test(off));
  });
  it('a stale refusal still names what it was refusing', () => assert.match(texts(cell({ state: 'stale', problem: 'bad_signature', reported_at: 1 })).join(' '), /bad signature/));
});

describe('Brokers page: signing line summary', () => {
  const sg = { enabled: true, key_id: 'abc123', public_key: 'PEM', error: null };
  const sum = (o) => ({ signature_verifying: 0, signature_not_verifying: 0, signature_refused: 0, ...o });
  it('some brokers not checking while ASIX signs: a bad "N of M" pill; all checking: an ok pill', () => {
    assert.ok(pills(brokerSigningLine(sg, sum({ signature_verifying: 1, signature_not_verifying: 2 }))).some((p) => p.text === '1 of 3 brokers check it' && p.cls === 'bad'));
    assert.ok(pills(brokerSigningLine(sg, sum({ signature_verifying: 2 }))).some((p) => p.text === 'All 2 reporting brokers check it' && p.cls === 'ok'));
  });
  it('refusing brokers are counted whether or not ASIX signs; no brokers reporting, or no summary, adds nothing', () => {
    assert.ok(pills(brokerSigningLine(sg, sum({ signature_verifying: 1, signature_refused: 1 }))).some((p) => p.text === '1 refusing the answer' && p.cls === 'bad'));
    assert.ok(pills(brokerSigningLine({ enabled: false, error: null }, sum({ signature_refused: 1 }))).some((p) => p.text === '1 refusing the answer'));
    assert.deepStrictEqual(pills(brokerSigningLine(sg, sum())).map((p) => p.text), ['Answers signed (key abc123)']);
    assert.deepStrictEqual(pills(brokerSigningLine(sg, undefined)).map((p) => p.text), ['Answers signed (key abc123)']);
    assert.deepStrictEqual(pills(brokerSigningLine({ enabled: false, error: null }, sum({ signature_not_verifying: 3 }))).map((p) => p.text), ['Answers not signed'], 'nothing to compare against when ASIX does not sign');
  });
  it('without a signing status there is nothing to draw', () => assert.strictEqual(brokerSigningLine(null, sum()), ''));
});
