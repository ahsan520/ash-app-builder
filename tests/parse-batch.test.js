'use strict';
// The parse step as a pure function (src/ingestion/parse-batch.js) and the rule sets built from rule text
// (src/ingestion/rule-sets.js): the pieces both the API (inline) and the parser workers run.
const test = require('node:test');
const assert = require('assert');
const { compile, apply, applyModel } = require('../src/ingestion/parsing-rules');
const { parseItems } = require('../src/ingestion/parse-batch');
const { buildSets } = require('../src/ingestion/rule-sets');

const P = compile(require('../src/ingestion/default-parsing-rules'), 'ingest').rules;
const M = compile(require('../src/ingestion/default-model-rules'), 'model').rules;
const ev = (app, message) => ({ raw: message, time: null, parsed: { format: 'syslog-file', host: 'h1', app_name: app, message } });

const USER_PARSING = `[INGEST:vendor="acme", product="app", target_dataset="acme_raw", source_type="syslog", no_hit=keep, content_id="acme"]
filter app_name = "acmed"
| alter tag = concat("a-", uppercase(host));`;
const USER_MODEL = `[MODEL: dataset=acme_raw]
alter xdm.event.description = tag;`;

test('buildSets with no user rules is the built-in sets, parsing and model', () => {
  for (const src of [undefined, {}, { parsing: '', model: '' }, { parsing: '  \n', model: '  ' }]) {
    const s = buildSets(src);
    assert.strictEqual(s.parsingSets.length, 1); assert.strictEqual(s.modelSets.length, 1);
  }
});

test('buildSets orders user rules as rules-store does: parsing user first, model user last', () => {
  const s = buildSets({ parsing: USER_PARSING, model: USER_MODEL });
  assert.strictEqual(s.parsingSets.length, 2); assert.strictEqual(s.modelSets.length, 2);
  assert.strictEqual(s.parsingSets[0][0].params.content_id, 'acme');          // user first
  assert.strictEqual(s.modelSets[1][0].params.dataset, 'acme_raw');           // user last
});

test('a broken user ruleset falls back to the built-in rules and never throws', () => {
  const log = console.error; console.error = () => {};
  try {
    const s = buildSets({ parsing: '[INGEST:content_id="a"] filter x = ;', model: 'not a rule' });
    assert.strictEqual(s.parsingSets.length, 1); assert.strictEqual(s.modelSets.length, 1);
  } finally { console.error = log; }
});

test('parseItems gives what the old inline loop gave: parse, xdm, drop, retarget', () => {
  const items = [
    ev('sshd', 'Failed password for invalid user bob from 203.0.113.9 port 51234 ssh2'),
    ev('kernel', 'eth0: link up'),
    ev('acmed', 'hello'),
    ev('other', 'plain'),
  ];
  const s = buildSets({ parsing: USER_PARSING, model: USER_MODEL });
  const { kept, dropped } = parseItems(s.parsingSets, s.modelSets, 'syslog', items.map((i) => structuredClone(i)));
  // reference: the loop that used to live in src/ingest/http-ingest.js, written out here
  const ref = []; let refDropped = 0;
  for (const it of items.map((i) => structuredClone(i))) {
    const o = apply(s.parsingSets, { source_type: 'syslog', raw: it.raw, time: it.time, parsed: it.parsed });
    if (o.dropped) { refDropped++; continue; }
    const mo = applyModel(s.modelSets, { source_type: o.source_type, raw: it.raw, time: o.time, parsed: o.parsed });
    if (mo.xdm) o.parsed.xdm = mo.xdm;
    ref.push({ raw: it.raw, time: o.time, parsed: o.parsed, source_type: o.source_type });
  }
  assert.deepStrictEqual(kept, ref); assert.strictEqual(dropped, refDropped);
  assert.strictEqual(kept.length, items.length - dropped);
  const acme = kept.find((k) => k.parsed._content_id === 'acme');
  assert.strictEqual(acme.source_type, 'acme_raw');                          // retargeted by target_dataset
  assert.strictEqual(acme.parsed.tag, 'a-H1');
  assert.strictEqual(acme.parsed.xdm.event.description, 'a-H1');             // user model rule ran on the new dataset
  assert.strictEqual(kept[0].parsed._content_id, 'linux_sshd');              // built-in rule still applies after the user rules
});

test('an event that only no_hit=drop rules apply to is dropped and counted, the rest are kept', () => {
  const drop = compile('[INGEST:content_id="noise", source_type="syslog", no_hit=drop] filter app_name = "chatty" | alter x = "1";', 'ingest').rules;
  const { kept, dropped } = parseItems([drop], [], 'syslog', [ev('chatty', 'a'), ev('other', 'b')]);
  assert.strictEqual(dropped, 1); assert.strictEqual(kept.length, 1); assert.strictEqual(kept[0].parsed._content_id, 'noise');
  // not a syslog event: the rule does not apply, so nothing is dropped
  assert.strictEqual(parseItems([drop], [], 'json', [ev('other', 'b')]).dropped, 0);
});

test('default rules alone: a sshd line is parsed and mapped, an unknown line is kept untouched', () => {
  const { kept, dropped } = parseItems([P], [M], 'syslog', [ev('sshd', 'Accepted publickey for root from 10.0.0.5 port 22 ssh2: RSA SHA256:abc'), ev('kernel', 'eth0: link up')]);
  assert.strictEqual(dropped, 0); assert.strictEqual(kept.length, 2);
  assert.strictEqual(kept[0].parsed._content_id, 'linux_sshd'); assert.strictEqual(kept[0].parsed.user, 'root');
  assert.ok(kept[0].parsed.xdm && kept[0].parsed.xdm.event);
  assert.strictEqual(kept[1].parsed._content_id, undefined);
});
