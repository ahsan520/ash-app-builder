'use strict';
// The Windows event filter policy (src/endpoints/win-filter.js, docs/endpoints.md task E1). Three layers:
//   1. validation and the reference evaluation (evaluate()), pure JavaScript;
//   2. the Wazuh agent-group output (XPath and <localfile>);
//   3. with a real Vector binary (VECTOR_BIN, or `vector` on PATH; written against 0.59.0) the generated transform is validated and `vector test` checks that it
//      keeps, drops and strips exactly what evaluate() says, on the same events. Skipped, with a message, when there is no Vector.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const w = require('../src/endpoints/win-filter');

const ok = (p) => { const v = w.validate(p); assert.deepStrictEqual(v.errors, []); return v.policy; };
const bad = (p) => { const v = w.validate(p); assert.strictEqual(v.ok, false); return v.errors.join(' | '); };
const ev = (channel, event_id, extra = {}) => ({ channel, event_id, fields: {}, message: 'text', ...extra });

const POLICY = {
  channels: { Application: { default: 'drop' } },
  rules: [
    { id: 'r1', action: 'drop', channel: 'Security', event_ids: [4656, '4700-4710'] },
    { id: 'r2', action: 'keep', event_ids: [5145], match: { field: 'SubjectUserName', regex: '^backup' } },
    { id: 'r3', action: 'drop', event_ids: [5145] },
    { id: 'r4', action: 'drop', channel: 'Microsoft-Windows-Sysmon/Operational', match: { regex: 'svchost\\.exe' } }],
  message_strip: [{ channel: 'Security', regex: '\\n\\nThis event is generated[\\s\\S]*$' }],
};

describe('Windows filter policy: validation', () => {
  it('an empty policy is valid and keeps everything', () => {
    const p = ok({}); assert.deepStrictEqual(p, { version: 1, default: 'keep', channels: {}, rules: [], strip_message: false, message_strip: [] });
    assert.strictEqual(w.evaluate(p, ev('Security', 4624)).keep, true);
  });
  it('event IDs are numbers, numeric text or ranges, and are normalised to [lo, hi]', () => {
    assert.deepStrictEqual(ok({ rules: [{ id: 'a', action: 'drop', event_ids: [4624, '4625', ' 4700-4710 ']}] }).rules[0].ids, [[4624, 4624], [4625, 4625], [4700, 4710]]);
    for (const x of [-1, 65536, '4710-4700', 'abc', '1-', '', 1.5, null]) assert.match(bad({ rules: [{ id: 'a', action: 'drop', event_ids: [x] }] }), /every event ID/, String(x));
    assert.match(bad({ rules: [{ id: 'a', action: 'drop', event_ids: [] }] }), /1 to 100/);
  });
  it('rejects bad shapes with a message that names the rule', () => {
    assert.match(bad(null), /must be an object/); assert.match(bad([]), /must be an object/);
    assert.match(bad({ version: 2 }), /version/); assert.match(bad({ default: 'allow' }), /default/);
    assert.match(bad({ strip_message: 'yes' }), /strip_message/); assert.match(bad({ rules: {} }), /rules must be a list/);
    assert.match(bad({ rules: [{ id: 'A B', action: 'drop' }] }), /rule 1: id/); assert.match(bad({ rules: [{ id: 'a', action: 'maybe' }] }), /rule 1: action/);
    assert.match(bad({ rules: [{ id: 'a', action: 'drop' }, { id: 'a', action: 'keep' }] }), /rule 2: id "a" is used twice/);
    assert.match(bad({ rules: [{ id: 'a', action: 'drop', channel: 'Sec"urity' }] }), /channel is not valid/);
    assert.match(bad({ rules: [{ id: 'a', action: 'drop', match: { field: 'a.b', regex: 'x' } }] }), /match.field/);
    assert.match(bad({ channels: { 'Bad"name': { default: 'keep' } } }), /not valid/); assert.match(bad({ channels: { Security: { default: 'x' } } }), /default/);
    assert.match(bad({ rules: Array.from({ length: w.MAX_RULES + 1 }, (_, i) => ({ id: 'r' + i, action: 'drop' })) }), /more than 200 rules/);
    assert.match(bad({ message_strip: [{ regex: '' }] }), /message_strip 1: regex/);
  });
  it('accepts only the regex syntax Rust and JavaScript read the same way', () => {
    for (const r of ['^svc_[a-z]+$', '\\n\\nThis event is generated[\\s\\S]*$', 'a{2,3}b', '(?:a|b)+', '\\{x\\}', 'svchost\\.exe', '\\x27']) assert.strictEqual(w.checkRegex(r), null, r);
    const no = { '[^]': /empty character class/, 'a[]b': /empty character class/, '[a[b]': /inside a character class/, '[a&&b]': /set operations/, 'a{x}': /not a quantifier/,
      '(?i)x': /\(\? syntax/, '(?=x)': /\(\? syntax/, '(?<n>x)': /\(\? syntax/, 'x\\1': /back-references/, '\\p{L}': /back-references/, '\\Aabc': /back-references/,
      "it's": /single quote/, 'a\nb': /control character/, '[a': /never closed/, '(': /not a valid/, ['a'.repeat(301)]: /longer than 300/, '': /non-empty/ };
    for (const [r, m] of Object.entries(no)) assert.match(w.checkRegex(r), m, JSON.stringify(r));
    assert.match(w.checkRegex(5), /non-empty/);
  });
});

describe('Windows filter policy: evaluate()', () => {
  const p = ok(POLICY);
  it('first matching rule wins; channel and event ID matching ignores case', () => {
    assert.deepStrictEqual(w.evaluate(p, ev('Security', 4656)).keep, false);
    assert.strictEqual(w.evaluate(p, ev('security', 4656)).rule_id, 'r1');
    assert.strictEqual(w.evaluate(p, ev('Security', 4705)).keep, false);       // inside the range
    assert.strictEqual(w.evaluate(p, ev('Security', 4711)).keep, true);        // just outside it
    assert.strictEqual(w.evaluate(p, ev('System', 4656)).keep, true);          // r1 is for Security only
    assert.strictEqual(w.evaluate(p, ev('Security', 5145, { fields: { subjectusername: 'backup01' } })).rule_id, 'r2');   // keep before the general drop, field names ignore case
    assert.strictEqual(w.evaluate(p, ev('Security', 5145, { fields: { SubjectUserName: 'bob' } })).rule_id, 'r3');
    assert.strictEqual(w.evaluate(p, ev('Security', 5145)).keep, false);       // field missing: the regex has nothing to match, falls through to r3
  });
  it('a rule with a regex and no field looks at the rendered message', () => {
    assert.strictEqual(w.evaluate(p, ev('Microsoft-Windows-Sysmon/Operational', 1, { message: 'Image: C:\\Windows\\System32\\svchost.exe' })).keep, false);
    assert.strictEqual(w.evaluate(p, ev('Microsoft-Windows-Sysmon/Operational', 1, { message: 'Image: C:\\x\\cmd.exe' })).keep, true);
    assert.strictEqual(w.evaluate(p, ev('Microsoft-Windows-Sysmon/Operational', 1, { message: undefined })).keep, true);
  });
  it('no rule matching falls back to the channel default, then the policy default', () => {
    assert.strictEqual(w.evaluate(p, ev('Application', 1000)).keep, false);
    assert.strictEqual(w.evaluate(p, ev('application', 1000)).keep, false);
    assert.strictEqual(w.evaluate(p, ev('System', 7036)).keep, true);
    assert.strictEqual(w.evaluate(ok({ default: 'drop', channels: { Security: { default: 'keep' } } }), ev('Security', 1)).keep, true);
    assert.strictEqual(w.evaluate(ok({ default: 'drop' }), ev('System', 1)).keep, false);
  });
  it('a kept event loses the matching trailing text, in order; a dropped one has no message', () => {
    const r = w.evaluate(p, ev('Security', 4624, { message: 'An account logged on.\n\nThis event is generated when a logon session is created.\nMore.' }));
    assert.deepStrictEqual([r.keep, r.message], [true, 'An account logged on.']);
    assert.strictEqual(w.evaluate(p, ev('System', 7036, { message: 'a\n\nThis event is generated x' })).message, 'a\n\nThis event is generated x');   // strip is for Security only
    assert.strictEqual(w.evaluate(p, ev('Security', 4656)).message, null);
    assert.strictEqual(w.evaluate(p, ev('Security', 4624, { message: undefined })).message, null);
    const two = ok({ message_strip: [{ regex: 'a+' }, { regex: 'b' }] }); assert.strictEqual(w.evaluate(two, ev('X', 1, { message: 'aabcb' })).message, 'c');
    assert.strictEqual(w.evaluate(ok({ strip_message: true }), ev('Security', 4624)).message, null);
  });
  it('the suggested preset is valid, drops the noisy IDs on Security and removes the message', () => {
    const q = ok(w.presetNoisySecurity());
    for (const id of [4656, 4658, 4690, 5145, 5156, 5158]) assert.strictEqual(w.evaluate(q, ev('Security', id)).keep, false, String(id));
    for (const id of [4624, 4625, 4688, 4720]) assert.strictEqual(w.evaluate(q, ev('Security', id)).message, null, String(id));
    assert.strictEqual(w.evaluate(q, ev('System', 5156)).keep, true);
  });
});

describe('Windows filter policy: Wazuh agent group output', () => {
  const x = (p, c = 'Security') => w.toXPath(ok(p), c);
  it('deny by ID with default keep becomes an exclusion; allow by ID with default drop becomes an inclusion', () => {
    assert.strictEqual(x(w.presetNoisySecurity()).query, 'Event/System[EventID != 4656 and EventID != 4658 and EventID != 4690 and EventID != 5145 and EventID != 5156 and EventID != 5158]');
    assert.strictEqual(x({ rules: [{ id: 'a', action: 'drop', event_ids: [4656, '4700-4710'] }] }).query, 'Event/System[EventID != 4656 and (EventID < 4700 or EventID > 4710)]');
    assert.strictEqual(x({ default: 'drop', rules: [{ id: 'a', action: 'keep', event_ids: [4624, '4720-4726'] }] }).query, 'Event/System[EventID = 4624 or (EventID >= 4720 and EventID <= 4726)]');
    assert.strictEqual(x({ channels: { Security: { default: 'drop' } }, rules: [{ id: 'a', action: 'keep', channel: 'Security', event_ids: [4624] }] }).query, 'Event/System[EventID = 4624]');
  });
  it('rules for other channels are ignored; anything XPath cannot say stays at the broker, with the reason', () => {
    assert.strictEqual(x({ rules: [{ id: 'a', action: 'drop', channel: 'Security', event_ids: [1] }] }, 'System').query, null);
    const why = (p, c) => x(p, c).reason;
    assert.match(why({}), /nothing to filter/);
    assert.match(why({ default: 'drop' }), /leave the channel out/);
    assert.match(why(POLICY), /regex/);
    assert.match(why({ rules: [{ id: 'a', action: 'drop', event_ids: [1] }, { id: 'b', action: 'keep', event_ids: [2] }] }), /mixed/);
    assert.match(why({ rules: [{ id: 'a', action: 'drop' }] }), /whole channel/);
    assert.match(why({ rules: [{ id: 'a', action: 'keep', event_ids: [1] }] }), /do not change/);
    assert.match(why({ rules: [{ id: 'a', action: 'drop', event_ids: Array.from({ length: 100 }, (_, i) => 1000 + i * 3) }] }), /longer than 1024/);
  });
  it('the agent.conf blocks escape the query and leave the query out where there is none', () => {
    const p = ok({ rules: [{ id: 'a', action: 'drop', channel: 'Security', event_ids: ['4700-4710'] }] });
    assert.strictEqual(w.toAgentConf(p, ['Security', 'Microsoft-Windows-Sysmon/Operational']),
      '<localfile>\n  <location>Security</location>\n  <log_format>eventchannel</log_format>\n  <query>Event/System[(EventID &lt; 4700 or EventID &gt; 4710)]</query>\n</localfile>\n'
      + '<localfile>\n  <location>Microsoft-Windows-Sysmon/Operational</location>\n  <log_format>eventchannel</log_format>\n</localfile>');
    assert.throws(() => w.toAgentConf(p, ['Sec"urity']), /not valid/);
  });
  it('the transform wrapper checks its names, since they are written unquoted', () => {
    assert.throws(() => w.toVectorTransform(ok({}), { name: 'a b' }), /name/); assert.throws(() => w.toVectorTransform(ok({}), { inputs: ['x"'] }), /inputs/);
    assert.throws(() => w.toVectorTransform(ok({}), { inputs: [] }), /inputs/);
    assert.match(w.toVectorTransform(ok({}), { name: 'f', inputs: ['a', 'b'] }), /^\[transforms\.f\]\ntype = "remap"\ninputs = \["a", "b"\]\ndrop_on_abort = true\n/);
  });
});

// ---- the generated transform in a real Vector ----
const VECTOR = process.env.VECTOR_BIN || (spawnSync('vector', ['--version']).status === 0 ? 'vector' : null);
const wz = (e) => { // an event as Wazuh writes it
  const f = {}; for (const [k, v] of Object.entries(e.fields || {})) f[k.charAt(0).toLowerCase() + k.slice(1)] = v;
  const log = { 'data.win.system.channel': e.channel, 'data.win.system.eventID': e.event_id === undefined ? undefined : String(e.event_id) };
  if (e.message !== undefined) log['data.win.system.message'] = e.message;
  for (const [k, v] of Object.entries(f)) log['data.win.eventdata.' + k] = v;
  return Object.fromEntries(Object.entries(log).filter(([, v]) => v !== undefined));
};
const q = (s) => JSON.stringify(s);   // a TOML basic string (ASCII text with \n and \" escapes)
function runVector(policy, events) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'winfilter-')), file = path.join(dir, 'v.toml');
  let t = '[sources.wazuh_events]\ntype = "demo_logs"\nformat = "json"\ncount = 1\n\n' + w.toVectorTransform(policy) + '\n[sinks.out]\ntype = "blackhole"\ninputs = ["asix_win_filter"]\n\n';
  events.forEach((e, i) => {
    const want = w.evaluate(policy, e);
    t += '[[tests]]\nname = ' + q('case-' + i) + '\n\n[[tests.inputs]]\ninsert_at = "asix_win_filter"\ntype = "log"\n[tests.inputs.log_fields]\n';
    for (const [k, v] of Object.entries(wz(e))) t += q(k) + ' = ' + q(v) + '\n';
    if (!want.keep) t += '\n[tests.no_outputs_from]\n';   // placeholder replaced below
    else t += '\n[[tests.outputs]]\nextract_from = "asix_win_filter"\n[[tests.outputs.conditions]]\ntype = "vrl"\nsource = \'\'\'\n' + (want.message === null ? '!exists(.data.win.system.message)' : '.data.win.system.message == ' + q(want.message)) + '\n\'\'\'\n';
    t += '\n';
  });
  t = t.replace(/\[tests\.no_outputs_from\]\n/g, '').replace(/(name = "case-\d+"\n)(\n\[\[tests\.inputs\]\][^]*?)(?=\n\[\[tests\]\]|\s*$)/g, (m, n, rest) => (rest.includes('[[tests.outputs]]') ? m : n + 'no_outputs_from = ["asix_win_filter"]\n' + rest));
  fs.writeFileSync(file, t);
  const v = spawnSync(VECTOR, ['validate', '--no-environment', file], { encoding: 'utf8' }), r = spawnSync(VECTOR, ['test', file], { encoding: 'utf8' });
  return { validate: v, test: r, file, text: t };
}

describe('Windows filter policy: the generated Vector transform agrees with evaluate()', { skip: VECTOR ? false : 'no Vector binary (set VECTOR_BIN or put `vector` on PATH)' }, () => {
  const events = [
    ev('Security', 4656), ev('security', 4656), ev('Security', 4705), ev('Security', 4711, { message: 'kept' }),
    ev('Security', 5145, { fields: { SubjectUserName: 'backup01' }, message: 'share' }), ev('Security', 5145, { fields: { SubjectUserName: 'bob' } }), ev('Security', 5145),
    ev('Microsoft-Windows-Sysmon/Operational', 1, { message: 'Image: C:\\Windows\\System32\\svchost.exe' }), ev('Microsoft-Windows-Sysmon/Operational', 1, { message: 'Image: C:\\x\\cmd.exe' }),
    ev('Application', 1000), ev('System', 7036, { message: 'a\n\nThis event is generated x' }),
    ev('Security', 4624, { message: 'An account logged on.\n\nThis event is generated when a logon session is created.\nMore.' }), ev('Security', 4624, { message: undefined }),
    ev('Security', undefined, { message: 'no id' })];
  it('keeps, drops and strips exactly what the reference evaluation says (event IDs arrive as text, as Wazuh writes them)', () => {
    const r = runVector(ok(POLICY), events);
    assert.strictEqual(r.validate.status, 0, r.validate.stdout + r.validate.stderr);
    assert.strictEqual(r.test.status, 0, r.test.stdout + r.test.stderr + '\n' + r.text);
    assert.match(r.test.stdout + r.test.stderr, /14 tests|test result|passed/i);
    assert.ok(!/warning\[/.test(r.test.stdout + r.test.stderr), 'Vector warned about the generated program:\n' + r.test.stderr);
  });
  it('a policy that uses none, some or all of channel, event ID and message compiles without warnings', () => {
    const cases = [{}, { default: 'drop' }, { rules: [{ id: 'a', action: 'drop', event_ids: [1] }] }, { rules: [{ id: 'a', action: 'drop', channel: 'X' }] },
      { rules: [{ id: 'a', action: 'drop', match: { regex: 'x' } }] }, { rules: [{ id: 'a', action: 'drop', match: { field: 'Foo', regex: 'x' } }] },
      { message_strip: [{ regex: 'x' }] }, { message_strip: [{ channel: 'X', event_ids: [2], regex: 'x' }] }, { strip_message: true }, { channels: { X: { default: 'drop' } } }];
    for (const c of cases) {
      const r = runVector(ok(c), [ev('X', 1, { message: 'x' }), ev('Y', 2, { message: 'y' })]);
      assert.strictEqual(r.test.status, 0, JSON.stringify(c) + '\n' + r.test.stdout + r.test.stderr + '\n' + r.text);
      assert.ok(!/warning\[/.test(r.test.stdout + r.test.stderr), JSON.stringify(c) + '\n' + r.test.stderr);
    }
  });
  it('the strip-everything preset removes the message from kept events and drops the noisy IDs', () => {
    const r = runVector(ok(w.presetNoisySecurity()), [ev('Security', 4624, { message: 'x' }), ev('Security', 5156), ev('System', 5156, { message: 'y' })]);
    assert.strictEqual(r.validate.status, 0, r.validate.stdout + r.validate.stderr);
    assert.strictEqual(r.test.status, 0, r.test.stdout + r.test.stderr + '\n' + r.text);
  });
  it('the test itself can fail: a policy that drops what the expectation keeps is reported', () => {
    const p = ok(POLICY), r = runVector(p, [ev('Security', 4711, { message: 'kept' })]);
    assert.strictEqual(r.test.status, 0);
    const wrong = fs.readFileSync(r.file, 'utf8').replace('.data.win.system.message == "kept"', '.data.win.system.message == "something else"');
    fs.writeFileSync(r.file, wrong);
    assert.notStrictEqual(spawnSync(VECTOR, ['test', r.file], { encoding: 'utf8' }).status, 0);
  });
});
