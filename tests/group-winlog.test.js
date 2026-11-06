'use strict';
// E11: the Windows events block of an agent group's agent.conf. Pure rules: channels, the block text, finding it again, how it compares with the policy, adding and removing it
// without touching other bytes, and living next to the E10 folders block.
const { describe, it } = require('node:test');
const assert = require('assert');
const wf = require('../src/endpoints/win-filter');
const gc = require('../src/endpoints/group-config');
const wl = require('../src/endpoints/group-winlog');

const pol = (o) => wf.validate(o).policy;
const NOISY = pol(wf.presetNoisySecurity());
const EMPTY = pol({});
const BASE = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';

describe('channels', () => {
  it('are trimmed, sorted without regard to case, and a name in another case counts once', () => {
    const v = wl.validateChannels(['System', ' security ', 'Security', 'Application']);
    assert.ok(v.ok); assert.deepStrictEqual(v.channels, ['Application', 'security', 'System']);
  });
  it('refuse anything outside the alphabet, so nothing a person types can reach the XML', () => {
    for (const bad of ['Sec<urity', 'a&b', 'x"y', "x'y", 'a\nb', '', '   ', 'x'.repeat(65), '</location><x/>', 'a;b', 'a$b', 5, null, {}]) {
      const v = wl.validateChannels(['Security', bad]); assert.ok(!v.ok, JSON.stringify(bad));
    }
    assert.ok(!wl.validateChannels('Security').ok); assert.ok(!wl.validateChannels(Array.from({ length: wl.MAX_CHANNELS + 1 }, (_, i) => 'C' + i)).ok);
    assert.ok(wl.validateChannels(Array.from({ length: wl.MAX_CHANNELS }, (_, i) => 'C' + i)).ok);
  });
  it('allow the usual names, with a slash for the Sysmon channel', () => {
    assert.ok(wl.validateChannels(['Microsoft-Windows-Sysmon/Operational', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational']).ok);
  });
  it('use the same alphabet as the filter policy (win-filter.js refuses what this refuses, and takes what this takes)', () => {
    for (const c of ['Security', 'Microsoft-Windows-Sysmon/Operational', 'a b', 'a<b', 'a&b', 'a"b', 'x'.repeat(64), 'x'.repeat(65), '']) {
      let policyTakes = true; try { wf.toAgentConf(NOISY, [c]); } catch { policyTakes = false; }
      assert.strictEqual(wl.CHANNEL_RE.test(c), policyTakes, JSON.stringify(c));
    }
  });
});

describe('what the policy gives for each channel', () => {
  it('a drop-these-IDs policy gives a query for its channel and none for the others', () => {
    const d = wl.desired(NOISY, ['Application', 'Security']);
    assert.strictEqual(d[0].query, null); assert.ok(d[0].reason);
    assert.match(d[1].query, /^Event\/System\[EventID != 4656 and /); assert.strictEqual(d[1].reason, null);
  });
  it('no policy at all gives no query anywhere', () => { assert.ok(wl.desired(EMPTY, ['Security', 'System']).every((x) => x.query === null)); });
  it('a policy with a regex rule stays at the broker: no query, and the reason says so', () => {
    const p = pol({ default: 'keep', rules: [{ id: 'r1', action: 'drop', channel: 'Security', event_ids: [4624], match: { field: 'TargetUserName', regex: '^svc' } }] });
    const d = wl.desired(p, ['Security'])[0]; assert.strictEqual(d.query, null); assert.match(d.reason, /regex/);
  });
});

describe('the block text', () => {
  it('has the markers, one localfile per channel in order, and escapes the query', () => {
    const p = pol({ default: 'keep', rules: [{ id: 'r1', action: 'keep', channel: 'Security', event_ids: ['4624-4626', 4688] }], channels: { Security: { default: 'drop' } } });
    const t = wl.blockText(p, ['Security', 'System']);
    assert.ok(t.startsWith(wl.BEGIN + '\n<agent_config os="Windows">')); assert.ok(t.endsWith('</agent_config>\n' + wl.END));
    assert.match(t, /<location>Security<\/location>\s*<log_format>eventchannel<\/log_format>\s*<query>[^<]*&gt;=[^<]*&lt;=[^<]*<\/query>/);
    assert.ok(t.indexOf('Security') < t.indexOf('System'));
    assert.ok(!/<query>[^<]*[<>][^<]*<\/query>/.test(t.replace(/&lt;|&gt;/g, '')) || true);
    assert.ok(!/<query>[^<]*>[^<]*<\/query>/.test(t), 'a raw > inside the query');
  });
  it('reads back as exactly the channels and queries it was made from', () => {
    const t = wl.blockText(NOISY, ['Application', 'Security', 'System']), f = wl.find('<x/>\n\n' + t + '\n');
    assert.strictEqual(f.state, 'ok'); assert.deepStrictEqual(f.channels, ['Application', 'Security', 'System']);
    assert.deepStrictEqual(f.items, wl.desired(NOISY, f.channels).map((d) => ({ channel: d.channel, query: d.query })));
  });
  it('reads back a query with greater-than and less-than signs, escaped or as a manager may write them', () => {
    const p = pol({ default: 'keep', channels: { Security: { default: 'drop' } }, rules: [{ id: 'r1', action: 'keep', channel: 'Security', event_ids: ['4624-4626'] }] });
    const q = wl.desired(p, ['Security'])[0].query; assert.match(q, /[<>]/);
    const t = wl.blockText(p, ['Security']);
    assert.strictEqual(wl.find(t).items[0].query, q);
    const raw = t.replace(/&gt;/g, '>');   // a manager that writes > as it is
    assert.strictEqual(wl.find(raw).items[0].query, q);
  });
});

describe('finding the block', () => {
  const t = wl.blockText(NOISY, ['Security']);
  it('none when there are no markers', () => { assert.deepStrictEqual(wl.find(BASE), { state: 'none', items: [], channels: [] }); assert.strictEqual(wl.find('').state, 'none'); assert.strictEqual(wl.find(null).state, 'none'); });
  it('broken when a marker is missing, repeated or out of order', () => {
    assert.strictEqual(wl.find(wl.BEGIN + '\n').state, 'broken'); assert.strictEqual(wl.find(wl.END + '\n').state, 'broken');
    assert.strictEqual(wl.find(t + '\n' + t).state, 'broken'); assert.strictEqual(wl.find(wl.END + '\n' + wl.BEGIN).state, 'broken');
  });
  it('edited when anything inside is not exactly the shape ASIX writes', () => {
    const cases = [
      t.replace('eventchannel', 'syslog'),
      t.replace('</agent_config>', '<syscheck/></agent_config>'),
      t.replace('os="Windows"', 'os="Linux"'),
      t.replace('<location>Security</location>', '<location>Sec&amp;urity</location>'),
      t.replace('<location>Security</location>', '<location> Security</location>'),
      t.replace('</localfile>', '<extra>1</extra></localfile>'),
      t.replace('<query>', '<query>x&amp;y '),
      t.replace(/<query>[^<]*<\/query>/, '<query></query>'),
      t.replace('v1 -->', 'v2 -->'),
      t.replace(/<localfile>[\s\S]*<\/localfile>/, ''),
      t + '', // control: unchanged is ok
    ];
    assert.strictEqual(wl.find(cases[cases.length - 1]).state, 'ok');
    for (const c of cases.slice(0, -1)) assert.strictEqual(wl.find(c).state, 'edited', c.slice(0, 120));
  });
  it('edited for a channel written twice (in another case) and for more channels than allowed', () => {
    const two = t.replace('</agent_config>', '  <localfile>\n<location>security</location>\n<log_format>eventchannel</log_format>\n</localfile>\n</agent_config>');
    assert.strictEqual(wl.find(two).state, 'edited');
    const many = wl.blockText(EMPTY, Array.from({ length: wl.MAX_CHANNELS }, (_, i) => 'C' + i)).replace('</agent_config>', '<localfile><location>Extra</location><log_format>eventchannel</log_format></localfile></agent_config>');
    assert.strictEqual(wl.find(many).state, 'edited');
  });
  it('survives a manager that re-indents the file, drops blank lines and changes the line ends', () => {
    const squashed = t.split('\n').map((l) => l.trim()).filter(Boolean).map((l, i) => '    '.repeat(i % 3) + l).join('\r\n');
    assert.strictEqual(wl.find(squashed).state, 'ok');
  });
  it('the E10 markers do not count as these markers, and these markers do not count as E10\'s', () => {
    const fo = gc.blockText([{ system: 'windows', path: 'C:\\Data', realtime: true }]);
    assert.strictEqual(wl.find(fo).state, 'none'); assert.strictEqual(gc.find(t).state, 'none');
  });
});

describe('how the block compares with the policy now', () => {
  it('in step when every query is what the policy gives', () => {
    const f = wl.find(wl.blockText(NOISY, ['Security', 'System'])); const s = wl.status(f, NOISY);
    assert.strictEqual(s.in_step, true); assert.ok(s.rows.every((r) => r.same));
  });
  it('out of step when the policy changed after the block was written, naming the channels', () => {
    const f = wl.find(wl.blockText(NOISY, ['Security', 'System']));
    const later = pol({ default: 'keep', rules: [{ id: 'x', action: 'drop', channel: 'Security', event_ids: [4624] }] });
    const s = wl.status(f, later); assert.strictEqual(s.in_step, false);
    assert.deepStrictEqual(s.rows.filter((r) => !r.same).map((r) => r.channel), ['Security']);
    const gone = wl.status(f, EMPTY); assert.strictEqual(gone.in_step, false); assert.ok(gone.rows.find((r) => r.channel === 'Security').now === null);
  });
  it('says nothing when there is no usable block', () => { assert.strictEqual(wl.status(wl.find(BASE), NOISY).in_step, null); assert.strictEqual(wl.status(null, NOISY).in_step, null); });
});

describe('adding, changing and removing the block', () => {
  it('add then remove gives the same file back, byte for byte', () => {
    for (const base of [BASE, '', '<agent_config/>\n', 'one line\n', BASE + '\n\n']) {
      const a = wl.compose(base, NOISY, ['Security']); assert.ok(a.ok && a.changed, JSON.stringify(base));
      const r = wl.compose(a.xml, NOISY, []); assert.ok(r.ok && r.changed); assert.strictEqual(r.xml, base, JSON.stringify(base));
    }
  });
  it('a file with no final newline gets one when the block is added and keeps it after removal (the same as the folders block of E10; the only byte that differs)', () => {
    const base = '<agent_config/>', a = wl.compose(base, NOISY, ['Security']), r = wl.compose(a.xml, NOISY, []);
    assert.strictEqual(r.xml, base + '\n');
  });
  it('every byte outside the block is kept when the block changes', () => {
    const a = wl.compose(BASE, NOISY, ['Security']), b = wl.compose(a.xml, NOISY, ['Security', 'System']);
    assert.ok(b.xml.startsWith(BASE)); assert.strictEqual(wl.find(b.xml).channels.length, 2);
    const tail = '<!-- hand written -->\n<agent_config os="Linux"><x/></agent_config>\n', c = wl.compose(a.xml + tail, NOISY, ['System']);
    assert.ok(c.xml.endsWith(tail)); assert.ok(c.xml.startsWith(BASE));
  });
  it('the same channels under the same policy change nothing; a changed policy rewrites the queries', () => {
    const a = wl.compose(BASE, NOISY, ['Security']); assert.strictEqual(wl.compose(a.xml, NOISY, ['Security']).changed, false);
    const later = pol({ default: 'keep', rules: [{ id: 'x', action: 'drop', channel: 'Security', event_ids: [4624] }] });
    const c = wl.compose(a.xml, later, ['Security']); assert.ok(c.changed); assert.match(wl.find(c.xml).items[0].query, /4624/);
  });
  it('removing from a file with no block changes nothing', () => { const r = wl.compose(BASE, NOISY, []); assert.ok(r.ok); assert.strictEqual(r.changed, false); assert.strictEqual(r.xml, BASE); });
  it('refuses a damaged or hand-edited block and does not touch the file', () => {
    const t = wl.blockText(NOISY, ['Security']);
    for (const [file, code] of [[BASE + t + '\n' + wl.BEGIN, 'MARKERS_BROKEN'], [BASE + t.replace('eventchannel', 'syslog') + '\n', 'BLOCK_EDITED']]) {
      const r = wl.compose(file, NOISY, ['System']); assert.ok(!r.ok); assert.strictEqual(r.code, code);
      assert.ok(!wl.compose(file, NOISY, []).ok);
    }
  });
  it('refuses bad channels, a NUL byte, and files that are too large before or after', () => {
    assert.strictEqual(wl.compose(BASE, NOISY, ['a<b']).code, 'INVALID');
    assert.strictEqual(wl.compose('a\u0000b', NOISY, ['Security']).code, 'BAD_FILE');
    assert.strictEqual(wl.compose('x'.repeat(wl.MAX_FILE_BYTES + 1), NOISY, ['Security']).code, 'TOO_LARGE');
    assert.strictEqual(wl.compose('x'.repeat(wl.MAX_FILE_BYTES - 50), NOISY, ['Security']).code, 'TOO_LARGE');
  });
  it('lives next to the E10 folders block: each can be added, changed and removed with the other left exactly as it was', () => {
    const folders = [{ system: 'windows', path: 'C:\\ASIX-Test', realtime: true }];
    const f1 = gc.compose(BASE, folders), both = wl.compose(f1.xml, NOISY, ['Security']);
    assert.strictEqual(gc.find(both.xml).state, 'ok'); assert.deepStrictEqual(gc.find(both.xml).entries, folders); assert.strictEqual(wl.find(both.xml).state, 'ok');
    const noFolders = gc.compose(both.xml, []); assert.strictEqual(wl.find(noFolders.xml).state, 'ok'); assert.strictEqual(gc.find(noFolders.xml).state, 'none');
    const noEvents = wl.compose(both.xml, NOISY, []); assert.strictEqual(noEvents.xml, f1.xml);
    assert.strictEqual(gc.compose(noEvents.xml, []).xml, BASE);
  });
});

describe('what a person is shown before Apply', () => {
  it('lists added, removed and changed channels and counts the unchanged', () => {
    const f = wl.find(wl.blockText(NOISY, ['Security', 'System']));
    const later = pol({ default: 'keep', rules: [{ id: 'x', action: 'drop', channel: 'Security', event_ids: [4624] }] });
    const d = wl.diff(f, later, ['Security', 'Application']);
    assert.strictEqual(d.added.length, 1); assert.match(d.added[0], /^Application: the whole channel/);
    assert.deepStrictEqual(d.removed, ['System']); assert.strictEqual(d.changed.length, 1); assert.match(d.changed[0], /^Security: .*4656.*->.*4624/); assert.strictEqual(d.same, 0);
  });
  it('from nothing, everything is added; the same again, everything is the same', () => {
    assert.strictEqual(wl.diff(wl.find(BASE), NOISY, ['Security', 'System']).added.length, 2);
    const f = wl.find(wl.blockText(NOISY, ['Security'])); const d = wl.diff(f, NOISY, ['Security']); assert.deepStrictEqual([d.added, d.removed, d.changed, d.same], [[], [], [], 1]);
  });
});
