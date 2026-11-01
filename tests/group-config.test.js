'use strict';
// E10: the pure rules for the ASIX block of a group's agent.conf (src/endpoints/group-config.js).
const { describe, it } = require('node:test');
const assert = require('assert');
const gc = require('../src/endpoints/group-config');

const BASE = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';
const L = (path, realtime = false) => ({ system: 'linux', path, realtime });
const W = (path, realtime = false) => ({ system: 'windows', path, realtime });

describe('paths', () => {
  it('accepts ordinary Linux and Windows folders', () => {
    for (const p of ['/srv/data', '/opt/my app/logs', '/home/user_1/.config', '/etc/nginx/conf.d/', '/data/a+b@c=d,e~f']) assert.strictEqual(gc.checkPath('linux', p), null, p);
    for (const p of ['C:\\Users\\Public', 'D:\\Data\\My Files', '%ProgramFiles%\\App', '%SystemRoot%\\System32\\drivers\\etc', 'C:\\Program Files (x86)\\App\\', 'c:\\temp']) assert.strictEqual(gc.checkPath('windows', p), null, p);
  });
  it('refuses what could reach the XML, the shell, or the whole machine', () => {
    for (const p of ['', ' /x', '/x ', 'relative/path', '/', '//', '/proc', '/proc/1', '/sys/kernel', '/dev', '/run/lock', '/a/../etc', '/a//b', '/a*', '/a?b', '/a<b', '/a&b', '/a"b', "/a'b", '/a`b', '/a$b', '/a;b', '/a|b', '/a{b}', '/a[b]', '/a\nb', '/a\u0000b', '/a\\b', '/' + 'x'.repeat(260)]) assert.ok(gc.checkPath('linux', p), 'linux ' + JSON.stringify(p.slice(0, 30)));
    for (const p of ['', 'C:', 'C:\\', 'D:/', 'C:/Users', '\\\\server\\share', 'C:\\a\\..\\b', 'C:\\a*', 'C:\\a<b', 'C:\\a"b', '%X%%Y%', '%bad var%\\x', 'Users\\Public', 'C:\\a\\\\b']) assert.ok(gc.checkPath('windows', p), 'windows ' + JSON.stringify(p));
    assert.ok(gc.checkPath('plan9', '/x')); assert.ok(gc.checkPath('linux', 5)); assert.ok(gc.checkPath('linux', null));
  });
});

describe('validate', () => {
  it('normalises: trailing separators dropped, Linux first, then by path', () => {
    const v = gc.validate([W('D:\\b\\'), L('/z/'), L('/a'), W('C:\\a')]);
    assert.ok(v.ok); assert.deepStrictEqual(v.entries.map((e) => e.system + e.path), ['linux/a', 'linux/z', 'windowsC:\\a', 'windowsD:\\b']);
  });
  it('refuses duplicates (Windows ignoring case), unknown fields, wrong types, too many entries and too many real-time ones', () => {
    assert.ok(!gc.validate([L('/a'), L('/a/')]).ok); assert.ok(!gc.validate([W('C:\\A'), W('c:\\a')]).ok); assert.ok(gc.validate([L('/a'), W('/a'.replace('/a', 'C:\\a'))]).ok);
    assert.ok(!gc.validate([{ system: 'linux', path: '/a', report_changes: true }]).ok); assert.ok(!gc.validate([{ system: 'linux', path: '/a', realtime: 'yes' }]).ok); assert.ok(!gc.validate([{ system: 'mac', path: '/a' }]).ok);
    assert.ok(!gc.validate('x').ok); assert.ok(!gc.validate([null]).ok); assert.ok(!gc.validate([[]]).ok);
    assert.ok(!gc.validate(Array.from({ length: 51 }, (_, i) => L('/d' + i))).ok); assert.ok(gc.validate(Array.from({ length: 50 }, (_, i) => L('/d' + i))).ok);
    assert.ok(!gc.validate(Array.from({ length: 11 }, (_, i) => L('/d' + i, true))).ok); assert.ok(gc.validate(Array.from({ length: 10 }, (_, i) => L('/d' + i, true))).ok);
  });
  it('system is case-insensitive in the input and lower case in the output; realtime defaults to false', () => {
    const v = gc.validate([{ system: 'LINUX', path: '/a' }]); assert.deepStrictEqual(v.entries, [{ system: 'linux', path: '/a', realtime: false }]);
  });
});

describe('compose and find', () => {
  const E_ONE = [L('/opt/app')];
  const E = [L('/srv/data', true), L('/opt/app'), W('C:\\Users\\Public')];
  it('adds one block at the end and keeps every other byte', () => {
    const c = gc.compose(BASE, E); assert.ok(c.ok && c.changed); assert.ok(c.xml.startsWith(BASE));
    assert.strictEqual(c.xml.split(gc.BEGIN).length, 2); assert.strictEqual(c.xml.split(gc.END).length, 2);
    assert.match(c.xml, /<agent_config os="Linux">\s*<syscheck>\s*<directories>\/opt\/app<\/directories>\s*<directories realtime="yes">\/srv\/data<\/directories>/);
    assert.match(c.xml, /<agent_config os="Windows">\s*<syscheck>\s*<directories>C:\\Users\\Public<\/directories>/);
  });
  it('reads back exactly what it wrote, and an empty list removes the block so the file is as it was', () => {
    const c = gc.compose(BASE, E); const f = gc.find(c.xml); assert.strictEqual(f.state, 'ok'); assert.deepStrictEqual(f.entries, gc.validate(E).entries);
    const r = gc.compose(c.xml, []); assert.ok(r.ok && r.changed); assert.strictEqual(r.xml, BASE);
    for (const base of ['', '<a/>\n\n<b/>\n', '<agent_config/>']) { const x = gc.compose(gc.compose(base, E).xml, []); assert.ok(x.ok); assert.strictEqual(x.xml.trim(), base.trim()); }
  });
  it('replaces only the block when one exists, and the text before and after stays', () => {
    const withTail = gc.compose(BASE, E).xml + '<agent_config os="Linux" name="x"><x/></agent_config>\n';
    const c = gc.compose(withTail, [W('D:\\Only')]); assert.ok(c.ok && c.changed);
    assert.ok(c.xml.startsWith(BASE)); assert.ok(c.xml.endsWith('<agent_config os="Linux" name="x"><x/></agent_config>\n')); assert.ok(!/\/srv\/data/.test(c.xml)); assert.deepStrictEqual(gc.find(c.xml).entries, [{ system: 'windows', path: 'D:\\Only', realtime: false }]);
  });
  it('the same list again changes nothing; removing a block that is not there changes nothing', () => {
    const c = gc.compose(BASE, E).xml; assert.strictEqual(gc.compose(c, E).changed, false); assert.strictEqual(gc.compose(c, [...E].reverse()).changed, false); assert.strictEqual(gc.compose(BASE, []).changed, false);
  });
  it('a value edited by hand that is still in the ASIX format is the list (and is shown as such)', () => {
    const c = gc.compose(BASE, E_ONE).xml.replace('/opt/app', '/opt/app2'); assert.deepStrictEqual(gc.find(c).entries.map((e) => e.path), ['/opt/app2']);
  });
  it('refuses damaged markers, a block edited by hand, and files that are too large or hold NUL', () => {
    const c = gc.compose(BASE, E).xml;
    for (const bad of [c.replace(gc.END, ''), c.replace(gc.BEGIN, ''), c + c.slice(c.indexOf(gc.BEGIN)), c.replace(gc.BEGIN, gc.END + '\n' + gc.BEGIN)]) { const r = gc.compose(bad, E); assert.ok(!r.ok); assert.strictEqual(r.code, 'MARKERS_BROKEN'); }
    for (const edited of [c.replace('</syscheck>', '<ignore>/etc/x</ignore></syscheck>'), c.replace('/opt/app</directories>', '/opt/app*</directories>'), c.replace('<directories>/opt/app', '<directories check_all="no">/opt/app'), c.replace(gc.BEGIN, '<!-- ASIX:monitored-folders:begin v2 -->'), c.replace('os="Linux"', 'os="Linux" name="a"')]) { const r = gc.compose(edited, E); assert.ok(!r.ok, 'edited'); assert.strictEqual(r.code, 'BLOCK_EDITED'); }
    assert.strictEqual(gc.compose('x'.repeat(gc.MAX_FILE_BYTES + 1), E).code, 'TOO_LARGE'); assert.strictEqual(gc.compose('a\u0000b', E).code, 'BAD_FILE');
    assert.strictEqual(gc.compose(BASE, [L('/a*')]).code, 'INVALID');
  });
  it('find tells none from broken from edited, and an entry list that would fail validation is edited', () => {
    assert.strictEqual(gc.find('').state, 'none'); assert.strictEqual(gc.find(BASE).state, 'none'); assert.strictEqual(gc.find(gc.BEGIN).state, 'broken');
    assert.strictEqual(gc.find(gc.BEGIN + '\n<agent_config os="Linux"><syscheck><directories>/proc</directories></syscheck></agent_config>\n' + gc.END).state, 'edited');
  });
  it('NOTHING typed can add an element, an attribute or a second path to the XML', () => {
    const nasty = ['/a</directories><directories>/etc', '/a"><x/>', '/a\n</agent_config>', '/a]]>', '/a<!--', '/a&amp;', '/a%3C', 'C:\\a</directories>', '%A%\\b" x="y'];
    for (const n of nasty) for (const sys of ['linux', 'windows']) assert.ok(!gc.validate([{ system: sys, path: n }]).ok, n);
    const fuzz = gc.validate([L('/ok')]).entries; const out = gc.blockText(fuzz); assert.strictEqual((out.match(/<directories/g) || []).length, 1);
  });
});

describe('diff', () => {
  it('lists added, removed, changed (real time switched) and unchanged entries', () => {
    const d = gc.diff([L('/a'), L('/b', true), W('C:\\w')], [L('/b'), L('/c'), W('C:\\w')]);
    assert.deepStrictEqual(d.added, ['Linux /c']); assert.deepStrictEqual(d.removed, ['Linux /a']); assert.deepStrictEqual(d.changed, ['Linux /b (real time)  ->  Linux /b']); assert.strictEqual(d.same, 1);
  });
  it('a first list is all added, an emptied list is all removed', () => {
    assert.deepStrictEqual(gc.diff([], [L('/a')]).added, ['Linux /a']); assert.deepStrictEqual(gc.diff([L('/a')], []).removed, ['Linux /a']);
  });
});

describe('group names and hashes', () => {
  it('a group name is a short, plain word', () => { for (const g of ['default', 'linux-servers', 'a.b_c', 'X'.repeat(64)]) assert.ok(gc.validGroup(g)); for (const g of ['', '.', '..', 'a/b', 'a b', 'a?b', 'x'.repeat(65), 5, null, 'a%2Fb']) assert.ok(!gc.validGroup(g), String(g)); });
  it('the hash is SHA-256 of the UTF-8 text', () => { assert.strictEqual(gc.sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); assert.notStrictEqual(gc.sha256('a'), gc.sha256('a ')); });
});
