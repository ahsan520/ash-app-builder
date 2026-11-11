'use strict';
// L1: the rules of lists that need no database (src/lists/model.js), the allow matcher, the published text, and the two actions' definitions.
const { describe, it } = require('node:test');
const assert = require('assert');
const model = require('../src/lists/model');
const actionsModel = require('../src/actions/model');

const BLOCK = { kind: 'block', item_type: 'ip', allow_private: false };
const ok = (list, v) => { const r = model.normalizeValue(list, v); assert.ok(!r.error, `${v}: ${r.error && r.error.message}`); return r.value.text; };
const code = (list, v) => { const r = model.normalizeValue(list, v); assert.ok(r.error, `${v} should be refused`); return r.error.code; };

describe('addresses', () => {
  it('writes every address in one normal form', () => {
    assert.strictEqual(ok(BLOCK, ' 203.0.113.7 '), '203.0.113.7');
    assert.strictEqual(ok(BLOCK, '203.0.113.7/32'), '203.0.113.7');
    assert.strictEqual(ok(BLOCK, '198.51.100.77/24'), '198.51.100.0/24');
    assert.strictEqual(ok(BLOCK, '2001:DB8:0:0:0:0:0:1'), '2001:db8::1');
    assert.strictEqual(ok(BLOCK, '2001:db8::/32'), '2001:db8::/32');
    assert.strictEqual(ok(BLOCK, '2001:db8::5/128'), '2001:db8::5');
  });
  it('refuses what is not an address', () => {
    for (const v of ['1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '1.2.3.4/33', '1.2.3.4/', 'example.com', '::ffff:1.2.3.4', '2001:db8::/129', '1:2:3:4:5:6:7:8:9', '', '  ']) assert.ok(model.normalizeValue(BLOCK, v).error, v);
    assert.ok(model.normalizeValue(BLOCK, 5).error);
    assert.ok(model.normalizeValue(BLOCK, 'a'.repeat(3000)).error);
  });
  it('a block list refuses what could cut the network off', () => {
    assert.strictEqual(code(BLOCK, '0.0.0.0/0'), 'TOO_WIDE');
    assert.strictEqual(code(BLOCK, '8.0.0.0/7'), 'TOO_WIDE');
    assert.strictEqual(code(BLOCK, '2000::/16'), 'TOO_WIDE');
    ok(BLOCK, '8.0.0.0/8'); ok(BLOCK, '2001:db8::/32');
    for (const v of ['127.0.0.1', '0.0.0.0', '224.0.0.5', '255.255.255.255', '::1', '::', 'ff02::1']) assert.strictEqual(code(BLOCK, v), 'NOT_LISTABLE', v);
    for (const v of ['10.1.2.3', '172.16.5.5', '172.31.255.1', '192.168.1.1', '169.254.1.1', '100.64.0.1', 'fd00::1', 'fe80::1', '10.0.0.0/8']) assert.strictEqual(code(BLOCK, v), 'PRIVATE_ADDRESS', v);
    ok(BLOCK, '172.32.0.1'); ok(BLOCK, '192.169.0.1');
  });
  it('private addresses are allowed when the list says so, but never the unusable ones', () => {
    const home = { ...BLOCK, allow_private: true };
    assert.strictEqual(ok(home, '192.168.1.50'), '192.168.1.50');
    assert.strictEqual(code(home, '127.0.0.1'), 'NOT_LISTABLE');
    assert.strictEqual(code(home, '0.0.0.0/0'), 'TOO_WIDE');
  });
  it('allow and watch lists take private addresses, wide networks that are not reserved, but never loopback', () => {
    for (const kind of ['allow', 'watch']) {
      const l = { kind, item_type: 'ip', allow_private: false };
      assert.strictEqual(ok(l, '10.1.2.3'), '10.1.2.3');
      assert.strictEqual(ok(l, '8.0.0.0/7'), '8.0.0.0/7');
      assert.strictEqual(code(l, '127.0.0.1'), 'NOT_LISTABLE');
    }
  });
});

describe('names, URLs and hashes', () => {
  it('domain names', () => {
    const l = { kind: 'block', item_type: 'domain' };
    assert.strictEqual(ok(l, ' Evil.Example.COM. '), 'evil.example.com');
    assert.strictEqual(ok(l, 'xn--80ak6aa92e.com'), 'xn--80ak6aa92e.com');
    for (const v of ['com', 'localhost', '*.example.com', 'exa mple.com', '-a.com', 'a..com', 'bücher.de', '1.2.3.4', 'a.' + 'b'.repeat(64) + '.com']) assert.ok(model.normalizeValue(l, v).error, v);
  });
  it('URLs', () => {
    const l = { kind: 'block', item_type: 'url' };
    assert.strictEqual(ok(l, 'HTTP://Evil.com/Path?a=1#frag'), 'http://evil.com/Path?a=1');
    for (const v of ['ftp://a.com', 'evil.com/x', 'http://u:p@a.com/', 'http://a.com/ x', 'http://']) assert.ok(model.normalizeValue(l, v).error, v);
  });
  it('hashes', () => {
    const l = { kind: 'watch', item_type: 'hash' };
    assert.strictEqual(ok(l, 'D41D8CD98F00B204E9800998ECF8427E'), 'd41d8cd98f00b204e9800998ecf8427e');
    ok(l, 'a'.repeat(40)); ok(l, 'a'.repeat(64));
    for (const v of ['a'.repeat(31), 'g'.repeat(32), 'a'.repeat(33)]) assert.ok(model.normalizeValue(l, v).error, v);
  });
});

describe('what an allow list covers', () => {
  it('addresses overlap in both directions', () => {
    const m = model.makeAllowMatcher('ip', [{ list_name: 'Office', value: '203.0.113.0/24' }, { list_name: 'DNS', value: '9.9.9.9' }]);
    assert.strictEqual(m('203.0.113.50').list_name, 'Office');
    assert.strictEqual(m('203.0.0.0/16').list_name, 'Office');      // a block that includes an allowed network
    assert.strictEqual(m('9.9.9.9').list_name, 'DNS');
    assert.strictEqual(m('9.9.9.8'), null);
    assert.strictEqual(m('2001:db8::1'), null);
  });
  it('an allowed name covers its subdomains, and a blocked parent includes an allowed subdomain', () => {
    const m = model.makeAllowMatcher('domain', [{ list_name: 'A', value: 'example.com' }, { list_name: 'B', value: 'ok.bad.org' }]);
    assert.ok(m('example.com')); assert.ok(m('x.y.example.com')); assert.ok(m('bad.org'));
    assert.strictEqual(m('badexample.com'), null); assert.strictEqual(m('other.org'), null);
  });
  it('URLs and hashes match exactly', () => {
    const m = model.makeAllowMatcher('hash', [{ list_name: 'A', value: 'a'.repeat(32) }]);
    assert.ok(m('a'.repeat(32))); assert.strictEqual(m('a'.repeat(31) + 'b'), null);
  });
  it('covers() agrees', () => {
    assert.ok(model.covers('ip', '10.0.0.0/8', '10.1.2.3')); assert.ok(!model.covers('ip', '1.1.1.1', '1.1.1.2'));
    assert.ok(model.covers('domain', 'a.example.com', 'example.com')); assert.ok(!model.covers('domain', 'badexample.com', 'example.com'));
  });
});

describe('request bodies', () => {
  it('create', () => {
    const r = model.parseCreate({ name: ' Block feed ', kind: 'block', item_type: 'ip' });
    assert.deepStrictEqual(r.value, { name: 'Block feed', kind: 'block', item_type: 'ip', description: null, allow_private: false });
    for (const b of [null, [], {}, { name: '', kind: 'block', item_type: 'ip' }, { name: 'a', kind: 'deny', item_type: 'ip' }, { name: 'a', kind: 'block', item_type: 'port' },
      { name: 'a', kind: 'block', item_type: 'ip', extra: 1 }, { name: 'a', kind: 'block', item_type: 'domain', allow_private: true }, { name: 'a'.repeat(101), kind: 'block', item_type: 'ip' }, { name: 'a', kind: 'block', item_type: 'ip', allow_private: 'yes' }]) assert.ok(model.parseCreate(b).error, JSON.stringify(b));
  });
  it('patch changes only name, description and allow_private', () => {
    assert.deepStrictEqual(model.parsePatch({ name: 'x', description: null }).value, { name: 'x', description: null });
    for (const b of [{}, { kind: 'allow' }, { item_type: 'url' }, { name: '' }, { allow_private: 1 }]) assert.ok(model.parsePatch(b).error, JSON.stringify(b));
  });
  it('entries: a list or a text, comments dropped, duplicates removed', () => {
    const t = model.parseEntriesBody({ text: '1.1.1.1 # office\n# whole line\n; also\n\n2.2.2.2\r\n1.1.1.1\n', expires: '24h', note: ' why ' });
    assert.deepStrictEqual(t.value, { values: ['1.1.1.1', '2.2.2.2'], note: 'why', expires: { seconds: 86400 } });
    assert.deepStrictEqual(model.parseEntriesBody({ values: ['a', 'a'] }).value, { values: ['a'], note: null, expires: { never: true } });
    assert.deepStrictEqual(model.parseEntriesBody({ values: ['a'], expires_at: '2030-01-02T03:04:05' }).value.expires, { at: '2030-01-02T03:04:05' });
    for (const b of [{}, { values: [] }, { values: [1] }, { values: ['a'], text: 'a' }, { text: '# only a comment' }, { values: ['a'], expires: 'forever' }, { values: ['a'], expires: '1h', expires_at: '2030-01-02T03:04:05' },
      { values: ['a'], expires_at: '2030-01-02' }, { values: ['a'], expires_at: '2030-13-45T03:04:05' }, { values: ['a'], note: 'x\ny' }, { values: ['a'], note: 'x'.repeat(201) }, { values: ['a'], other: 1 },
      { values: Array(1001).fill('a').map((x, i) => x + i) }, { text: Array(1001).fill(0).map((_, i) => 'v' + i).join('\n') }]) assert.ok(model.parseEntriesBody(b).error, JSON.stringify(b).slice(0, 80));
  });
  it('remove and the entries query', () => {
    assert.deepStrictEqual(model.parseRemoveBody({ values: [' a ', 'a', 'b'] }).value, { values: ['a', 'b'] });
    for (const b of [{}, { values: [] }, { values: [''] }, { values: ['a'], x: 1 }]) assert.ok(model.parseRemoveBody(b).error);
    assert.deepStrictEqual(model.parseEntriesQuery({}).value, { q: null, limit: 50, offset: 0, expired: false });
    assert.strictEqual(model.parseEntriesQuery({ limit: '200', offset: '10', q: ' x ', expired: 'true' }).value.q, 'x');
    for (const q of [{ limit: '0' }, { limit: '201' }, { limit: 'a' }, { offset: '-1' }, { expired: 'yes' }, { q: 'x'.repeat(101) }]) assert.ok(model.parseEntriesQuery(q).error, JSON.stringify(q));
  });
});

describe('the published text and the token', () => {
  it('one sorted value per line with a final newline; empty is empty', () => {
    assert.strictEqual(model.feedText(['b', 'a']), 'a\nb\n');
    assert.strictEqual(model.feedText([]), '');
  });
  it('the ETag follows the content', () => {
    assert.strictEqual(model.etagOf('a\n'), model.etagOf('a\n'));
    assert.notStrictEqual(model.etagOf('a\n'), model.etagOf('b\n'));
    assert.match(model.etagOf(''), /^"[0-9a-f]{32}"$/);
  });
  it('tokens are long, shaped, hashed and different every time', () => {
    const a = model.newToken(); const b = model.newToken();
    assert.notStrictEqual(a, b); assert.ok(model.tokenShape(a)); assert.ok(a.startsWith('asix_lt_'));
    assert.match(model.hashToken(a), /^[0-9a-f]{64}$/);
    for (const t of ['', 'x', 'asix_lt_short', 'asix_lt_' + 'a'.repeat(44), 'asix_ik_' + 'a'.repeat(43), 'asix_lt_' + 'a'.repeat(42) + '/', null, undefined, 5]) assert.ok(!model.tokenShape(t), String(t));
  });
});

describe('the two list actions', () => {
  const catalog = require('../src/actions/catalog');
  const defs = require('../src/lists/actions');
  it('are registered, and their definitions pass the registry check', () => {
    for (const d of [defs.ADD, defs.REMOVE]) { assert.deepStrictEqual(actionsModel.checkDefinition(d), [], d.id); assert.ok(catalog.get(d.id), d.id); }
  });
  it('are medium risk, reversible, never above level 3, and ask for approval from automation', () => {
    for (const d of [defs.ADD, defs.REMOVE]) {
      assert.strictEqual(d.risk, 'medium'); assert.strictEqual(d.reversible, true); assert.ok(d.max_autonomy <= 3); assert.strictEqual(d.default_autonomy, 2);
      assert.strictEqual(actionsModel.decide(d, { enabled: true, autonomy_level: 3 }, 'automation').outcome, 'approval', d.id);
      assert.strictEqual(actionsModel.decide(d, null, 'user').outcome, 'refuse', d.id);   // off until an administrator enables it
    }
  });
  it('the parameters a caller can send are checked against the definition', () => {
    const id = '00000000-0000-4000-8000-000000000001';
    assert.ok(!actionsModel.validateParams(defs.ADD, { list_id: id, value: '1.2.3.4' }).error);
    assert.ok(!actionsModel.validateParams(defs.ADD, { list_id: id, value: '1.2.3.4', expires: '7d', note: 'x' }).error);
    assert.ok(actionsModel.validateParams(defs.ADD, { list_id: id, value: '1.2.3.4', expires: 'forever' }).error);
    assert.ok(actionsModel.validateParams(defs.ADD, { list_id: 'x', value: '1.2.3.4' }).error);
    assert.ok(actionsModel.validateParams(defs.REMOVE, { list_id: id }).error);
  });
  it('the existing case actions are untouched', () => {
    for (const a of ['case.create', 'case.add_note', 'case.set_severity', 'case.set_owner', 'case.set_status', 'case.add_alerts', 'case.remove_alerts']) assert.ok(catalog.get(a), a);
  });
});
