'use strict';
// IOC feeds: reading what a feed returned (src/feeds/parser.js) and the checks of src/feeds/model.js.
const { describe, it } = require('node:test');
const assert = require('assert');
const { parseFeed, MAX_ITEMS } = require('../src/feeds/parser');
const model = require('../src/feeds/model');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const pairs = (r) => r.items.map((x) => `${x.type}:${x.value}`);

describe('plain text', () => {
  it('one indicator per line, comments and notes dropped, written in normal form, duplicates removed', () => {
    const r = parseFeed('plain-text', '# header\n; also a comment\n// and this\n1.2.3.4 ; SBL12345\nEvil.COM # seen today\nhxxp://bad[.]org/a\n\n1.2.3.4\nd41d8cd98f00b204e9800998ecf8427e\nnot valid\n8.8.8.0/24\n');
    assert.deepStrictEqual(pairs(r), ['ip:1.2.3.4', 'domain:evil.com', 'url:http://bad.org/a', 'md5:d41d8cd98f00b204e9800998ecf8427e']);
    assert.strictEqual(r.invalid, 2);   // "not valid" and the CIDR, which the IOC store cannot hold
  });
  it('Windows line ends and an empty body', () => {
    assert.deepStrictEqual(pairs(parseFeed('plain-text', '1.1.1.1\r\n2.2.2.2\r\n')), ['ip:1.1.1.1', 'ip:2.2.2.2']);
    assert.deepStrictEqual(parseFeed('plain-text', ''), { items: [], invalid: 0, lines: 0 });
  });
});
describe('csv', () => {
  it('takes the first cell that is an indicator, skips a header, honours quotes and other separators', () => {
    const r = parseFeed('csv', 'indicator,type,note\n"1.2.3.4",ip,"a, b"\nbotnet;evil.net;x\n\tbad.example.org\tdomain\nrubbish,more\n');
    assert.deepStrictEqual(pairs(r), ['ip:1.2.3.4', 'domain:evil.net', 'domain:bad.example.org']);
    assert.strictEqual(r.invalid, 1);
  });
});
describe('json', () => {
  it('an array of strings or of objects, or an object holding one of the usual lists', () => {
    assert.deepStrictEqual(pairs(parseFeed('json', '["1.1.1.1", {"value":"a.example.org"}, {"ioc":"http://x.example.net/p"}, {"x":1}, 5, null]')), ['ip:1.1.1.1', 'domain:a.example.org', 'url:http://x.example.net/p']);
    assert.strictEqual(parseFeed('json', '["1.1.1.1", {"x":1}, 5, null]').invalid, 3);
    for (const k of ['indicators', 'iocs', 'data', 'items', 'results', 'values', 'observables']) assert.deepStrictEqual(pairs(parseFeed('json', JSON.stringify({ [k]: ['9.9.9.9'] }))), ['ip:9.9.9.9'], k);
  });
  it('refuses what is not a list of indicators', () => {
    for (const body of ['not json', '{"a":1}', '"1.1.1.1"', '5']) assert.throws(() => parseFeed('json', body), (e) => e.code === 'BAD_FORMAT', body);
  });
});
describe('size', () => {
  it('a feed over the limit is refused whole, never cut', () => {
    const body = Array.from({ length: MAX_ITEMS + 1 }, (_, i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`).join('\n');
    assert.throws(() => parseFeed('plain-text', body), (e) => e.code === 'TOO_MANY_ITEMS');
    assert.strictEqual(parseFeed('plain-text', body.split('\n').slice(0, MAX_ITEMS).join('\n')).items.length, MAX_ITEMS);
  });
});

describe('the checks of a feed', () => {
  const id = '00000000-0000-4000-8000-000000000001';
  it('create: defaults, and every limit', () => {
    assert.deepStrictEqual(model.parseCreate({ integration_id: id, name: ' Blocklist ' }, UUID).value, { integration_id: id, name: 'Blocklist', severity: 'medium', ttl_days: 30, interval_hours: 24 });
    for (const b of [null, [], {}, { integration_id: 'x', name: 'a' }, { integration_id: id }, { integration_id: id, name: '' }, { integration_id: id, name: 'a', severity: 'urgent' }, { integration_id: id, name: 'a', ttl_days: 0 },
      { integration_id: id, name: 'a', ttl_days: 366 }, { integration_id: id, name: 'a', ttl_days: 1.5 }, { integration_id: id, name: 'a', ttl_days: '30' }, { integration_id: id, name: 'a', interval_hours: 5 }, { integration_id: id, name: 'a', junk: 1 }]) assert.ok(model.parseCreate(b, UUID).error, JSON.stringify(b));
    assert.ok(!model.parseCreate({ integration_id: id, name: 'a', ttl_days: 365, interval_hours: 1, severity: 'critical' }, UUID).error);
  });
  it('patch changes only what it names; the integration never changes', () => {
    assert.deepStrictEqual(model.parsePatch({ severity: 'high', enabled: false }).value, { severity: 'high', enabled: false });
    for (const b of [{}, { integration_id: id }, { enabled: 'no' }, { ttl_days: 0 }]) assert.ok(model.parsePatch(b).error, JSON.stringify(b));
  });
  it('run: only force', () => {
    assert.deepStrictEqual(model.parseRun(undefined).value, { force: false }); assert.deepStrictEqual(model.parseRun({ force: true }).value, { force: true });
    for (const b of [{ force: 'yes' }, { other: 1 }, []]) assert.ok(model.parseRun(b).error);
  });
  it('a feed that shrinks to under a fifth of what it was (when it was 20 or more) is suspect', () => {
    assert.ok(model.shrank(100, 19)); assert.ok(!model.shrank(100, 20)); assert.ok(!model.shrank(19, 0), 'small feeds may empty'); assert.ok(model.shrank(20, 3)); assert.ok(!model.shrank(null, 0));
  });
});
