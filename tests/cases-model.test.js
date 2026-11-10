'use strict';
// CS1: the rules in src/cases/model.js, which need no database. (The SQL and the routes are tested against a real PostgreSQL in tests/cases-db.test.js.)
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const m = require('../src/cases/model');

const U1 = '11111111-1111-4111-8111-111111111111';
const U2 = '22222222-2222-4222-8222-222222222222';
const ok = (r) => { assert.ok(!r.error, r.error && r.error.message); return r.value; };
const err = (r, re, code = 'INVALID_BODY') => { assert.ok(r.error, 'expected an error'); assert.strictEqual(r.error.code, code); assert.match(r.error.message, re); };

describe('the allowed values match the database', () => {
  const yaml = fs.readFileSync(path.join(__dirname, '../k8s/12-schema-init.yaml'), 'utf8');
  const list = (col) => [...yaml.match(new RegExp(`CONSTRAINT cases_${col}_chk CHECK \\(${col} IN \\(([^)]*)\\)\\)`))[1].matchAll(/'([a-z]+)'/g)].map((x) => x[1]);
  it('statuses are the ones the table accepts', () => assert.deepStrictEqual(m.STATUSES, list('status')));
  it('severities are the ones the table accepts', () => assert.deepStrictEqual([...m.SEVERITIES].sort(), list('severity').sort()));
  it('every kind of timeline entry has words, and the kinds are the ones the model lists', () => {
    for (const k of m.KINDS) assert.ok(m.describeEvent({ kind: k, data: { from: 'a', to: 'b', title: 't' }, body: 'b' }).length > 0, k);
    assert.strictEqual(m.describeEvent({ kind: 'something-new' }), 'something-new');
  });
});

describe('topSeverity', () => {
  it('is the worst one', () => { assert.strictEqual(m.topSeverity(['low', 'high', 'medium']), 'high'); assert.strictEqual(m.topSeverity(['low', 'critical']), 'critical'); assert.strictEqual(m.topSeverity(['low']), 'low'); });
  it('is medium when there is nothing to go on, and ignores what it does not know', () => { assert.strictEqual(m.topSeverity([]), 'medium'); assert.strictEqual(m.topSeverity(undefined), 'medium'); assert.strictEqual(m.topSeverity(['weird']), 'medium'); assert.strictEqual(m.topSeverity(['weird', 'low']), 'low'); });
});

describe('parseCreate', () => {
  it('a title alone is enough; everything else has a default', () => {
    assert.deepStrictEqual(ok(m.parseCreate({ title: '  Router attack ' })), { title: 'Router attack', description: null, severity: null, owner_id: null, alert_ids: [] });
  });
  it('takes every field, lower-cases and de-duplicates the alert ids', () => {
    const v = ok(m.parseCreate({ title: 't', description: ' d ', severity: 'high', owner_id: U1.toUpperCase(), alert_ids: [U1.toUpperCase(), U1, U2] }));
    assert.deepStrictEqual([v.description, v.severity, v.owner_id, v.alert_ids], ['d', 'high', U1, [U1, U2]]);
  });
  it('an empty description is no description', () => assert.strictEqual(ok(m.parseCreate({ title: 't', description: '   ' })).description, null));
  it('refuses what is not valid', () => {
    err(m.parseCreate(null), /JSON object/); err(m.parseCreate([]), /JSON object/); err(m.parseCreate('x'), /JSON object/);
    err(m.parseCreate({}), /title must be/); err(m.parseCreate({ title: '   ' }), /title must be/); err(m.parseCreate({ title: 5 }), /title must be/); err(m.parseCreate({ title: 'x'.repeat(201) }), /title must be/);
    err(m.parseCreate({ title: 't', severity: 'urgent' }), /severity must be/); err(m.parseCreate({ title: 't', owner_id: 'nope' }), /owner_id must be/);
    err(m.parseCreate({ title: 't', description: 5 }), /description must be/); err(m.parseCreate({ title: 't', description: 'x'.repeat(5001) }), /description must be/);
    err(m.parseCreate({ title: 't', alert_ids: 'x' }), /alert_ids must be/); err(m.parseCreate({ title: 't', alert_ids: ['nope'] }), /alert_ids must be/);
    err(m.parseCreate({ title: 't', alert_ids: Array.from({ length: 51 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`) }), /up to 50/);
    err(m.parseCreate({ title: 't', status: 'closed' }), /unknown field: status/); err(m.parseCreate({ title: 't', a: 1, b: 2 }), /unknown field: a, b/);
  });
  it('the title limit is 200 characters, counted after trimming', () => { assert.ok(!m.parseCreate({ title: ' ' + 'x'.repeat(200) + ' ' }).error); });
});

describe('parsePatch', () => {
  it('keeps only the fields that were sent', () => assert.deepStrictEqual(ok(m.parsePatch({ status: 'closed' })), { status: 'closed' }));
  it('null clears the owner and the description; an empty description too', () => {
    assert.deepStrictEqual(ok(m.parsePatch({ owner_id: null, description: null })), { owner_id: null, description: null });
    assert.deepStrictEqual(ok(m.parsePatch({ description: '  ' })), { description: null });
  });
  it('refuses an empty patch, unknown fields and bad values', () => {
    err(m.parsePatch({}), /at least one of/); err(m.parsePatch(null), /JSON object/); err(m.parsePatch({ id: 'x' }), /unknown field: id/); err(m.parsePatch({ case_number: 5 }), /unknown field/);
    err(m.parsePatch({ status: 'done' }), /status must be/); err(m.parsePatch({ severity: 'x' }), /severity must be/); err(m.parsePatch({ title: '' }), /title must be/); err(m.parsePatch({ owner_id: 'x' }), /owner_id must be/); err(m.parsePatch({ owner_id: undefined, title: undefined }), /title must be/);
  });
  it('cannot be used to reach inherited properties', () => err(m.parsePatch({ constructor: 1 }), /unknown field: constructor/));
});

describe('notes, alert lists and list queries', () => {
  it('a note is trimmed text of 1 to 2000 characters', () => {
    assert.strictEqual(ok(m.parseNote({ body: '  hi ' })), 'hi');
    for (const b of [null, {}, { body: '' }, { body: '  ' }, { body: 5 }, { body: 'x'.repeat(2001) }]) err(m.parseNote(b), /body must be/);
    assert.ok(!m.parseNote({ body: 'x'.repeat(2000) }).error);
  });
  it('an alert list is 1 to 50 ids', () => {
    assert.deepStrictEqual(ok(m.parseAlertIds({ alert_ids: [U1, U1.toUpperCase(), U2] })), [U1, U2]);
    for (const b of [null, {}, { alert_ids: [] }, { alert_ids: 'x' }, { alert_ids: ['x'] }]) assert.ok(m.parseAlertIds(b).error);
  });
  it('list defaults: active, no owner filter, 50 from 0', () => assert.deepStrictEqual(ok(m.parseListQuery({}, U1)), { status: 'active', owner: null, limit: 50, offset: 0 }));
  it('list filters', () => {
    assert.strictEqual(ok(m.parseListQuery({ status: 'closed' })).status, 'closed');
    assert.deepStrictEqual(ok(m.parseListQuery({ owner: 'me' }, U1)).owner, { me: U1 });
    assert.deepStrictEqual(ok(m.parseListQuery({ owner: 'unassigned' })).owner, { none: true });
    assert.deepStrictEqual(ok(m.parseListQuery({ owner: U2.toUpperCase() })).owner, { id: U2 });
    const p = ok(m.parseListQuery({ limit: '200', offset: '100000' })); assert.deepStrictEqual([p.limit, p.offset], [200, 100000]);
  });
  it('list refusals carry their own codes', () => {
    err(m.parseListQuery({ status: 'nope' }), /status must be/, 'INVALID_STATUS');
    err(m.parseListQuery({ owner: 'me' }, null), /signed-in user/, 'INVALID_OWNER'); err(m.parseListQuery({ owner: 'x' }), /owner must be/, 'INVALID_OWNER');
    for (const q of [{ limit: '0' }, { limit: '201' }, { limit: 'x' }, { limit: '1.5' }, { offset: '-1' }, { offset: '100001' }, { offset: 'x' }]) err(m.parseListQuery(q), /whole number/, 'INVALID_PAGE');
  });
});

describe('closed cases', () => {
  it('open and investigating cases accept anything', () => { for (const s of ['open', 'investigating']) assert.strictEqual(m.closedBlocks(s, { title: 'x', status: 'closed' }), false); });
  it('a closed case may only be reopened (alone or with edits) or left alone', () => {
    assert.strictEqual(m.closedBlocks('closed', { status: 'open', title: 'x' }), false);
    assert.strictEqual(m.closedBlocks('closed', { status: 'closed' }), false);
    assert.strictEqual(m.closedBlocks('closed', { title: 'x' }), true);
    assert.strictEqual(m.closedBlocks('closed', { status: 'closed', severity: 'low' }), true);
    assert.strictEqual(m.closedBlocks('closed', { owner_id: null }), true);
  });
});

describe('what counts as a change', () => {
  const before = { title: 'A', description: null, severity: 'low', status: 'open', owner_id: U1, owner_name: 'alice' };
  it('nothing, when every value is the same', () => assert.deepStrictEqual(m.changeEvents(before, { title: 'A', severity: 'low', status: 'open', owner_id: U1, description: null }, 'alice'), []));
  it('a description of null and of nothing are the same', () => assert.deepStrictEqual(m.changeEvents({ ...before, description: '' }, { description: null }), []));
  it('each real change is one entry, in a fixed order, with the words a person needs', () => {
    const ev = m.changeEvents(before, { description: 'new', title: 'B', severity: 'high', owner_id: U2, status: 'investigating' }, 'bob');
    assert.deepStrictEqual(ev.map((e) => e.kind), ['status', 'owner', 'severity', 'title', 'description']);
    assert.deepStrictEqual(ev.map((e) => m.describeEvent(e)), ['Status: Open → Investigating', 'Owner: alice → bob', 'Severity: low → high', 'Title changed from "A" to "B"', 'Description edited']);
  });
  it('clearing the owner says "nobody"', () => {
    const [e] = m.changeEvents(before, { owner_id: null }, null);
    assert.strictEqual(m.describeEvent(e), 'Owner: alice → nobody');
    assert.strictEqual(m.describeEvent(m.changeEvents({ ...before, owner_id: null, owner_name: null }, { owner_id: U2 }, 'bob')[0]), 'Owner: nobody → bob');
  });
  it('a field that is not in the patch is never a change', () => assert.deepStrictEqual(m.changeEvents(before, { title: 'B' }).map((e) => e.kind), ['title']));
});

describe('the words of the timeline', () => {
  it('created, with and without alerts', () => {
    assert.strictEqual(m.describeEvent({ kind: 'created', data: {} }), 'Case created');
    assert.strictEqual(m.describeEvent({ kind: 'created', data: { alerts: 1 } }), 'Case created with 1 alert');
    assert.strictEqual(m.describeEvent({ kind: 'created', data: { alerts: 3 } }), 'Case created with 3 alerts');
  });
  it('alerts added and removed, by title (or by id when the title is unknown)', () => {
    assert.strictEqual(m.describeEvent({ kind: 'alert_added', data: { title: 'Malware', alert_id: U1 } }), 'Alert added: Malware');
    assert.strictEqual(m.describeEvent({ kind: 'alert_removed', data: { alert_id: U1, title: null } }), 'Alert removed: ' + U1);
  });
  it('a note is its own text, an empty one is empty', () => { assert.strictEqual(m.describeEvent({ kind: 'note', body: 'Called them' }), 'Called them'); assert.strictEqual(m.describeEvent({ kind: 'note' }), ''); });
  it('data may be missing', () => assert.doesNotThrow(() => m.describeEvent({ kind: 'status' })));
});
