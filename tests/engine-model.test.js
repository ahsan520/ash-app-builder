'use strict';
// SR3, the rules of src/engine/model.js: the run token, what a start request may say, what the engine may send back, and what is handed to the engine.
const { describe, it } = require('node:test');
const assert = require('assert');
require('../src/lists/actions');   // registers list.add_entry and list.remove_entry, as the gateway does
const m = require('../src/engine/model');

const start = (o) => m.parseStart({ playbook: 'block-ip', webhook_url: 'https://engine.example.test/hook', allowed_actions: ['list.add_entry'], ...o });
const code = (r) => r.error && r.error.code;

describe('engine model', () => {
  it('a run token is 32 random bytes in a fixed shape, unique, and only its SHA-256 is meant to be stored', () => {
    const a = m.newToken(); const b = m.newToken();
    assert.match(a, /^aet_[A-Za-z0-9_-]{43}$/); assert.notStrictEqual(a, b);
    assert.ok(m.tokenShape(a)); assert.ok(!m.tokenShape('aet_short')); assert.ok(!m.tokenShape(null)); assert.ok(!m.tokenShape(a + 'x')); assert.ok(!m.tokenShape(' ' + a));
    assert.match(m.hashToken(a), /^[0-9a-f]{64}$/); assert.strictEqual(m.hashToken(a), m.hashToken(a)); assert.notStrictEqual(m.hashToken(a), m.hashToken(b)); assert.ok(!m.hashToken(a).includes(a));
  });

  it('parseStart: accepts a good request with defaults, and refuses a tenant (or anything unlisted) in the body', () => {
    const r = start({ input: { value: '203.0.113.50' } });
    assert.deepStrictEqual(r.value, { playbook: 'block-ip', webhook_url: 'https://engine.example.test/hook', allowed_actions: ['list.add_entry'], input: { value: '203.0.113.50' }, ttl_seconds: 900, max_calls: 20 });
    assert.deepStrictEqual(start({}).value.input, {});
    assert.strictEqual(code(start({ tenant_id: 'x' })), 'INVALID_BODY'); assert.strictEqual(code(start({ origin: 'user' })), 'INVALID_BODY');
    for (const bad of [null, [], 'x', 5]) assert.strictEqual(code(m.parseStart(bad)), 'INVALID_BODY');
  });

  it('parseStart: playbook, webhook address, allowed actions, input, time and call limits are checked', () => {
    for (const p of ['', 'Bad', '-x', 'a b', 'x'.repeat(81), 5, undefined]) assert.strictEqual(code(start({ playbook: p })), 'INVALID_PLAYBOOK', String(p));
    assert.strictEqual(code(start({ webhook_url: '' })), 'INVALID_WEBHOOK_URL'); assert.strictEqual(code(start({ webhook_url: 'x'.repeat(2049) })), 'INVALID_WEBHOOK_URL'); assert.strictEqual(code(start({ webhook_url: 5 })), 'INVALID_WEBHOOK_URL');
    for (const a of [[], 'list.add_entry', ['nodot'], ['No.Caps'], ['no.such_action'], ['list.add_entry', 'list.add_entry'], [5], Array(21).fill('list.add_entry')]) assert.strictEqual(code(start({ allowed_actions: a })), 'INVALID_ALLOWED_ACTIONS', JSON.stringify(a));
    assert.strictEqual(code(start({ input: [] })), 'INVALID_INPUT'); assert.strictEqual(code(start({ input: 'x' })), 'INVALID_INPUT'); assert.strictEqual(code(start({ input: { a: 'x'.repeat(9000) } })), 'INVALID_INPUT');
    assert.strictEqual(start({ ttl_seconds: 30 }).value.ttl_seconds, 30); assert.strictEqual(start({ ttl_seconds: 86400 }).value.ttl_seconds, 86400);
    for (const t of [29, 86401, 1.5, '60', null]) assert.strictEqual(code(start({ ttl_seconds: t })), 'INVALID_TTL_SECONDS', String(t));
    assert.strictEqual(start({ max_calls: 100 }).value.max_calls, 100);
    for (const t of [0, 101, 2.5, '5']) assert.strictEqual(code(start({ max_calls: t })), 'INVALID_MAX_CALLS', String(t));
  });

  it('parseStart does not keep the caller\'s object: the allowed list is a copy', () => {
    const list = ['list.add_entry']; const r = start({ allowed_actions: list }); list.push('x'); assert.deepStrictEqual(r.value.allowed_actions, ['list.add_entry']);
  });

  it('parseFinish, parseCall: only the listed fields, a refused status or summary, a tenant or an origin in a callback body', () => {
    assert.deepStrictEqual(m.parseFinish({ status: 'succeeded' }).value, { status: 'succeeded', summary: null });
    assert.deepStrictEqual(m.parseFinish({ status: 'failed', summary: '  it broke  ' }).value, { status: 'failed', summary: 'it broke' });
    assert.strictEqual(m.parseFinish({ status: 'failed', summary: '   ' }).value.summary, null);
    for (const b of [undefined, null, [], { status: 'running' }, { status: 'succeeded', extra: 1 }, { status: 'succeeded', summary: 5 }, { status: 'succeeded', summary: 'x'.repeat(501) }]) assert.ok(m.parseFinish(b).error, JSON.stringify(b));
    assert.deepStrictEqual(m.parseCall(undefined).value, { parameters: {} }); assert.deepStrictEqual(m.parseCall({}).value, { parameters: {} }); assert.deepStrictEqual(m.parseCall({ parameters: { a: 1 } }).value, { parameters: { a: 1 } });
    for (const b of [[], { parameters: [] }, { parameters: 'x' }, { tenant_id: 'x' }, { parameters: {}, origin: 'user' }]) assert.ok(m.parseCall(b).error, JSON.stringify(b));
  });

  it('what the engine is told: one word for the decision, and only the fields it may see', () => {
    const run = (status, extra) => ({ id: 'r1', action_id: 'list.add_entry', status, result: { v: 1 }, params: { secret: 'p' }, undo: { x: 1 }, decided_by_name: 'bob', error_code: null, error_message: null, ...extra });
    assert.deepStrictEqual(['succeeded', 'awaiting_approval', 'recommended', 'refused', 'failed', 'rejected'].map((s) => m.outcomeOf(run(s))), ['executed', 'awaiting_approval', 'recommended', 'refused', 'failed', 'rejected']);
    const v = m.callView(run('succeeded')); assert.deepStrictEqual(Object.keys(v).sort(), ['action', 'error_code', 'error_message', 'id', 'outcome', 'result', 'status']);
    assert.deepStrictEqual(v.result, { v: 1 }); assert.strictEqual(m.callView(run('refused', { error_code: 'ACTION_DISABLED', error_message: 'off' })).result, null);
    assert.ok(!JSON.stringify(v).includes('secret') && !JSON.stringify(v).includes('bob'));
  });

  it('the callback address: https only, no credentials or query, from ASIX_ENGINE_CALLBACK_BASE or else the public URL, with the path added once', () => {
    assert.strictEqual(m.callbackBase({ ASIX_ENGINE_CALLBACK_BASE: 'https://asix.example.test:30443' }).value, 'https://asix.example.test:30443/v1/engine/callback');
    assert.strictEqual(m.callbackBase({ ASIX_ENGINE_CALLBACK_BASE: 'https://asix.example.test/x/' }).value, 'https://asix.example.test/x/v1/engine/callback');
    assert.strictEqual(m.callbackBase({ ASIX_PUBLIC_URL: 'https://asix.example.test' }).value, 'https://asix.example.test/v1/engine/callback');
    assert.strictEqual(m.callbackBase({ ASIX_ENGINE_CALLBACK_BASE: 'https://a.test', ASIX_PUBLIC_URL: 'https://b.test' }).value, 'https://a.test/v1/engine/callback');
    for (const e of [{}, { ASIX_ENGINE_CALLBACK_BASE: '' }, { ASIX_PUBLIC_URL: '__ASIX_PUBLIC_URL__' }, { ASIX_ENGINE_CALLBACK_BASE: 'http://asix.example.test' }, { ASIX_ENGINE_CALLBACK_BASE: 'not a url' },
      { ASIX_ENGINE_CALLBACK_BASE: 'https://u:p@asix.example.test' }, { ASIX_ENGINE_CALLBACK_BASE: 'https://asix.example.test/?a=1' }, { ASIX_ENGINE_CALLBACK_BASE: 'https://asix.example.test/#f' }]) assert.strictEqual(code(m.callbackBase(e)), 'ENGINE_NOT_CONFIGURED', JSON.stringify(e));
    assert.strictEqual(m.callbackBase(null).error.code, 'ENGINE_NOT_CONFIGURED');
  });

  it('what is handed to the engine: the run, the token, the callback address and the input, and nothing that identifies a credential of a tenant', () => {
    const b = m.hookBody({ runId: 'r', tenantId: 't', token: 'aet_x', callbackUrl: 'https://a.test/v1/engine/callback', playbook: 'p', input: { v: 1 }, webhook_url: 'https://secret', secret: 's' });
    assert.deepStrictEqual(Object.keys(b).sort(), ['callback_base', 'input', 'playbook', 'run_id', 'tenant_id', 'token']);
  });
});
