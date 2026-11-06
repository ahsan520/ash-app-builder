'use strict';
// E11: reading, previewing and changing the Windows events block of a group against the stand-in manager over real HTTPS (tests/fixtures/fake-wazuh-api.js, written from the documented
// Wazuh 4.x shape and what a real 4.14.9 manager was seen to do, NOT a real manager): the real API client, the real service, a recording history.
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '800';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const fake = require('./fixtures/fake-wazuh-api');
const api = require('../src/endpoints/wazuh-api');
const wf = require('../src/endpoints/win-filter');
const gc = require('../src/endpoints/group-config');
const gcs = require('../src/endpoints/group-config-service');
const wl = require('../src/endpoints/group-winlog');
const service = require('../src/endpoints/group-winlog-service');

const WRITER = { user: 'asix-groupconfig', password: 'Wr1ter-pw!' };
const NOISY = wf.validate(wf.presetNoisySecurity()).policy;
let srv, n = 0;
const mgr = () => ({ tenant_id: 'T-' + srv.port, api_url: srv.url, api_user: srv.user, api_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', api_secret_enc_hash: 'h' });
const wr = () => ({ api_user: WRITER.user, api_password: WRITER.password, hash: 'w1' });
const makeCtx = () => { const rows = []; return { m: mgr(), w: wr(), api, rows, hist: { record: async (r) => { const id = 'w' + (++n); rows.push({ id, ...r }); return { id }; }, settle: async (id, result, sha, note) => { Object.assign(rows.find((x) => x.id === id), { result, after_sha256: sha, note }); } } }; };
const writes = () => srv.state.groupWrites;
const BASE_DEFAULT = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';
const sha = gc.sha256;

before(async () => { srv = await fake.start({ writer: WRITER }); });
after(async () => { await srv.stop(); });
beforeEach(() => { srv.state.groups.set('default', BASE_DEFAULT); srv.state.groups.set('linux', ''); srv.state.groupWrites.length = 0; srv.state.rejectConf = null; srv.state.reindentConf = false; srv.state.mode = null; srv.state.requests.length = 0; });

describe('describe and preview (read only)', () => {
  it('a group with no block: state none, no channels, the hash of the file', async () => {
    const d = await service.describe(makeCtx(), 'default', NOISY); assert.ok(d.ok); assert.strictEqual(d.state, 'none'); assert.deepStrictEqual(d.channels, []); assert.strictEqual(d.in_step, null); assert.strictEqual(d.sha256, sha(BASE_DEFAULT));
  });
  it('preview shows what would be written and writes nothing', async () => {
    const p = await service.preview(makeCtx(), 'default', NOISY, ['Security', 'System']); assert.ok(p.ok); assert.strictEqual(p.changed, true); assert.strictEqual(p.base_sha256, sha(BASE_DEFAULT));
    assert.strictEqual(p.diff.added.length, 2); assert.match(p.pushes.find((x) => x.channel === 'Security').query, /EventID != 4656/); assert.strictEqual(p.pushes.find((x) => x.channel === 'System').query, null); assert.strictEqual(p.outside_unchanged, true);
    assert.strictEqual(writes().length, 0); assert.ok(srv.state.requests.every((r) => r.method === 'GET' || r.path.includes('authenticate')));
  });
  it('preview refuses bad channels and a hand-edited block with the reason, and still reads the hash', async () => {
    const bad = await service.preview(makeCtx(), 'default', NOISY, ['a<b']); assert.ok(!bad.ok); assert.strictEqual(bad.code, 'INVALID');
    srv.state.groups.set('default', BASE_DEFAULT + wl.blockText(NOISY, ['Security']).replace('eventchannel', 'syslog') + '\n');
    const e = await service.preview(makeCtx(), 'default', NOISY, ['System']); assert.ok(!e.ok); assert.strictEqual(e.code, 'BLOCK_EDITED'); assert.match(e.base_sha256, /^[0-9a-f]{64}$/);
  });
  it('a bad group name is refused before any request', async () => {
    for (const g of ['', '..', 'a/b', 'x'.repeat(65)]) { const r = await service.describe(makeCtx(), g, NOISY); assert.ok(!r.ok); assert.strictEqual(r.code, 'BAD_GROUP'); }
    assert.ok(!srv.state.requests.some((r) => r.path.startsWith('/groups')));
  });
});

describe('apply', () => {
  it('writes the block, keeps every other byte, reads it back and settles the history as applied', async () => {
    const ctx = makeCtx(); const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT), policyRevision: 3 });
    assert.ok(r.ok && r.changed); assert.strictEqual(writes().length, 1); assert.ok(writes()[0].xml.startsWith(BASE_DEFAULT));
    assert.strictEqual(wl.find(srv.state.groups.get('default')).state, 'ok'); assert.strictEqual(ctx.rows[0].result, 'applied'); assert.strictEqual(ctx.rows[0].policy_revision, 3); assert.deepStrictEqual(ctx.rows[0].channels_before, []); assert.deepStrictEqual(ctx.rows[0].channels_after, ['Security']);
    assert.strictEqual(ctx.rows[0].before_content, BASE_DEFAULT);
  });
  it('a stale hash writes nothing', async () => {
    const r = await service.apply(makeCtx(), 'default', NOISY, ['Security'], { baseSha: sha('something else') }); assert.ok(!r.ok); assert.strictEqual(r.code, 'STALE'); assert.strictEqual(writes().length, 0); assert.strictEqual(r.current_sha256, sha(BASE_DEFAULT));
  });
  it('a missing or malformed hash is refused', async () => {
    for (const b of [undefined, '', 'abc', 'G'.repeat(64)]) { const r = await service.apply(makeCtx(), 'default', NOISY, ['Security'], { baseSha: b }); assert.strictEqual(r.code, 'BASE_REQUIRED'); }
    assert.strictEqual(writes().length, 0);
  });
  it('nothing to change writes nothing and leaves no history row', async () => {
    const ctx = makeCtx(); await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) });
    const d = await service.describe(ctx, 'default', NOISY); const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: d.sha256 });
    assert.ok(r.ok); assert.strictEqual(r.changed, false); assert.strictEqual(writes().length, 1); assert.strictEqual(ctx.rows.length, 1);
  });
  it('a policy saved after the block was written shows as out of step, and a second apply brings it in step', async () => {
    const ctx = makeCtx(); await service.apply(ctx, 'default', NOISY, ['Security', 'System'], { baseSha: sha(BASE_DEFAULT) });
    const later = wf.validate({ default: 'keep', rules: [{ id: 'x', action: 'drop', channel: 'Security', event_ids: [4624] }] }).policy;
    const d = await service.describe(ctx, 'default', later); assert.strictEqual(d.in_step, false); assert.deepStrictEqual(d.rows.filter((x) => !x.same).map((x) => x.channel), ['Security']);
    const r = await service.apply(ctx, 'default', later, d.channels, { baseSha: d.sha256, policyRevision: 2 }); assert.ok(r.ok && r.changed);
    assert.strictEqual((await service.describe(ctx, 'default', later)).in_step, true); assert.match(wl.find(srv.state.groups.get('default')).items[0].query, /4624/);
  });
  it('removing (an empty list) takes the block out and gives the file back', async () => {
    const ctx = makeCtx(); await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) });
    const d = await service.describe(ctx, 'default', NOISY); const r = await service.apply(ctx, 'default', NOISY, [], { baseSha: d.sha256, action: 'remove' });
    assert.ok(r.ok && r.changed); assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT); assert.strictEqual(ctx.rows[1].action, 'remove'); assert.strictEqual(ctx.rows[1].result, 'applied');
  });
  it('undo is an apply of the channels before: the block goes back and the rest of the file stays', async () => {
    const ctx = makeCtx(); await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) });
    let d = await service.describe(ctx, 'default', NOISY); await service.apply(ctx, 'default', NOISY, ['Security', 'System'], { baseSha: d.sha256 });
    d = await service.describe(ctx, 'default', NOISY); const edited = srv.state.groups.get('default') + '<!-- someone else -->\n'; srv.state.groups.set('default', edited); d = await service.describe(ctx, 'default', NOISY);
    const r = await service.apply(ctx, 'default', NOISY, ctx.rows[1].channels_before, { baseSha: d.sha256, action: 'undo' });
    assert.ok(r.ok); const now = srv.state.groups.get('default'); assert.deepStrictEqual(wl.find(now).channels, ['Security']); assert.ok(now.includes('<!-- someone else -->'));
  });
  it('a manager that refuses says why, leaves the file and the history says failed', async () => {
    srv.state.rejectConf = () => 'Invalid element in the configuration: query'; const ctx = makeCtx();
    const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) });
    assert.ok(!r.ok); assert.strictEqual(r.code, 'REJECTED'); assert.match(r.message, /Invalid element/); assert.strictEqual(r.unchanged, true); assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT);
    assert.strictEqual(ctx.rows[0].result, 'failed'); assert.match(ctx.rows[0].note, /Invalid element/);
  });
  it('a manager that cannot be reached is reported, and the history says it did not finish', async () => {
    const ctx = makeCtx(); let reads = 0;
    ctx.api = { ...api, putGroupAgentConf: async () => { throw new api.WazuhApiError('UNREACHABLE', 'The manager cannot be reached'); }, groupAgentConf: async (m, w, g) => { if (reads++ > 0) throw new api.WazuhApiError('UNREACHABLE', 'The manager cannot be reached'); return api.groupAgentConf(m, w, g); } };
    const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.code, 'MANAGER'); assert.strictEqual(r.unchanged, 'unknown'); assert.strictEqual(ctx.rows[0].result, 'failed');
  });
  it('if the manager answers OK but holds something else, the old file is put back and the history says rolled back', async () => {
    const ctx = makeCtx(); const put = api.putGroupAgentConf; let first = true;
    ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { await put(m, w, g, xml); if (first) { first = false; srv.state.groups.set(g, xml.replace('eventchannel', 'syslog')); } } };
    const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.code, 'VERIFY_FAILED'); assert.strictEqual(r.rolled_back, true); assert.match(r.message, /put back/);
    assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT); assert.strictEqual(ctx.rows[0].result, 'rolled_back'); assert.strictEqual(writes().length, 2);
  });
  it('a manager that holds the right channels with a different query is also not a success', async () => {
    const ctx = makeCtx(); const put = api.putGroupAgentConf; let first = true;
    ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { await put(m, w, g, xml); if (first) { first = false; srv.state.groups.set(g, xml.replace('EventID != 4656 and ', '')); } } };
    const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) }); assert.strictEqual(r.code, 'VERIFY_FAILED'); assert.strictEqual(r.rolled_back, true);
  });
  it('if the old file cannot be put back either, it says so plainly and the history keeps the old file', async () => {
    const ctx = makeCtx(); const put = api.putGroupAgentConf; let calls = 0;
    ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { calls++; if (calls === 1) { await put(m, w, g, xml); srv.state.groups.set(g, 'garbage'); } else throw new api.WazuhApiError('UNREACHABLE', 'gone'); } };
    const r = await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: sha(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.rolled_back, false); assert.match(r.message, /could NOT be put back/); assert.strictEqual(ctx.rows[0].before_content, BASE_DEFAULT);
  });
  it('a manager that re-indents and rewrites the file is not mistaken for a failure', async () => {
    srv.state.reindentConf = true; const ctx = makeCtx();
    const r = await service.apply(ctx, 'default', NOISY, ['Application', 'Security'], { baseSha: sha(BASE_DEFAULT) }); assert.ok(r.ok, r.message); assert.strictEqual(ctx.rows[0].result, 'applied');
    const d = await service.describe(ctx, 'default', NOISY); assert.strictEqual(d.state, 'ok'); assert.strictEqual(d.in_step, true);
  });
});

describe('next to the folders block of E10', () => {
  const L = [{ system: 'windows', path: 'C:\\ASIX-Test', realtime: true }];
  it('each service leaves the other\u2019s block exactly as it was, whichever came first', async () => {
    const ctx = makeCtx(); const fctx = { ...makeCtx(), hist: { record: async () => ({ id: 'f' }), settle: async () => {} } };
    await gcs.apply(fctx, 'default', L, { baseSha: sha(BASE_DEFAULT) });
    let d = await service.describe(ctx, 'default', NOISY); assert.strictEqual(d.state, 'none');
    await service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: d.sha256 });
    const fd = await gcs.describe(fctx, 'default'); assert.strictEqual(fd.state, 'ok'); assert.deepStrictEqual(fd.entries, L);
    await gcs.apply(fctx, 'default', [], { baseSha: fd.sha256, action: 'remove' });
    d = await service.describe(ctx, 'default', NOISY); assert.strictEqual(d.state, 'ok'); assert.deepStrictEqual(d.channels, ['Security']);
    await service.apply(ctx, 'default', NOISY, [], { baseSha: d.sha256, action: 'remove' }); assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT);
  });
  it('two changes to the same group at once take turns (the folders block and this one share a lock), so neither is lost', async () => {
    const ctx = makeCtx(); const fctx = { ...makeCtx(), hist: { record: async () => ({ id: 'f' }), settle: async () => {} } };
    const h = sha(BASE_DEFAULT);
    const [a, b] = await Promise.all([service.apply(ctx, 'default', NOISY, ['Security'], { baseSha: h }), gcs.apply(fctx, 'default', L, { baseSha: h })]);
    // one of them wins; the other reads the file after it and finds its hash stale, which is the safe answer (nothing is lost)
    assert.ok([a, b].filter((x) => x.ok).length >= 1); const stale = [a, b].filter((x) => !x.ok); for (const s of stale) assert.strictEqual(s.code, 'STALE');
    const now = srv.state.groups.get('default'); assert.ok(wl.find(now).state === 'ok' || gc.find(now).state === 'ok');
    assert.ok(writes().length === [a, b].filter((x) => x.ok).length);
  });
});
