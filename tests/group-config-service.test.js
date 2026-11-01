'use strict';
// E10: reading, previewing and changing the ASIX block of a group's agent.conf against the stand-in manager over real HTTPS (tests/fixtures/fake-wazuh-api.js, written from the documented
// Wazuh 4.x shape, NOT a real manager): the real API client, the real service, a recording history.
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '800';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const fake = require('./fixtures/fake-wazuh-api');
const api = require('../src/endpoints/wazuh-api');
const gc = require('../src/endpoints/group-config');
const service = require('../src/endpoints/group-config-service');

const WRITER = { user: 'asix-groupconfig', password: 'Wr1ter-pw!' };
const L = (path, realtime = false) => ({ system: 'linux', path, realtime });
const W = (path) => ({ system: 'windows', path, realtime: false });
let srv, n = 0;
const mgr = () => ({ tenant_id: 'T-' + srv.port, api_url: srv.url, api_user: srv.user, api_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', api_secret_enc_hash: 'h' });
const wr = () => ({ api_user: WRITER.user, api_password: WRITER.password, hash: 'w1' });
const makeCtx = () => { const rows = []; return { m: mgr(), w: wr(), api, rows, hist: { record: async (r) => { const id = 'h' + (++n); rows.push({ id, ...r }); return { id }; }, settle: async (id, result, sha, note) => { Object.assign(rows.find((x) => x.id === id), { result, after_sha256: sha, note }); } } }; };
const writes = () => srv.state.groupWrites;
const BASE_DEFAULT = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';

before(async () => { srv = await fake.start({ writer: WRITER }); });
after(async () => { await srv.stop(); });
beforeEach(() => { srv.state.groups.set('default', BASE_DEFAULT); srv.state.groups.set('linux', ''); srv.state.groupWrites.length = 0; srv.state.rejectConf = null; srv.state.mode = null; srv.state.requests.length = 0; });

describe('the writer is a separate user with its own token', () => {
  it('lists groups with their machine counts', async () => {
    const g = await api.groupList(mgr(), wr()); assert.deepStrictEqual(g.map((x) => x.name).sort(), ['default', 'linux']); assert.strictEqual(g.find((x) => x.name === 'default').agents, 3);
  });
  it('the read-only user cannot read groups or write a configuration (the manager says 403)', async () => {
    const ro = { api_user: srv.user, api_password: srv.password, hash: 'ro' };
    for (const f of [() => api.groupList(mgr(), ro), () => api.groupAgentConf(mgr(), ro, 'default'), () => api.putGroupAgentConf(mgr(), ro, 'default', '<agent_config/>')]) { await assert.rejects(f(), (e) => e.code === 'FORBIDDEN'); }
    assert.strictEqual(writes().length, 0);
  });
  it('a wrong password is AUTH_FAILED and the writer\u2019s token is separate from the read-only token', async () => {
    await assert.rejects(api.groupList(mgr(), { ...wr(), api_password: 'Wrong-pw-1!' }), (e) => e.code === 'AUTH_FAILED');
    await api.groupList(mgr(), wr()); assert.ok(srv.state.requests.some((r) => r.path === '/security/user/authenticate?raw=true'));
  });
  it('the writer\'s token and the read-only user\'s token live side by side (each signs in once, neither evicts the other)', async () => {
    const m = { ...mgr(), tenant_id: 'T-sidebyside-' + srv.port }; const before = srv.state.authCalls;
    for (let i = 0; i < 3; i++) { await api.managerInfo(m); await api.groupList(m, wr()); }
    assert.strictEqual(srv.state.authCalls - before, 2);
  });
  it('group names are checked before any request; the body is only ever the configuration text', async () => {
    for (const g of ['', '..', 'a/b', 'a b', 'x'.repeat(65), 'a?x=1']) await assert.rejects(api.groupAgentConf(mgr(), wr(), g), (e) => e.code === 'BAD_GROUP', g);
    await assert.rejects(api.putGroupAgentConf(mgr(), wr(), 'default', 'x'.repeat(262145)), (e) => e.code === 'BAD_BODY'); await assert.rejects(api.putGroupAgentConf(mgr(), wr(), 'default', { a: 1 }), (e) => e.code === 'BAD_BODY');
    assert.ok(!srv.state.requests.some((r) => r.path.startsWith('/groups')));
  });
  it('PUT sends the text as application/xml with its exact length', async () => {
    await api.putGroupAgentConf(mgr(), wr(), 'default', '<agent_config>\u00e9</agent_config>\n'); const w = writes()[0]; assert.strictEqual(w.contentType, 'application/xml'); assert.strictEqual(w.xml, '<agent_config>\u00e9</agent_config>\n');
  });
});

describe('describe and preview (read only)', () => {
  it('a group with no block: state none, no entries, a hash of the file', async () => {
    const d = await service.describe(makeCtx(), 'default'); assert.ok(d.ok); assert.strictEqual(d.state, 'none'); assert.deepStrictEqual(d.entries, []); assert.strictEqual(d.sha256, gc.sha256(BASE_DEFAULT));
  });
  it('an empty group file reads as an empty file', async () => { const d = await service.describe(makeCtx(), 'linux'); assert.ok(d.ok); assert.strictEqual(d.state, 'none'); assert.strictEqual(d.sha256, gc.sha256('')); });
  it('an unknown group is refused by the manager and passed on as an error', async () => { await assert.rejects(service.describe(makeCtx(), 'nogroup'), (e) => e.code === 'BAD_RESPONSE'); });
  it('preview shows the difference and WRITES NOTHING', async () => {
    const p = await service.preview(makeCtx(), 'default', [L('/srv/data', true), W('C:\\Data')]);
    assert.ok(p.ok && p.changed); assert.deepStrictEqual(p.diff.added, ['Linux /srv/data (real time)', 'Windows C:\\Data']); assert.strictEqual(p.base_sha256, gc.sha256(BASE_DEFAULT)); assert.strictEqual(p.outside_unchanged, true);
    assert.strictEqual(writes().length, 0); assert.ok(srv.state.requests.every((r) => r.method !== 'PUT' || r.path.startsWith('/security')));
  });
  it('preview refuses a bad entry with the reason, and a bad group', async () => {
    const p = await service.preview(makeCtx(), 'default', [L('/')]); assert.ok(!p.ok); assert.strictEqual(p.code, 'INVALID'); assert.match(p.message, /whole file system/);
    assert.strictEqual((await service.preview(makeCtx(), '../x', [])).code, 'BAD_GROUP');
  });
});

describe('apply', () => {
  it('writes only the block, keeps the rest of the file, records the history before and settles it, and reads the result back', async () => {
    const ctx = makeCtx(); const base = gc.sha256(BASE_DEFAULT);
    const r = await service.apply(ctx, 'default', [L('/srv/data', true), W('C:\\Data')], { baseSha: base });
    assert.ok(r.ok && r.changed); assert.strictEqual(writes().length, 1); assert.ok(writes()[0].xml.startsWith(BASE_DEFAULT)); assert.strictEqual(srv.state.groups.get('default'), writes()[0].xml);
    assert.deepStrictEqual(gc.find(srv.state.groups.get('default')).entries.map((e) => e.path), ['/srv/data', 'C:\\Data']);
    assert.strictEqual(ctx.rows.length, 1); const h = ctx.rows[0]; assert.strictEqual(h.result, 'applied'); assert.strictEqual(h.before_content, BASE_DEFAULT); assert.strictEqual(h.before_sha256, base); assert.deepStrictEqual(h.entries_before, []); assert.strictEqual(h.after_sha256, r.sha256); assert.strictEqual(h.action, 'apply');
  });
  it('the order is: read, history row, write, read again (the history exists before the manager is called)', async () => {
    const ctx = makeCtx(); let atWrite = null; const orig = ctx.hist.record; ctx.hist.record = async (r) => { const x = await orig(r); x.sawRow = true; return x; };
    const put = api.putGroupAgentConf; ctx.api = { ...api, putGroupAgentConf: async (...a) => { atWrite = ctx.rows.map((x) => x.result); return put(...a); } };
    await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.deepStrictEqual(atWrite, ['failed'], 'a row with result failed (not finished) existed when the manager was called');
  });
  it('refuses a change made on an old view of the file (STALE), and writes nothing', async () => {
    const ctx = makeCtx(); srv.state.groups.set('default', BASE_DEFAULT + '<!-- someone edited -->\n');
    const r = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.code, 'STALE'); assert.strictEqual(writes().length, 0); assert.strictEqual(ctx.rows.length, 0);
  });
  it('requires the hash of a preview', async () => {
    for (const b of [undefined, '', 'abc', 'G'.repeat(64), 5]) assert.strictEqual((await service.apply(makeCtx(), 'default', [L('/a')], { baseSha: b })).code, 'BASE_REQUIRED');
    assert.strictEqual(writes().length, 0);
  });
  it('the same list again is "nothing to change": no write, no history row', async () => {
    const ctx = makeCtx(); const a = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) });
    const b = await service.apply(ctx, 'default', [L('/a')], { baseSha: a.sha256 }); assert.ok(b.ok); assert.strictEqual(b.changed, false); assert.strictEqual(writes().length, 1); assert.strictEqual(ctx.rows.length, 1);
  });
  it('the manager refusing the file leaves the group as it was, says why, and settles the history as failed', async () => {
    const ctx = makeCtx(); srv.state.rejectConf = () => 'Wazuh syntax error: bad option';
    const r = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.code, 'REJECTED'); assert.match(r.message, /bad option/); assert.strictEqual(r.unchanged, true);
    assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT); assert.strictEqual(ctx.rows[0].result, 'failed'); assert.match(ctx.rows[0].note, /bad option/);
  });
  it('a manager that cannot be reached is reported, and the history says it did not finish', async () => {
    const ctx = makeCtx(); const dead = { ...api, putGroupAgentConf: async () => { throw new api.WazuhApiError('UNREACHABLE', 'The manager cannot be reached'); }, groupAgentConf: async (m, w, g) => { if (ctx.reads++ > 0) throw new api.WazuhApiError('UNREACHABLE', 'The manager cannot be reached'); return api.groupAgentConf(m, w, g); } }; ctx.reads = 0; ctx.api = dead;
    const r = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.code, 'MANAGER'); assert.strictEqual(r.unchanged, 'unknown'); assert.strictEqual(ctx.rows[0].result, 'failed');
  });
  it('if the manager answers OK but holds something else, the old file is put back and the history says rolled back', async () => {
    const ctx = makeCtx(); const put = api.putGroupAgentConf; let first = true;
    ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { await put(m, w, g, xml); if (first) { first = false; srv.state.groups.set(g, xml.replace('/data-a', '/data-b')); } } };
    const r = await service.apply(ctx, 'default', [L('/data-a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.code, 'VERIFY_FAILED'); assert.strictEqual(r.rolled_back, true); assert.match(r.message, /put back/);
    assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT); assert.strictEqual(ctx.rows[0].result, 'rolled_back'); assert.strictEqual(writes().length, 2);
  });
  it('if the old file cannot be put back either, it says so plainly and the history keeps the old file', async () => {
    const ctx = makeCtx(); const put = api.putGroupAgentConf; let calls = 0;
    ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { calls++; if (calls === 1) { await put(m, w, g, xml); srv.state.groups.set(g, 'garbage'); } else throw new api.WazuhApiError('UNREACHABLE', 'gone'); } };
    const r = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.ok(!r.ok); assert.strictEqual(r.rolled_back, false); assert.match(r.message, /could NOT be put back/); assert.strictEqual(ctx.rows[0].result, 'failed'); assert.strictEqual(ctx.rows[0].before_content, BASE_DEFAULT);
  });
  it('a manager that reformats the file is not mistaken for a failure (entries are compared, not bytes)', async () => {
    const ctx = makeCtx(); const put = api.putGroupAgentConf;
    ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { await put(m, w, g, xml); srv.state.groups.set(g, xml.replace(/\n/g, '\r\n')); } };
    const r = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) }); assert.ok(r.ok, JSON.stringify(r)); assert.strictEqual(ctx.rows[0].result, 'applied');
  });
  it('removing the list takes the block out and gives the file back as it was', async () => {
    const ctx = makeCtx(); const a = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) });
    const b = await service.apply(ctx, 'default', [], { baseSha: a.sha256, action: 'remove' }); assert.ok(b.ok && b.changed); assert.strictEqual(srv.state.groups.get('default'), BASE_DEFAULT); assert.strictEqual(ctx.rows[1].action, 'remove');
  });
  it('a block edited by hand or damaged markers are refused and nothing is written', async () => {
    for (const [xml, code] of [[gc.compose(BASE_DEFAULT, [L('/a')]).xml.replace('</syscheck>', '<x/></syscheck>'), 'BLOCK_EDITED'], [gc.compose(BASE_DEFAULT, [L('/a')]).xml.replace(gc.END, ''), 'MARKERS_BROKEN']]) {
      srv.state.groups.set('default', xml); srv.state.groupWrites.length = 0; const ctx = makeCtx();
      const r = await service.apply(ctx, 'default', [L('/b')], { baseSha: gc.sha256(xml) }); assert.strictEqual(r.code, code); assert.strictEqual(writes().length, 0); assert.strictEqual(ctx.rows.length, 0);
    }
  });
  it('two changes at once on one group: one wins, the other is told the file changed (no lost update)', async () => {
    const base = gc.sha256(BASE_DEFAULT); const c1 = makeCtx(), c2 = makeCtx();
    const [a, b] = await Promise.all([service.apply(c1, 'default', [L('/one')], { baseSha: base }), service.apply(c2, 'default', [L('/two')], { baseSha: base })]);
    assert.strictEqual([a, b].filter((r) => r.ok).length, 1); assert.strictEqual([a, b].find((r) => !r.ok).code, 'STALE'); assert.strictEqual(writes().length, 1);
  });
  it('different groups do not wait for each other', async () => {
    const [a, b] = await Promise.all([service.apply(makeCtx(), 'default', [L('/one')], { baseSha: gc.sha256(BASE_DEFAULT) }), service.apply(makeCtx(), 'linux', [L('/two')], { baseSha: gc.sha256('') })]); assert.ok(a.ok && b.ok);
  });
});

describe('undo: only the block goes back, not the file', () => {
  it('sets the block to the entries before that change and keeps edits made elsewhere in the file since', async () => {
    const ctx = makeCtx(); const a = await service.apply(ctx, 'default', [L('/a')], { baseSha: gc.sha256(BASE_DEFAULT) });
    const b = await service.apply(ctx, 'default', [L('/a'), L('/b')], { baseSha: a.sha256 });
    const withEdit = srv.state.groups.get('default') + '<!-- edited elsewhere -->\n'; srv.state.groups.set('default', withEdit);
    const u = await service.apply(ctx, 'default', ctx.rows[1].entries_before, { baseSha: gc.sha256(withEdit), action: 'undo' });
    assert.ok(u.ok && u.changed, JSON.stringify(u)); const now = srv.state.groups.get('default'); assert.deepStrictEqual(gc.find(now).entries.map((e) => e.path), ['/a']); assert.ok(now.endsWith('<!-- edited elsewhere -->\n')); assert.strictEqual(ctx.rows[2].action, 'undo'); assert.ok(b.ok);
  });
});
