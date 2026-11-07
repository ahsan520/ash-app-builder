'use strict';
// E13: the Linux logs block of an agent group's agent.conf: the pure rules, and the service against the stand-in manager over real HTTPS (tests/fixtures/fake-wazuh-api.js; NOT a real manager).
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '800';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const fake = require('./fixtures/fake-wazuh-api');
const api = require('../src/endpoints/wazuh-api');
const gc = require('../src/endpoints/group-config');
const gcs = require('../src/endpoints/group-config-service');
const wl = require('../src/endpoints/group-winlog');
const wf = require('../src/endpoints/win-filter');
const ll = require('../src/endpoints/group-linuxlog');
const service = require('../src/endpoints/group-linuxlog-service');

const BASE = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';
const F = (path) => ({ type: 'file', path }), J = { type: 'journald' };

describe('paths and entries', () => {
  it('accept log files and patterns, and the journal once', () => {
    const v = ll.validateEntries([F('/var/log/b.log'), J, F('/var/log/a/*.log'), J, F('/var/log/b.log')]); assert.ok(v.ok);
    assert.deepStrictEqual(v.entries, [J, F('/var/log/a/*.log'), F('/var/log/b.log')]);
  });
  it('refuse everything that is not a plain absolute file path, or is a secret or system place', () => {
    for (const p of ['relative.log', '/', '/var/log/', '/var/log//x', '/var/log/../etc/passwd', '/var/log/./x', '/var/log/a b', '/var/log/a;b', '/var/log/$(id)', '/var/log/`id`', '/var/log/a\nb', '/var/log/<x>', '/var/log/a&b', '/var/log/a"b', "/var/log/a'b",
      '/proc/self/environ', '/sys/kernel/x', '/dev/mem', '/boot/grub/grub.cfg', '/etc/shadow', '/etc/shadow-', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d/x', '/etc/ssh/ssh_host_rsa_key', '/home/a/.ssh/authorized_keys', '/home/a/id_ed25519', '/srv/app/tls.key', '/srv/x/CERT.PEM', '/root/.bash_history', '/root/.profile', '/x/.netrc', '/x/' + 'a'.repeat(200)]) {
      assert.ok(ll.pathProblem(p), p); assert.ok(!ll.validateEntries([F(p)]).ok, p);
    }
    for (const bad of [null, 5, 'x', [], {}, { type: 'file' }, { type: 'dir', path: '/a' }, { type: 'journald', path: '/a' }, { type: 'file', path: '/var/log/a', extra: 1 }]) assert.ok(!ll.validateEntries([bad]).ok, JSON.stringify(bad));
    assert.ok(!ll.validateEntries('x').ok); assert.ok(!ll.validateEntries(Array.from({ length: 21 }, (_, i) => F('/var/log/f' + i))).ok); assert.ok(ll.validateEntries(Array.from({ length: 20 }, (_, i) => F('/var/log/f' + i))).ok);
  });
});

describe('the block', () => {
  const E = [J, F('/var/log/app/*.log'), F('/var/log/auth.log')];
  it('has the markers, the right log format for each kind, and reads back as the same entries', () => {
    const t = ll.blockText(E); assert.ok(t.startsWith(ll.BEGIN + '\n<agent_config os="Linux">')); assert.match(t, /<log_format>journald<\/log_format>\s*<location>journald<\/location>/); assert.match(t, /<log_format>syslog<\/log_format>\s*<location>\/var\/log\/app\/\*\.log<\/location>/);
    const f = ll.find('<x/>\n\n' + t + '\n'); assert.strictEqual(f.state, 'ok'); assert.deepStrictEqual(f.entries, E);
  });
  it('is none, broken or edited by what is in the file; a manager that re-indents is fine', () => {
    const t = ll.blockText(E);
    assert.strictEqual(ll.find(BASE).state, 'none'); assert.strictEqual(ll.find(t + t).state, 'broken'); assert.strictEqual(ll.find(ll.END + ll.BEGIN).state, 'broken');
    for (const c of [t.replace('os="Linux"', 'os="Windows"'), t.replace('journald</location>', 'other</location>'), t.replace('/var/log/auth.log', '/etc/shadow'), t.replace('</agent_config>', '<syscheck/></agent_config>'), t.replace('v1 -->', 'v2 -->'), t.replace('<log_format>syslog', '<log_format>json'), t.replace(/<localfile>[\s\S]*<\/localfile>/, '')]) assert.strictEqual(ll.find(c).state, 'edited', c.slice(0, 100));
    const squashed = t.split('\n').map((l) => l.trim()).filter(Boolean).join('\r\n'); assert.strictEqual(ll.find(squashed).state, 'ok');
  });
  it('add then remove gives the same file back; bytes outside the block are kept; the same list changes nothing', () => {
    for (const base of [BASE, '', 'one\n', BASE + '\n\n']) { const a = ll.compose(base, E); assert.ok(a.ok && a.changed); assert.strictEqual(ll.compose(a.xml, []).xml, base, JSON.stringify(base)); assert.strictEqual(ll.compose(a.xml, E).changed, false); }
    const a = ll.compose(BASE, E), tail = '<!-- hand written -->\n', c = ll.compose(a.xml + tail, [F('/var/log/x.log')]); assert.ok(c.xml.startsWith(BASE) && c.xml.endsWith(tail));
  });
  it('refuses a damaged or edited block, bad entries, NUL and size', () => {
    const t = ll.blockText(E);
    assert.strictEqual(ll.compose(BASE + t + '\n' + ll.BEGIN, E).code, 'MARKERS_BROKEN'); assert.strictEqual(ll.compose(BASE + t.replace('syslog', 'json') + '\n', E).code, 'BLOCK_EDITED'); assert.strictEqual(ll.compose(BASE, [F('/etc/shadow')]).code, 'INVALID');
    assert.strictEqual(ll.compose('a\u0000', E).code, 'BAD_FILE'); assert.strictEqual(ll.compose('x'.repeat(ll.MAX_FILE_BYTES + 1), E).code, 'TOO_LARGE');
  });
  it('lives next to the folders block (E10) and the Windows channels block (E11): each added, changed and removed with the others left as they were', () => {
    const folders = [{ system: 'linux', path: '/srv/data', realtime: true }], pol = wf.validate(wf.presetNoisySecurity()).policy;
    const f1 = gc.compose(BASE, folders), w1 = wl.compose(f1.xml, pol, ['Security']), l1 = ll.compose(w1.xml, E);
    assert.strictEqual(gc.find(l1.xml).state, 'ok'); assert.strictEqual(wl.find(l1.xml).state, 'ok'); assert.strictEqual(ll.find(l1.xml).state, 'ok');
    assert.strictEqual(ll.find(gc.blockText(folders)).state, 'none'); assert.strictEqual(ll.find(wl.blockText(pol, ['Security'])).state, 'none'); assert.strictEqual(wl.find(ll.blockText(E)).state, 'none'); assert.strictEqual(gc.find(ll.blockText(E)).state, 'none');
    assert.strictEqual(ll.compose(l1.xml, []).xml, w1.xml); assert.strictEqual(wl.compose(w1.xml, pol, []).xml, f1.xml); assert.strictEqual(gc.compose(f1.xml, []).xml, BASE);
  });
  it('diff lists added, removed and unchanged', () => { const d = ll.diff(ll.find(ll.blockText([J, F('/a/x.log')])), [F('/a/x.log'), F('/a/y.log')]); assert.deepStrictEqual([d.added, d.removed, d.same], [['/a/y.log'], ['the systemd journal'], 1]); });
});

describe('the service against the stand-in manager', () => {
  const WRITER = { user: 'asix-groupconfig', password: 'Wr1ter-pw!' }; let srv, n = 0;
  const mgr = () => ({ tenant_id: 'T-' + srv.port, api_url: srv.url, api_user: srv.user, api_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', api_secret_enc_hash: 'h' });
  const makeCtx = () => { const rows = []; return { m: mgr(), w: { api_user: WRITER.user, api_password: WRITER.password, hash: 'w1' }, api, rows, hist: { record: async (r) => { const id = 'l' + (++n); rows.push({ id, ...r }); return { id }; }, settle: async (id, result, sha, note) => { Object.assign(rows.find((x) => x.id === id), { result, after_sha256: sha, note }); } } }; };
  const writes = () => srv.state.groupWrites; const sha = gc.sha256;
  before(async () => { srv = await fake.start({ writer: WRITER }); }); after(async () => { await srv.stop(); });
  beforeEach(() => { srv.state.groups.set('default', BASE); srv.state.groupWrites.length = 0; srv.state.rejectConf = null; srv.state.reindentConf = false; });
  const E = [J, F('/var/log/app/*.log')];
  it('describe and preview read only; apply writes the block, keeps the rest and settles the history', async () => {
    const ctx = makeCtx(); const d = await service.describe(ctx, 'default'); assert.strictEqual(d.state, 'none'); const p = await service.preview(ctx, 'default', E); assert.ok(p.ok && p.changed); assert.strictEqual(writes().length, 0);
    const r = await service.apply(ctx, 'default', E, { baseSha: p.base_sha256 }); assert.ok(r.ok && r.changed); assert.ok(writes()[0].xml.startsWith(BASE)); assert.strictEqual(ll.find(srv.state.groups.get('default')).state, 'ok'); assert.strictEqual(ctx.rows[0].result, 'applied'); assert.deepStrictEqual(ctx.rows[0].entries_after, E);
  });
  it('a stale or missing hash writes nothing; bad entries and a bad group are refused', async () => {
    assert.strictEqual((await service.apply(makeCtx(), 'default', E, { baseSha: sha('x') })).code, 'STALE'); assert.strictEqual((await service.apply(makeCtx(), 'default', E, {})).code, 'BASE_REQUIRED');
    assert.strictEqual((await service.apply(makeCtx(), 'default', [F('/etc/shadow')], { baseSha: sha(BASE) })).code, 'INVALID'); assert.strictEqual((await service.describe(makeCtx(), '../x')).code, 'BAD_GROUP'); assert.strictEqual(writes().length, 0);
  });
  it('remove and undo restore the earlier list and keep other changes', async () => {
    const ctx = makeCtx(); await service.apply(ctx, 'default', [J], { baseSha: sha(BASE) }); let d = await service.describe(ctx, 'default'); await service.apply(ctx, 'default', E, { baseSha: d.sha256 });
    srv.state.groups.set('default', srv.state.groups.get('default') + '<!-- other -->\n'); d = await service.describe(ctx, 'default');
    const u = await service.apply(ctx, 'default', ctx.rows[1].entries_before, { baseSha: d.sha256, action: 'undo' }); assert.ok(u.ok); const now = srv.state.groups.get('default'); assert.deepStrictEqual(ll.find(now).entries, [J]); assert.ok(now.includes('<!-- other -->'));
    d = await service.describe(ctx, 'default'); await service.apply(ctx, 'default', [], { baseSha: d.sha256, action: 'remove' }); assert.ok(!srv.state.groups.get('default').includes('ASIX:linux-logs'));
  });
  it('a refusing manager leaves the file; a wrong read-back is rolled back; a re-indenting manager is not a failure', async () => {
    srv.state.rejectConf = () => 'Invalid element'; let ctx = makeCtx(); let r = await service.apply(ctx, 'default', E, { baseSha: sha(BASE) }); assert.strictEqual(r.code, 'REJECTED'); assert.strictEqual(r.unchanged, true); assert.strictEqual(ctx.rows[0].result, 'failed'); srv.state.rejectConf = null;
    ctx = makeCtx(); const put = api.putGroupAgentConf; let first = true; ctx.api = { ...api, putGroupAgentConf: async (m, w, g, xml) => { await put(m, w, g, xml); if (first) { first = false; srv.state.groups.set(g, xml.replace('/var/log/app/*.log', '/var/log/other.log')); } } };
    r = await service.apply(ctx, 'default', E, { baseSha: sha(BASE) }); assert.strictEqual(r.code, 'VERIFY_FAILED'); assert.strictEqual(r.rolled_back, true); assert.strictEqual(srv.state.groups.get('default'), BASE); assert.strictEqual(ctx.rows[0].result, 'rolled_back');
    srv.state.reindentConf = true; ctx = makeCtx(); r = await service.apply(ctx, 'default', E, { baseSha: sha(BASE) }); assert.ok(r.ok, r.message); assert.strictEqual(ctx.rows[0].result, 'applied');
  });
  it('takes turns with the folders block on one group (one lock), and neither block is lost', async () => {
    const ctx = makeCtx(), fctx = { ...makeCtx(), hist: { record: async () => ({ id: 'f' }), settle: async () => {} } }, h = sha(BASE);
    const [a, b] = await Promise.all([service.apply(ctx, 'default', E, { baseSha: h }), gcs.apply(fctx, 'default', [{ system: 'linux', path: '/srv/d', realtime: true }], { baseSha: h })]);
    assert.ok([a, b].some((x) => x.ok)); for (const x of [a, b].filter((y) => !y.ok)) assert.strictEqual(x.code, 'STALE'); assert.strictEqual(writes().length, [a, b].filter((x) => x.ok).length);
  });
});
