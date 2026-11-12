'use strict';
// IOC feeds page (a page the module brings itself, docs/portal-shell.md). Same method as tests/lists-page.test.js: the real page file, a fake el() and a fake server.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = path.join(__dirname, '../src/portal/modules/ioc-feeds/feeds.js');
let tmp; let page;
before(async () => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-feeds-')); fs.copyFileSync(PAGE, path.join(tmp, 'feeds.mjs')); page = await import(pathToFileURL(path.join(tmp, 'feeds.mjs')).href); });
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

const clean = (k) => k.flat(Infinity).filter((x) => x !== '' && x != null);
const fakeEl = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: clean(kids), replaceChildren(...k) { this.kids = clean(k); } });
const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = clean(k); } });
const walk = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
const all = (host) => host.kids.flatMap(walk);
const allText = (host) => all(host).flatMap((x) => [x.textContent, ...(x.kids || []).filter((c) => typeof c === 'string')]).filter((x) => typeof x === 'string').join(' | ');
const buttons = (host, label) => all(host).filter((n) => n.tag === 'button' && (label === undefined || n.textContent === label));
const inputs = (host, type) => all(host).filter((n) => n.tag === 'input' && (!type || n.type === type));
const selects = (host) => all(host).filter((n) => n.tag === 'select');
const tick = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };
const click = async (host, label, nth = 0) => { const b = buttons(host, label)[nth]; assert.ok(b, `no button "${label}" in: ${allText(host).slice(0, 500)}`); assert.ok(!b.disabled, `"${label}" is disabled`); b.onclick(); await tick(); };
const type = (node, value) => { node.value = value; node.oninput({ target: node }); };
const choose = (sel, value) => sel.onchange({ target: { value } });

const ID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const mk = (n, over = {}) => ({ id: ID(n), integration_id: ID(900), integration_name: 'Blocklist feed', name: 'Feed ' + n, severity: 'medium', ttl_days: 30, interval_hours: 24, enabled: true, last_run_at: null, last_status: null, last_error: null, last_item_count: null, running: false, ...over });
const INTEG = [{ id: ID(900), name: 'Blocklist feed', status: 'configured', config: {} }];
const RUN_OK = { id: ID(70), run_kind: 'manual', started_at: '2026-11-11T10:00:00', status: 'ok', items: 5, added: 4, updated: 0, expired: 1, invalid: 2, skipped_other: 1, error_code: null, error_message: null };

function server(initial = [], { integrations = INTEG, runs = [] } = {}) {
  const S = { feeds: initial.map((f) => ({ ...f })), calls: [], fail: null, next: null, runs };
  S.api = async (p, opts = {}) => {
    const method = opts.method || 'GET'; S.calls.push({ method, path: p, body: opts.body });
    if (S.fail && S.fail.test(method + ' ' + p)) throw new Error('The server said no');
    let m;
    if (method === 'GET' && p === '/v1/ioc-feeds') return { success: true, feeds: S.feeds, integrations, severities: ['low', 'medium', 'high', 'critical'], intervals: [1, 6, 12, 24] };
    if (method === 'POST' && p === '/v1/ioc-feeds') { const f = mk(60, { ...opts.body, id: ID(60), integration_name: 'Blocklist feed' }); S.feeds.push(f); return { success: true, feed: f }; }
    if ((m = /^\/v1\/ioc-feeds\/([^/]+)\/runs\?/.exec(p))) return { success: true, runs: S.runs };
    if ((m = /^\/v1\/ioc-feeds\/([^/]+)\/run$/.exec(p))) { const run = S.next || RUN_OK; const f = S.feeds.find((x) => x.id === m[1]); f.last_status = run.status; f.last_run_at = '2026-11-11T10:00:00'; f.last_item_count = run.items; S.runs = [run, ...S.runs]; return { success: true, run }; }
    if ((m = /^\/v1\/ioc-feeds\/([^/?]+)(\?.*)?$/.exec(p))) {
      const f = S.feeds.find((x) => x.id === m[1]);
      if (method === 'DELETE') { S.feeds = S.feeds.filter((x) => x !== f); return { success: true, indicators_removed: 0 }; }
      if (method === 'PUT') { Object.assign(f, opts.body); return { success: true, feed: f }; }
    }
    throw new Error('unexpected ' + method + ' ' + p);
  };
  return S;
}
const ctxFor = (S, { write = true } = {}) => ({ el: fakeEl, api: S.api, can: (p) => (p === 'threatintel:feeds:write' ? write : true), tenant: 't', navigate() {}, theme: 'dark', toasts: [], toast(t, k) { this.toasts.push([t, k]); } });
async function open(S, opts) { const host = fakeHost(); const ctx = ctxFor(S, opts); await page.mount(host, ctx); return { host, ctx }; }

describe('the list of feeds', () => {
  it('shows each feed with its last run', async () => {
    const S = server([mk(1, { name: 'Main', last_status: 'ok', last_run_at: '2026-11-11T09:30:00', last_item_count: 120 }), mk(2, { name: 'Broken', last_status: 'failed', last_error: 'The feed answered with status 500', enabled: false }), mk(3, { name: 'New' })]);
    const { host } = await open(S); const t = allText(host);
    assert.match(t, /Main/); assert.match(t, /Last run succeeded/); assert.match(t, /Last run 2026-11-11 09:30, 120 indicators/); assert.match(t, /every day/);
    assert.match(t, /Last run failed/); assert.match(t, /status 500/); assert.match(t, /Switched off/); assert.match(t, /Never run/);
  });
  it('says so when there are none', async () => { const { host } = await open(server([])); assert.match(allText(host), /There are no feeds yet/); });
  it('a viewer without the write permission sees nothing that changes anything', async () => {
    const { host } = await open(server([mk(1)]), { write: false });
    assert.strictEqual(buttons(host, 'Add a feed').length, 0);
    await click(host, 'Open');
    const labels = buttons(host).map((b) => b.textContent);
    for (const bad of ['Run now', 'Save settings', 'Switch off', 'Delete the feed…']) assert.ok(!labels.includes(bad), bad);
    assert.match(allText(host), /medium severity, kept 30 days/);
  });
});

describe('adding a feed', () => {
  it('sends the choices as numbers and opens the new feed', async () => {
    const S = server([]); const { host, ctx } = await open(S);
    await click(host, 'Add a feed'); assert.ok(buttons(host, 'Add')[0].disabled, 'no integration chosen yet');
    choose(selects(host)[0], ID(900)); await tick();
    type(inputs(host, 'text')[0], 'Daily blocklist');
    choose(selects(host)[1], 'high'); choose(selects(host)[2], '6'); type(inputs(host, 'text')[1], '14');
    await click(host, 'Add');
    assert.deepStrictEqual(S.calls.find((c) => c.method === 'POST').body, { integration_id: ID(900), name: 'Daily blocklist', severity: 'high', ttl_days: 14, interval_hours: 6 });
    assert.match(allText(host), /Recent runs/); assert.ok(ctx.toasts.some(([t]) => /added/.test(t)));
  });
  it('without a threat feed integration it says where to add one', async () => {
    const { host } = await open(server([], { integrations: [] })); await click(host, 'Add a feed');
    assert.match(allText(host), /needs an integration of the type Threat feed/); assert.strictEqual(buttons(host, 'Add').length, 0);
  });
  it('a refusal keeps the form and shows the reason', async () => {
    const S = server([]); S.fail = /^POST \/v1\/ioc-feeds$/; const { host } = await open(S);
    await click(host, 'Add a feed'); choose(selects(host)[0], ID(900)); await tick(); type(inputs(host, 'text')[0], 'X'); await click(host, 'Add');
    assert.match(allText(host), /The server said no/); assert.strictEqual(inputs(host, 'text')[0].value, 'X');
  });
});

describe('one feed', () => {
  const setup = async (opts, feed = mk(1, { last_status: 'ok', last_item_count: 5 }), runs = [RUN_OK]) => { const S = server([feed], { runs }); const o = await open(S, opts); await click(o.host, 'Open'); return { S, ...o }; };
  it('shows the recent runs with what each changed', async () => {
    const { host } = await setup({}, undefined, [RUN_OK, { ...RUN_OK, id: ID(71), status: 'failed', run_kind: 'schedule', error_code: 'HTTP_STATUS', error_message: 'The feed answered with status 500' }]);
    const t = allText(host);
    assert.match(t, /5 in the feed · 4 added · 0 refreshed · 1 expired · 2 not recognised · 1 owned by another source/); assert.match(t, /by hand/); assert.match(t, /scheduled/); assert.match(t, /HTTP_STATUS: The feed answered with status 500/);
  });
  it('Run now shows what happened and refreshes the history', async () => {
    const { S, host } = await setup({}, undefined, []);
    assert.match(allText(host), /It has not run yet/);
    await click(host, 'Run now');
    assert.deepStrictEqual(S.calls.find((c) => /\/run$/.test(c.path)).body, {});
    assert.match(allText(host), /Done: 5 indicators in the feed, 4 added, 0 refreshed, 1 expired\./); assert.match(allText(host), /5 in the feed · 4 added/);
  });
  it('a failed run shows its reason; only a shrunk feed offers Run anyway, which sends force', async () => {
    const { S, host } = await setup(); S.next = { ...RUN_OK, status: 'failed', error_code: 'HTTP_STATUS', error_message: 'The feed answered with status 500', items: null };
    await click(host, 'Run now'); assert.match(allText(host), /Failed \(HTTP_STATUS\): The feed answered with status 500/); assert.strictEqual(buttons(host, 'Run anyway').length, 0);
    S.next = { ...RUN_OK, status: 'failed', error_code: 'FEED_SHRANK', error_message: 'The feed lists 2 indicators, far fewer than the 25 last time.', items: 2 };
    await click(host, 'Run now'); assert.match(allText(host), /FEED_SHRANK/);
    S.next = RUN_OK; await click(host, 'Run anyway');
    assert.deepStrictEqual(S.calls.filter((c) => /\/run$/.test(c.path)).map((c) => c.body), [{}, {}, { force: true }]);
  });
  it('saves only the setting that changed, and says when nothing did', async () => {
    const { S, host } = await setup();
    await click(host, 'Save settings'); assert.match(allText(host), /Nothing has changed/); assert.ok(!S.calls.some((c) => c.method === 'PUT'));
    type(inputs(host, 'text')[0], '90'); await click(host, 'Save settings');
    assert.deepStrictEqual(S.calls.find((c) => c.method === 'PUT').body, { ttl_days: 90 });
  });
  it('switching off and on', async () => {
    const { S, host } = await setup();
    await click(host, 'Switch off'); assert.deepStrictEqual(S.calls.find((c) => c.method === 'PUT').body, { enabled: false }); assert.match(allText(host), /Switched off/);
    await click(host, 'Switch on'); assert.doesNotMatch(allText(host), /Switched off/);
  });
  it('deleting takes two presses; the indicators stay unless asked', async () => {
    const { S, host, ctx } = await setup();
    await click(host, 'Delete the feed…'); assert.match(allText(host), /Delete "Feed 1"\? /); assert.ok(!S.calls.some((c) => c.method === 'DELETE'));
    await click(host, 'No'); assert.ok(!S.calls.some((c) => c.method === 'DELETE'));
    await click(host, 'Delete the feed…'); await click(host, 'Yes, delete');
    assert.deepStrictEqual(S.calls.find((c) => c.method === 'DELETE').path, '/v1/ioc-feeds/' + ID(1));
    assert.match(allText(host), /There are no feeds yet/); assert.ok(ctx.toasts.some(([t]) => /deleted/.test(t)));
  });
  it('deleting with the box ticked also removes the indicators', async () => {
    const { S, host } = await setup();
    inputs(host, 'checkbox')[0].onchange({ target: { checked: true } }); await click(host, 'Delete the feed…'); assert.match(allText(host), /and its indicators\? /);
    await click(host, 'Yes, delete'); assert.strictEqual(S.calls.find((c) => c.method === 'DELETE').path, '/v1/ioc-feeds/' + ID(1) + '?remove_indicators=true');
  });
});

describe('the page file', () => {
  const src = fs.readFileSync(PAGE, 'utf8');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/\s\/\/\s.*$/gm, '');
  it('draws only through ctx.el and talks only through ctx.api', () => {
    for (const bad of [/\bdocument\b/, /\bwindow\b/, /\binnerHTML\b/, /\balert\(/, /\bconfirm\(/, /\bfetch\(/, /\blocalStorage\b/, /\bXMLHttpRequest\b/, /\beval\(/, /\bconsole\./]) assert.ok(!bad.test(code), String(bad));
  });
  it('is the page the manifest names', () => {
    const m = require('../src/modules/manifests/ioc-feeds');
    assert.deepStrictEqual(m.ui.entries.map((e) => e.page), ['feeds.js']); assert.ok(m.permissions.includes(m.ui.entries[0].permission)); assert.deepStrictEqual(m.requires, ['threat-intel', 'integrations']);
    assert.ok(fs.existsSync(path.join(__dirname, '../src/portal/modules/ioc-feeds', m.ui.entries[0].page)));
  });
});
