'use strict';
// SR1: the Integrations page (a page the module brings itself, docs/portal-shell.md). Same method as tests/lists-page.test.js: the real page file, a fake el()
// and a fake server. What matters most: a credential is write-only on the page too.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = path.join(__dirname, '../src/portal/modules/integrations/integrations.js');
let tmp; let page;
before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-integ-'));
  fs.copyFileSync(PAGE, path.join(tmp, 'integrations.mjs'));
  page = await import(pathToFileURL(path.join(tmp, 'integrations.mjs')).href);
});
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

const DEFS = [
  { id: 'opnsense', name: 'OPNsense', category: 'firewall', description: 'An OPNsense firewall.', config: [{ name: 'base_url', label: 'Address of the firewall', type: 'url', required: true }],
    credentials: [{ name: 'api_key', label: 'API key', required: true }, { name: 'api_secret', label: 'API secret', required: true }] },
  { id: 'threat-feed', name: 'Threat feed (HTTP)', category: 'threat-intel', description: 'An HTTP feed.', config: [{ name: 'feed_url', label: 'Address of the feed', type: 'url', required: true }, { name: 'format', label: 'Format', type: 'enum', values: ['plain-text', 'csv'], required: true }],
    credentials: [{ name: 'token', label: 'Token', required: false }] },
];
const ID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const mk = (n, over = {}) => ({ id: ID(n), definition_id: 'opnsense', definition_name: 'OPNsense', category: 'firewall', known_definition: true, name: 'Edge ' + n, config: { base_url: 'https://fw.example.com' }, enabled: true, status: 'not_configured',
  credentials: [{ name: 'api_key', label: 'API key', required: true, set: false }, { name: 'api_secret', label: 'API secret', required: true, set: false }], credential_set_at: null, credential_set_by_name: null, created_by_name: 'alice', ...over });

function server(initial = [], { secretsOk = true } = {}) {
  const S = { list: initial.map((x) => ({ ...x })), calls: [], fail: null, secretsOk };
  S.api = async (p, opts = {}) => {
    const method = opts.method || 'GET'; S.calls.push({ method, path: p, body: opts.body });
    if (S.fail && S.fail.test(method + ' ' + p)) throw new Error('The server said no');
    let m;
    if (p === '/v1/integrations/definitions') return { success: true, definitions: DEFS, categories: [] };
    if (method === 'GET' && p === '/v1/integrations') return { success: true, integrations: S.list, secrets_configured: S.secretsOk };
    if (method === 'POST' && p === '/v1/integrations') { const d = DEFS.find((x) => x.id === opts.body.definition_id); const i = mk(60, { definition_id: d.id, definition_name: d.name, category: d.category, name: opts.body.name, config: opts.body.config, id: ID(60) }); S.list.push(i); return { success: true, integration: i }; }
    if ((m = /^\/v1\/integrations\/([^/]+)\/credentials$/.exec(p))) {
      const i = S.list.find((x) => x.id === m[1]);
      if (method === 'PUT') { for (const k of Object.keys(opts.body.values)) i.credentials.find((c) => c.name === k).set = true; i.status = i.credentials.every((c) => !c.required || c.set) ? 'configured' : 'not_configured'; i.credential_set_at = '2026-11-11T10:00:00'; i.credential_set_by_name = 'alice'; return { success: true, integration: i }; }
      i.credentials.forEach((c) => { c.set = false; }); i.status = 'not_configured'; return { success: true, integration: i };
    }
    if ((m = /^\/v1\/integrations\/([^/]+)$/.exec(p))) {
      const i = S.list.find((x) => x.id === m[1]);
      if (method === 'DELETE') { S.list = S.list.filter((x) => x !== i); return { success: true }; }
      if (method === 'PUT') { if (opts.body.enabled !== undefined) { i.enabled = opts.body.enabled; i.status = i.enabled ? 'configured' : 'disabled'; } for (const [k, v] of Object.entries(opts.body.config || {})) { if (v === null) delete i.config[k]; else i.config[k] = v; } return { success: true, integration: i }; }
    }
    throw new Error('unexpected ' + method + ' ' + p);
  };
  return S;
}
const ctxFor = (S, { write = true } = {}) => ({ el: fakeEl, api: S.api, can: (p) => (p === 'soar:integrations:write' ? write : true), tenant: 't', navigate() {}, theme: 'dark', toasts: [], toast(t, k) { this.toasts.push([t, k]); } });
async function open(S, opts) { const host = fakeHost(); const ctx = ctxFor(S, opts); await page.mount(host, ctx); return { host, ctx }; }

describe('the list of integrations', () => {
  it('groups by category with status, product and settings', async () => {
    const S = server([mk(1, { name: 'Edge', status: 'configured' }), mk(2, { name: 'Blocklist', definition_id: 'threat-feed', definition_name: 'Threat feed (HTTP)', category: 'threat-intel', config: { feed_url: 'https://f.example/x.txt', format: 'csv' }, status: 'not_configured' })]);
    const { host } = await open(S); const t = allText(host);
    assert.match(t, /Firewalls/); assert.match(t, /Threat intelligence/); assert.match(t, /Edge/); assert.match(t, /Configured/); assert.match(t, /Not configured/);
    assert.match(t, /base_url: https:\/\/fw\.example\.com/); assert.match(t, /format: csv/);
  });
  it('says so when there are none; warns when the key is missing', async () => {
    const { host } = await open(server([], { secretsOk: false }));
    assert.match(allText(host), /There are no integrations yet/); assert.match(allText(host), /key that protects stored secrets is not configured/);
  });
  it('a viewer without the write permission sees no button that changes anything and no input', async () => {
    const S = server([mk(1)]); const { host } = await open(S, { write: false });
    assert.strictEqual(buttons(host, 'Add an integration').length, 0);
    await click(host, 'Open');
    const labels = buttons(host).map((b) => b.textContent);
    for (const bad of ['Save settings', 'Save credentials', 'Clear all credentials…', 'Switch off', 'Delete…']) assert.ok(!labels.includes(bad), bad);
    assert.strictEqual(inputs(host).length, 0);
    assert.match(allText(host), /API key/); assert.match(allText(host), /Not set/);
  });
});

describe('adding one', () => {
  it('draws the settings of the chosen product, sends them, then opens it', async () => {
    const S = server([]); const { host, ctx } = await open(S);
    await click(host, 'Add an integration');
    assert.ok(buttons(host, 'Add')[0].disabled, 'nothing chosen yet');
    choose(selects(host)[0], 'threat-feed'); await tick();
    assert.match(allText(host), /An HTTP feed\./); assert.match(allText(host), /Address of the feed \(required\)/); assert.match(allText(host), /Format \(required\)/);
    type(inputs(host, 'text').find((i) => i.value === '' && i.style.includes('60%')), 'Blocklist');
    type(inputs(host, 'text').find((i) => i.value === '' && i.style.includes('70%')), 'https://f.example/x.txt');
    choose(selects(host)[1], 'plain-text');
    await click(host, 'Add');
    assert.deepStrictEqual(S.calls.find((c) => c.method === 'POST').body, { definition_id: 'threat-feed', name: 'Blocklist', config: { feed_url: 'https://f.example/x.txt', format: 'plain-text' } });
    assert.match(allText(host), /Credentials/); assert.ok(ctx.toasts.some(([t]) => /added/.test(t)));
  });
  it('a refusal keeps the form and shows the reason', async () => {
    const S = server([]); S.fail = /^POST \/v1\/integrations$/; const { host } = await open(S);
    await click(host, 'Add an integration'); choose(selects(host)[0], 'opnsense'); await tick();
    type(inputs(host, 'text')[0], 'Edge'); await click(host, 'Add');
    assert.match(allText(host), /The server said no/); assert.strictEqual(inputs(host, 'text')[0].value, 'Edge');
  });
});

describe('credentials are write-only', () => {
  const setup = async (opts, list = [mk(1)]) => { const S = server(list); const o = await open(S, opts); await click(o.host, 'Open'); return { S, ...o }; };
  it('every credential input is a password input, empty, and the page shows only whether it is set', async () => {
    const { host } = await setup({}, [mk(1, { credentials: [{ name: 'api_key', label: 'API key', required: true, set: true }, { name: 'api_secret', label: 'API secret', required: true, set: false }], status: 'not_configured' })]);
    const pw = inputs(host, 'password'); assert.strictEqual(pw.length, 2);
    for (const p of pw) { assert.strictEqual(p.value, ''); assert.strictEqual(p.autocomplete, 'new-password'); }
    assert.strictEqual(pw[0].placeholder, 'Type to replace'); assert.strictEqual(pw[1].placeholder, 'Type to set');
    assert.match(allText(host), /API key \| .*Set/); assert.match(allText(host), /Not set/);
  });
  it('saves only what was typed, then drops it from the page', async () => {
    const { S, host } = await setup();
    type(inputs(host, 'password')[0], 'k-TYPED-SECRET'); await click(host, 'Save credentials');
    assert.deepStrictEqual(S.calls.find((c) => c.method === 'PUT' && /credentials$/.test(c.path)).body, { values: { api_key: 'k-TYPED-SECRET' } });
    for (const p of inputs(host, 'password')) assert.strictEqual(p.value, '', 'nothing typed stays on the page');
    assert.ok(!allText(host).includes('k-TYPED-SECRET')); assert.ok(!JSON.stringify(all(host).map((n) => n.value)).includes('k-TYPED-SECRET'));
    assert.match(allText(host), /Set/); assert.match(allText(host), /Last changed 2026-11-11 10:00 by alice/);
  });
  it('becomes Configured when the last required credential is set', async () => {
    const { host } = await setup();
    type(inputs(host, 'password')[0], 'a'); type(inputs(host, 'password')[1], 'b'); await click(host, 'Save credentials');
    assert.match(allText(host), /Configured/); assert.doesNotMatch(allText(host), /Not configured: set every credential/);
  });
  it('asks for a value instead of sending an empty request', async () => {
    const { S, host } = await setup(); const n = S.calls.length;
    await click(host, 'Save credentials'); assert.match(allText(host), /Type at least one credential first/); assert.strictEqual(S.calls.length, n);
  });
  it('a failed save keeps what was typed so it is not lost, and shows the reason', async () => {
    const { S, host } = await setup(); S.fail = /credentials$/;
    type(inputs(host, 'password')[0], 'k-KEEP'); await click(host, 'Save credentials');
    assert.match(allText(host), /The server said no/); assert.strictEqual(inputs(host, 'password')[0].value, 'k-KEEP');
  });
  it('leaving the integration forgets anything typed', async () => {
    const { host } = await setup();
    type(inputs(host, 'password')[0], 'k-LEAVE'); await click(host, 'Back to the integrations'); await click(host, 'Open');
    assert.strictEqual(inputs(host, 'password')[0].value, '');
  });
  it('clearing every credential takes two presses', async () => {
    const { S, host } = await setup({}, [mk(1, { status: 'configured', credentials: [{ name: 'api_key', label: 'API key', required: true, set: true }, { name: 'api_secret', label: 'API secret', required: true, set: true }] })]);
    await click(host, 'Clear all credentials…'); assert.ok(!S.calls.some((c) => c.method === 'DELETE')); assert.match(allText(host), /Remove every credential\?/);
    await click(host, 'No'); assert.ok(!S.calls.some((c) => c.method === 'DELETE'));
    await click(host, 'Clear all credentials…'); await click(host, 'Yes, clear them');
    assert.ok(S.calls.some((c) => c.method === 'DELETE' && /credentials$/.test(c.path))); assert.match(allText(host), /Not configured/);
  });
  it('cannot save while the deployment has no key', async () => {
    const S = server([mk(1)], { secretsOk: false }); const { host } = await open(S); await click(host, 'Open');
    assert.ok(buttons(host, 'Save credentials')[0].disabled); assert.match(allText(host), /Credentials cannot be saved/);
  });
});

describe('settings, switching off, deleting', () => {
  const setup = async (list = [mk(1, { status: 'configured' })]) => { const S = server(list); const o = await open(S); await click(o.host, 'Open'); return { S, ...o }; };
  it('sends only the setting that changed', async () => {
    const { S, host } = await setup();
    type(inputs(host, 'text')[0], 'https://new.example.com'); await click(host, 'Save settings');
    assert.deepStrictEqual(S.calls.find((c) => c.method === 'PUT').body, { config: { base_url: 'https://new.example.com' } });
  });
  it('says nothing changed instead of sending nothing', async () => {
    const { S, host } = await setup(); const n = S.calls.length; await click(host, 'Save settings');
    assert.match(allText(host), /Nothing has changed/); assert.ok(!S.calls.slice(n).some((c) => c.method === 'PUT'));
  });
  it('switching off needs one press and shows Disabled; switching back on restores it', async () => {
    const { S, host } = await setup();
    await click(host, 'Switch off'); assert.deepStrictEqual(S.calls.find((c) => c.method === 'PUT').body, { enabled: false }); assert.match(allText(host), /Disabled/);
    await click(host, 'Switch on'); assert.match(allText(host), /Configured/);
  });
  it('deleting takes two presses and returns to the list', async () => {
    const { S, host, ctx } = await setup();
    await click(host, 'Delete…'); assert.match(allText(host), /Delete "Edge 1" and its credentials\?/); assert.ok(!S.calls.some((c) => c.method === 'DELETE'));
    await click(host, 'Yes, delete'); assert.ok(S.calls.some((c) => c.method === 'DELETE' && c.path === '/v1/integrations/' + ID(1)));
    assert.match(allText(host), /There are no integrations yet/); assert.ok(ctx.toasts.some(([t]) => /deleted/.test(t)));
  });
  it('a product ASIX no longer describes can still be opened and deleted', async () => {
    const { host } = await setup([mk(1, { definition_id: 'gone', definition_name: 'gone', category: null, known_definition: false, credentials: [] })]);
    assert.match(allText(host), /no longer has a description/); assert.ok(buttons(host, 'Delete…').length);
  });
});

describe('the page file', () => {
  const src = fs.readFileSync(PAGE, 'utf8');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/\s\/\/\s.*$/gm, '');
  it('draws only through ctx.el and talks only through ctx.api', () => {
    for (const bad of [/\bdocument\b/, /\bwindow\b/, /\binnerHTML\b/, /\balert\(/, /\bconfirm\(/, /\bfetch\(/, /\blocalStorage\b/, /\bsessionStorage\b/, /\bXMLHttpRequest\b/, /\beval\(/, /\bconsole\./]) assert.ok(!bad.test(code), String(bad));
  });
  it('never draws a credential as text or as a value it received', () => {
    assert.ok(!/credential_enc/.test(code));
    assert.ok(/type: 'password'/.test(code));
  });
  it('is the page the manifest names', () => {
    const m = require('../src/modules/manifests/integrations');
    assert.deepStrictEqual(m.ui.entries.map((e) => e.page), ['integrations.js']); assert.ok(m.permissions.includes(m.ui.entries[0].permission));
    assert.ok(fs.existsSync(path.join(__dirname, '../src/portal/modules/integrations', m.ui.entries[0].page)));
  });
});
