'use strict';
// The License page, a native module page (src/portal/modules/licensing/license.js, docs/portal-shell.md). The page file is an ES module in a CommonJS project, so it is copied to a temporary
// .mjs file and imported. It draws only through ctx.el, so a fake el() and a fake host are enough: no browser, no network, no database.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = path.join(__dirname, '../src/portal/modules/licensing/license.js');
let tmp, page;
before(async () => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-lic-')); fs.copyFileSync(PAGE, path.join(tmp, 'license.mjs')); page = await import(pathToFileURL(path.join(tmp, 'license.mjs')).href); });
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

const clean = (k) => k.flat(Infinity).filter((x) => x !== '' && x != null);
const fakeEl = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: clean(kids), replaceChildren(...k) { this.kids = clean(k); } });
const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = clean(k); } });
const walk = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
const allText = (host) => host.kids.flatMap(walk).flatMap((x) => [x.textContent, x.value && x.readOnly ? x.value : null, ...(x.kids || []).filter((c) => typeof c === 'string')]).filter(Boolean).join('\n');
const buttons = (host, label) => host.kids.flatMap(walk).filter((n) => n.tag === 'button' && (label === undefined || n.textContent === label));
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const click = async (host, label, nth = 0) => { const b = buttons(host, label)[nth]; assert.ok(b, `no button "${label}" in: ${allText(host).slice(0, 300)}`); b.onclick(); await tick(); };

const IID = '11111111-2222-4333-8444-555555555555';
const LIC = { status: 'valid', customer: 'Acme', kind: 'residential', expires_at: '2027-11-01T00:00:00.000Z', days_left: 300, grace_days_left: null, expiring: false, features: ['search', 'alerts'], reason: null, mode: 'on', channel: 'dev', enforce: true, source: 'stored', installation_id: IID };
const FILES = [{ id: '00000000-0000-4000-8000-000000000001', label: 'Acme 2027', customer: 'Acme', kind: 'residential', expires_at: '2027-11-01T00:00:00Z', active: true }, { id: '00000000-0000-4000-8000-000000000002', label: 'Trial', customer: 'Acme', kind: 'enterprise', expires_at: '2026-12-01T00:00:00Z', active: false }];
const RES = (o = {}) => ({ success: true, license: { ...LIC, ...(o.license || {}) }, build: o.build || { channel: 'dev', version: null }, files: o.files || [], can_switch_enforcement: o.can !== undefined ? o.can : true });

async function open(res, { perms = ['license:read', 'license:write'], fail = {} } = {}) {
  const calls = [], toasts = [], host = fakeHost();
  const ctx = { el: fakeEl, can: (p) => perms.includes(p), toast: (t) => toasts.push(t), tenant: { id: 't' },
    api: async (p, o) => { const key = ((o && o.method) || 'GET') + ' ' + p.replace(/[0-9a-f]{8}-[0-9a-f-]{27}/, ':id'); calls.push({ key, body: o && o.body }); if (fail[key]) throw new Error(fail[key]); return key === 'GET /v1/license' ? res : { success: true }; } };
  await page.mount(host, ctx); await tick();
  return { host, calls, toasts };
}

describe('the notice in plain words', () => {
  const text = async (lic) => allText((await open(RES({ license: lic }))).host);
  it('says the right thing for every state, and nothing extra for a healthy license', async () => {
    assert.doesNotMatch(await text({}), /expires in|expired on|lapsed|No valid license|OFF/);
    assert.match(await text({ expiring: true, days_left: 9 }), /expires in 9 days/); assert.match(await text({ expiring: true, days_left: 1 }), /expires in 1 day \(/);
    assert.match(await text({ status: 'grace', grace_days_left: 12 }), /expired on .* Everything still works for 12 more days\. After that search, reports and alerts STOP/); assert.match(await text({ status: 'grace', grace_days_left: 1 }), /for 1 more day\./);
    assert.match(await text({ status: 'expired' }), /has lapsed: search, reports, detections and alerts are OFF and you are not being alerted to attacks.*Collection, retention and backup keep working and no data is removed/);
    assert.match(await text({ status: 'wrong_install' }), /different installation/); assert.match(await text({ status: 'clock_error' }), /clock is behind/); assert.match(await text({ status: 'none' }), /No valid license: licensed features are locked/);
    assert.match(await text({ status: 'off', mode: 'off', enforce: false }), /Licensing is OFF on this development build: every module is available/);
  });
});

describe('the License page', () => {
  it('shows the installation id (selectable text), the build, the active license with its features, and the stored licenses', async () => {
    const { host } = await open(RES({ files: FILES })); const t = allText(host);
    assert.ok(t.includes(IID)); assert.match(t, /development build \(dev\)/); assert.match(t, /Valid/); assert.match(t, /Customer: Acme/); assert.match(t, /search/); assert.match(t, /Acme 2027/); assert.match(t, /Active/); assert.match(t, /Available/);
    const id = host.kids.flatMap(walk).find((n) => n.tag === 'input' && n.readOnly); assert.strictEqual(id.value, IID); let selected = 0; id.onclick({ target: { select() { selected += 1; } } }); assert.strictEqual(selected, 1);
  });
  it('Activate, Deactivate and Remove each ask first (Confirm or Cancel drawn in the page); Cancel does nothing; Confirm calls the server and redraws', async () => {
    const o = await open(RES({ files: FILES })); const { host, calls } = o;
    assert.strictEqual(buttons(host, 'Activate').length, 1); assert.strictEqual(buttons(host, 'Remove').length, 1); assert.strictEqual(buttons(host, 'Deactivate').length, 1);
    await click(host, 'Activate'); assert.match(allText(host), /Make this license the active one\?/); await click(host, 'Cancel'); assert.ok(!calls.some((c) => c.key.startsWith('POST')));
    await click(host, 'Activate'); await click(host, 'Confirm'); assert.ok(calls.some((c) => c.key === 'POST /v1/license/:id/activate' && JSON.stringify(c.body) === '{}')); assert.strictEqual(calls.filter((c) => c.key === 'GET /v1/license').length, 2);
    await click(host, 'Remove'); await click(host, 'Confirm'); assert.ok(calls.some((c) => c.key === 'DELETE /v1/license/:id'));
    await click(host, 'Deactivate'); assert.match(allText(host), /Licensed features lock/); await click(host, 'Confirm'); assert.ok(calls.some((c) => c.key === 'POST /v1/license/deactivate'));
  });
  it('a refusal from the server is shown as text', async () => {
    const o = await open(RES({ files: FILES }), { fail: { 'POST /v1/license/:id/activate': 'It was made for a different installation.' } }); await click(o.host, 'Activate'); await click(o.host, 'Confirm'); assert.match(allText(o.host), /different installation/);
  });
  it('Store license needs text, sends the pasted license and label, tells the person it is not active yet, and empties the boxes', async () => {
    const o = await open(RES()); const { host, calls, toasts } = o; const ta = host.kids.flatMap(walk).find((n) => n.tag === 'textarea'); const lab = host.kids.flatMap(walk).find((n) => n.tag === 'input' && /Label/.test(n.placeholder || ''));
    await click(host, 'Store license'); assert.ok(!calls.some((c) => c.key === 'POST /v1/license')); assert.match(allText(host), /Paste a license or choose a file first/);
    ta.oninput({ target: { value: ' aaa.bbb.ccc \n' } }); lab.oninput({ target: { value: 'Acme 2027' } }); await click(host, 'Store license');
    assert.deepStrictEqual(calls.find((c) => c.key === 'POST /v1/license').body, { license: ' aaa.bbb.ccc \n', label: 'Acme 2027' }); assert.deepStrictEqual(toasts, ['Stored. It is not active until you activate it.']);
    assert.strictEqual(host.kids.flatMap(walk).find((n) => n.tag === 'textarea').value, ''); assert.match(buttons(host, 'Store license')[0].title, /not activated until you activate/);
  });
  it('a file chosen is read as text into the box; a file that is too large is refused', async () => {
    const o = await open(RES()); const { host } = o; const file = host.kids.flatMap(walk).find((n) => n.tag === 'input' && n.type === 'file');
    await file.onchange({ target: { files: [{ size: 200, text: async () => ' x.y.z\n' }] } }); await tick(); assert.strictEqual(host.kids.flatMap(walk).find((n) => n.tag === 'textarea').value, 'x.y.z');
    await file.onchange({ target: { files: [{ size: 99999, text: async () => 'no' }] } }); await tick(); assert.match(allText(host), /too large to be a license/);
  });
  it('a server refusal when storing is shown and the text is kept for another try', async () => {
    const o = await open(RES(), { fail: { 'POST /v1/license': 'It is not a valid license (the license signature or claims are not valid).' } }); const ta = o.host.kids.flatMap(walk).find((n) => n.tag === 'textarea');
    ta.oninput({ target: { value: 'a.b.c' } }); await click(o.host, 'Store license'); assert.match(allText(o.host), /not a valid license/); assert.strictEqual(o.host.kids.flatMap(walk).find((n) => n.tag === 'textarea').value, 'a.b.c');
  });
  it('a role that can only read sees the licenses but no buttons and no add box', async () => {
    const { host } = await open(RES({ files: FILES }), { perms: ['license:read'] }); assert.strictEqual(buttons(host).length, 0); assert.match(allText(host), /can look at licenses but not store or activate them/); assert.match(allText(host), /Acme 2027/);
  });
});

describe('the on/off switch of licensing', () => {
  it('a development build shows the switch with its explanation; it asks first and sends the opposite value', async () => {
    let o = await open(RES({ license: { enforce: false, mode: 'off', status: 'off' } })); assert.match(allText(o.host), /the rest of the platform behaves as if licensing did not exist/);
    await click(o.host, 'Switch licensing on'); assert.match(allText(o.host), /Switch licensing on\? Features the active license does not include lock now/); await click(o.host, 'Confirm'); assert.deepStrictEqual(o.calls.find((c) => c.key === 'PUT /v1/license/enforcement').body, { enforce: true });
    o = await open(RES({ license: { enforce: true } })); await click(o.host, 'Switch licensing off'); await click(o.host, 'Cancel'); assert.ok(!o.calls.some((c) => c.key.startsWith('PUT')));
    await click(o.host, 'Switch licensing off'); await click(o.host, 'Confirm'); assert.deepStrictEqual(o.calls.find((c) => c.key === 'PUT /v1/license/enforcement').body, { enforce: false });
  });
  it('a release build has no switch and says licensing is always on', async () => {
    const { host } = await open(RES({ can: false, build: { channel: 'release', version: '26.4.0' }, license: { channel: 'release' } })); assert.match(allText(host), /release build: licensing is always on/); assert.ok(!buttons(host, 'Switch licensing on').length && !buttons(host, 'Switch licensing off').length); assert.match(allText(host), /26\.4\.0/);
  });
});

describe('what a module page must not do', () => {
  it('uses no browser dialogs or globals, and never sets HTML', () => {
    const src = fs.readFileSync(PAGE, 'utf8').replace(/\/\/.*$/gm, ''); for (const bad of ['document', 'window', 'alert(', 'confirm(', 'innerHTML', 'insertAdjacentHTML', 'outerHTML', 'localStorage', 'FileReader', 'navigator', 'eval(', 'Function(']) assert.ok(!src.includes(bad), bad);
  });
  it('shows text from the server as text: a label that looks like markup is not drawn as an element', async () => {
    const { host } = await open(RES({ files: [{ id: '00000000-0000-4000-8000-000000000003', label: '<img src=x onerror=alert(1)>', customer: '<b>x</b>', active: false }] })); assert.ok(allText(host).includes('<img src=x')); assert.ok(!host.kids.flatMap(walk).some((n) => n.tag === 'img' || n.tag === 'b' && !n.textContent));
  });
  it('is declared by the licensing manifest as a native page in Settings, General, and the file exists', () => {
    const m = require('../src/modules/registry').loadDir().find((x) => x.id === 'licensing'); assert.ok(m); assert.strictEqual(m.ui.kind, 'native'); const e = m.ui.entries[0]; assert.strictEqual(e.area, 'Settings'); assert.strictEqual(e.group, 'General'); assert.strictEqual(e.permission, 'license:read'); assert.strictEqual(e.page, 'license.js');
    assert.strictEqual(m.entitlement, null); assert.strictEqual(m.tier, 'home'); assert.deepStrictEqual(m.requires, []);
  });
});
