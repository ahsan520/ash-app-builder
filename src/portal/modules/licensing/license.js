// License: the installation id, what the active license unlocks, the licenses stored on this installation, and the on/off switch of licensing on a development build (docs/licensing.md).
// A native module page (docs/portal-shell.md): draws only through ctx.el and the host it is given, talks to the server only through ctx.api, uses no browser dialogs (confirmation is drawn
// inside the page: a button, then Confirm or Cancel) and sets everything it shows as text. The shell shows an error card with Retry if loading fails.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('license:write');
  const S = { r: null, confirm: null, msg: null, busy: false, text: '', label: '' };
  const load = async () => { S.r = await ctx.api('/v1/license'); };
  await load();

  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const pill = (text, cls) => E('span', { className: 'pill ' + (cls || 'off'), textContent: text });
  const btn = (label, onclick, pri, off, title) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, title: title || '', style: 'margin-right:6px' });
  const when = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z?$/, '') : '-');
  const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
  const draw = () => { if (alive) host.replaceChildren(...page()); };

  // Do something that changes the server, then read the state again. A refusal is shown as text and nothing is redrawn from stale data.
  const run = async (fn, done) => {
    S.busy = true; S.msg = null; S.confirm = null; draw();
    try { await fn(); await load(); if (done) ctx.toast(done); } catch (e) { S.msg = { text: e.message }; }
    S.busy = false; draw();
  };

  // ---- what the state means, in plain words -----------------------------------------------------------------------
  const notice = (lic) => {
    const warn = (text) => E('div', { className: 'warn', style: 'margin-bottom:10px', textContent: text });
    if (lic.mode === 'off') return warn(lic.channel === 'dev'
      ? 'Licensing is OFF on this development build: every module is available, whatever a license says. Switch it on below to see what a customer sees.'
      : 'Licensing is off.');
    if (lic.status === 'valid') return lic.expiring ? warn('The license expires in ' + plural(lic.days_left, 'day') + ' (' + when(lic.expires_at) + '). Ask for a renewal. After a grace period, search, reports and alerts stop; collection keeps running and your data stays.') : '';
    if (lic.status === 'grace') return warn('The license expired on ' + when(lic.expires_at) + '. Everything still works for ' + plural(lic.grace_days_left, 'more day') + '. After that search, reports and alerts STOP and you will not be alerted to attacks; collection continues and no data is removed. Renew now.');
    if (lic.status === 'expired') return warn('The license has lapsed: search, reports, detections and alerts are OFF and you are not being alerted to attacks. Collection, retention and backup keep working and no data is removed. Store and activate a renewed license to switch everything back on at once.');
    if (lic.status === 'wrong_install') return warn('This license was made for a different installation, so it unlocks nothing here. Send the installation id to get one for this installation.');
    if (lic.status === 'clock_error') return warn('The server clock is behind the last time the platform ran, so the license is not used. Set the clock right.');
    return warn('No valid license: licensed features are locked. Collection and retention keep working. Send the installation id to get a license, then store and activate it here.');
  };
  const STATUS = { valid: ['Valid', 'ok'], grace: ['In grace', 'off'], expired: ['Lapsed', 'bad'], off: ['Licensing off', 'off'], none: ['No license', 'off'], wrong_install: ['Wrong installation', 'bad'], invalid: ['Not valid', 'bad'], clock_error: ['Clock error', 'bad'] };

  // ---- cards ---------------------------------------------------------------------------------------------------------
  const confirmBox = (id) => {
    const c = S.confirm; if (!c || c.id !== id) return '';
    const text = { activate: 'Make this license the active one?', deactivate: 'Deactivate the license? Licensed features lock (while licensing is on).', remove: 'Remove this stored license?',
      on: 'Switch licensing on? Features the active license does not include lock now.', offswitch: 'Switch licensing off? Every module becomes available again.' }[c.type];
    return E('div', { className: 'card', style: 'margin:8px 0' }, T('div', '', text), E('div', { style: 'margin-top:8px' }, btn('Confirm', c.go, true), btn('Cancel', () => { S.confirm = null; draw(); })));
  };
  const ask = (type, id, go) => () => { S.confirm = { type, id, go }; draw(); };

  const installCard = (r) => E('div', { className: 'card' }, T('h3', '', 'This installation'),
    T('div', 'mute', 'A license is made for this id. Send it to your supplier to get one.'),
    E('input', { readOnly: true, value: r.license.installation_id || 'not available yet', style: 'width:340px;font-family:monospace;margin-top:6px', onclick: (ev) => { if (ev && ev.target && ev.target.select) ev.target.select(); } }),
    T('div', 'mute', 'Version: ' + ((r.build && r.build.version) || 'development build') + ' (' + (r.build ? r.build.channel : '-') + ')', { style: 'margin-top:8px' }));

  const activeCard = (r) => {
    const lic = r.license, st = STATUS[lic.status] || [lic.status, 'off'];
    return E('div', { className: 'card' }, T('h3', '', 'Active license'), E('div', {}, pill(st[0], st[1])),
      T('div', '', 'Customer: ' + (lic.customer || '-')), T('div', '', 'Kind: ' + (lic.kind || '-')), T('div', '', 'Expires (UTC): ' + (lic.expires_at ? when(lic.expires_at) : '-')),
      T('div', '', 'Days left: ' + (lic.days_left === null || lic.days_left === undefined ? '-' : lic.days_left)),
      (lic.features || []).length ? E('div', { style: 'display:flex;gap:6px;flex-wrap:wrap;margin-top:8px' }, ...lic.features.map((f) => pill(f, 'ok'))) : T('div', 'mute', 'No licensed features.', { style: 'margin-top:8px' }));
  };

  const switchCard = (r) => {
    const on = r.license.enforce === true;
    if (!r.can_switch_enforcement) return E('div', { className: 'card' }, T('h3', '', 'Licensing'), pill('On', 'ok'), T('div', 'mute', 'This is a release build: licensing is always on.', { style: 'margin-top:8px' }));
    return E('div', { className: 'card' }, T('h3', '', 'Licensing'),
      T('div', 'mute', 'This is a development build. While licensing is off every module is available and nothing is checked; the rest of the platform behaves as if licensing did not exist. Switch it on to see exactly what a customer sees.'),
      E('div', { style: 'margin-top:8px' }, pill(on ? 'On' : 'Off', on ? 'ok' : 'off'),
        canWrite ? btn(on ? 'Switch licensing off' : 'Switch licensing on', ask(on ? 'offswitch' : 'on', 'switch', () => run(() => ctx.api('/v1/license/enforcement', { method: 'PUT', body: { enforce: !on } }))), false, S.busy) : ''),
      confirmBox('switch'));
  };

  const storedCard = (r) => {
    const rows = (r.files || []).map((f) => E('div', { style: 'padding:8px 0;border-top:1px solid var(--line, #ddd)' },
      E('div', {}, T('b', '', f.label || 'License'), ' ', f.active ? pill('Active', 'ok') : pill('Available', 'off')),
      T('div', 'mute', [f.customer, f.kind, 'expires ' + when(f.expires_at)].filter(Boolean).join(' - ')),
      canWrite ? E('div', { style: 'margin-top:6px' },
        f.active ? btn('Deactivate', ask('deactivate', f.id, () => run(() => ctx.api('/v1/license/deactivate', { method: 'POST', body: {} }))), false, S.busy)
          : E('span', {}, btn('Activate', ask('activate', f.id, () => run(() => ctx.api('/v1/license/' + encodeURIComponent(f.id) + '/activate', { method: 'POST', body: {} }))), true, S.busy),
            btn('Remove', ask('remove', f.id, () => run(() => ctx.api('/v1/license/' + encodeURIComponent(f.id), { method: 'DELETE' }))), false, S.busy))) : '',
      confirmBox(f.id)));
    return E('div', { className: 'card' }, T('h3', '', 'Stored licenses'), rows.length ? E('div', {}, ...rows) : T('div', 'mute', 'No license is stored yet.'));
  };

  const addCard = () => {
    if (!canWrite) return T('div', 'mute', 'Your role can look at licenses but not store or activate them.');
    const area = E('textarea', { placeholder: 'Paste the license here, or choose a file', rows: 4, value: S.text, style: 'width:100%;margin-top:8px;font-family:monospace', oninput: (ev) => { S.text = ev && ev.target ? ev.target.value : S.text; } });
    const label = E('input', { placeholder: 'Label, for example "Acme enterprise 2027"', value: S.label, style: 'width:320px', oninput: (ev) => { S.label = ev && ev.target ? ev.target.value : S.label; } });
    const file = E('input', { type: 'file', onchange: async (ev) => {
      const f = ev && ev.target && ev.target.files && ev.target.files[0]; if (!f) return;
      if (f.size > 16384) { S.msg = { text: 'That file is too large to be a license.' }; draw(); return; }
      S.text = String(await f.text()).trim(); draw();
    } });
    const store = btn('Store license', async () => {
      if (!S.text.trim()) { S.msg = { text: 'Paste a license or choose a file first.' }; draw(); return; }
      await run(async () => { await ctx.api('/v1/license', { method: 'POST', body: { license: S.text, label: S.label } }); S.text = ''; S.label = ''; }, 'Stored. It is not active until you activate it.');
    }, true, S.busy, 'Checks the license and keeps it; it is not activated until you activate it');
    return E('div', { className: 'card' }, T('h3', '', 'Add a license'), E('div', {}, label, ' ', file), area, E('div', { style: 'margin-top:8px' }, store));
  };

  function page() {
    const r = S.r;
    return [T('h2', '', 'License'), T('p', 'desc', 'The installation id, what the license unlocks, and the licenses stored on this installation. A license is made for this installation id; storing one does not switch it on.'),
      notice(r.license), S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg.text)) : '',
      E('div', { className: 'grid' }, installCard(r), activeCard(r), switchCard(r)), storedCard(r), addCard()];
  }
  draw();
}

export function unmount() { alive = false; }
