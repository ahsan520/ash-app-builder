// Integrations: a tenant's accounts for other products (firewalls, threat feeds, enrichment) (docs/integrations.md, task SR1).
// A page the module brings itself (docs/portal-shell.md). Rules of a module page: draw only through ctx.el, talk to the server only through ctx.api, never use
// document, window, alert, confirm or innerHTML; everything from the server is set as text.
// Credentials are write-only: an input for one is always empty (type password), what is typed is sent once and dropped, and the page only ever shows whether a
// credential is set. Taking an integration away or clearing its credentials takes two presses.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('soar:integrations:write');
  const S = { defs: [], list: [], secretsOk: true, view: 'index', open: null, creating: false, newForm: { definition_id: '', name: '', config: {} },
    cfg: {}, cred: {}, confirm: null, busy: false, msg: null };
  const STATUS = { not_configured: ['Not configured', 'off'], configured: ['Configured', 'ok'], disabled: ['Disabled', 'bad'] };
  const CATEGORY = { firewall: 'Firewalls', 'threat-intel': 'Threat intelligence', enrichment: 'Enrichment', ticketing: 'Ticketing', messaging: 'Messaging', identity: 'Identity', endpoint: 'Endpoints', other: 'Other' };

  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const btn = (label, onclick, pri, off) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, style: 'margin-right:6px' });
  const pill = (text, cls) => E('span', { className: 'pill ' + cls, textContent: text, style: 'margin-right:6px' });
  const field = (label, control) => E('div', { style: 'margin:6px 0' }, T('div', 'mute', label), control);
  const when = (v) => (v ? String(v).replace('T', ' ').slice(0, 16) : '');
  const defOf = (id) => S.defs.find((d) => d.id === id) || null;
  const draw = () => { if (alive) host.replaceChildren(...(S.view === 'detail' ? detailPage() : indexPage())); };
  const message = () => (S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg)) : '');
  const statusPill = (i) => { const [t, c] = STATUS[i.status] || [i.status, 'off']; return pill(t, c); };
  const current = () => S.list.find((i) => i.id === S.open) || null;

  const load = async () => {
    const [d, l] = await Promise.all([ctx.api('/v1/integrations/definitions'), ctx.api('/v1/integrations')]);
    S.defs = d.definitions; S.list = l.integrations; S.secretsOk = l.secrets_configured;
  };
  await load();   // a failure here is the shell's error card, with Retry

  const run = async (fn, done) => {
    S.busy = true; S.msg = null; draw();
    try { await fn(); if (done) ctx.toast(done); } catch (e) { S.msg = e.message; }
    S.busy = false; draw();
  };
  const openIt = (i) => { S.open = i.id; S.view = 'detail'; S.cfg = { ...i.config }; S.cred = {}; S.confirm = null; S.msg = null; draw(); };
  const back = async () => { S.view = 'index'; S.open = null; S.cred = {}; S.confirm = null; S.msg = null; try { await load(); } catch (e) { S.msg = e.message; } draw(); };

  // A setting is drawn from its field: text, address, choice or yes/no. `store` is the object the typed value goes into.
  function control(f, store) {
    if (f.type === 'boolean') return E('input', { type: 'checkbox', style: 'width:auto', checked: !!store[f.name], onchange: (ev) => { store[f.name] = ev.target.checked; } });
    if (f.type === 'enum') {
      return E('select', { onchange: (ev) => { store[f.name] = ev.target.value; } }, E('option', { value: '', textContent: 'Choose…', selected: !store[f.name] }),
        ...f.values.map((v) => E('option', { value: v, textContent: v, selected: store[f.name] === v })));
    }
    return E('input', { type: 'text', style: 'width:70%', value: store[f.name] || '', oninput: (ev) => { store[f.name] = ev.target.value; } });
  }
  const label = (f) => f.label + (f.required ? ' (required)' : '');

  // ---- the integrations ----------------------------------------------------------------------------------------------------------------
  function indexPage() {
    const cats = [...new Set(S.list.map((i) => i.category || 'other'))].sort();
    return [
      T('h2', '', 'Integrations'),
      T('div', 'mute', 'An integration is your account for another product: a firewall, a threat feed, a lookup service. Its settings are shown here; its credentials (keys and tokens) go in and never come out. An integration is Not configured until its credentials are set.'),
      !S.secretsOk ? E('div', { className: 'card' }, T('div', 'err', 'The key that protects stored secrets is not configured on this deployment, so credentials cannot be saved yet.')) : '',
      message(),
      canWrite ? E('div', { style: 'margin:10px 0' }, btn(S.creating ? 'Cancel' : 'Add an integration', () => { S.creating = !S.creating; S.msg = null; draw(); }, !S.creating, S.busy)) : '',
      S.creating ? newForm() : '',
      ...(S.list.length ? cats.flatMap((c) => [T('h3', '', CATEGORY[c] || c), ...S.list.filter((i) => (i.category || 'other') === c).map(card)]) : [T('div', 'mute', 'There are no integrations yet.')]),
    ];
  }
  function newForm() {
    const f = S.newForm; const def = defOf(f.definition_id);
    const create = () => run(async () => {
      const config = {};
      for (const c of def.config) { const v = f.config[c.name]; if (c.type === 'boolean') { if (v) config[c.name] = true; } else if (typeof v === 'string' && v.trim()) config[c.name] = v.trim(); }
      const r = await ctx.api('/v1/integrations', { method: 'POST', body: { definition_id: def.id, name: f.name, config } });
      S.creating = false; S.newForm = { definition_id: '', name: '', config: {} };
      await load(); ctx.toast('Integration added'); openIt(r.integration);
    });
    return E('div', { className: 'card' }, T('b', '', 'Add an integration'),
      field('Product', E('select', { onchange: (ev) => { f.definition_id = ev.target.value; f.config = {}; draw(); } }, E('option', { value: '', textContent: 'Choose…', selected: !def }),
        ...S.defs.map((d) => E('option', { value: d.id, textContent: (CATEGORY[d.category] || d.category) + ': ' + d.name, selected: f.definition_id === d.id })))),
      def ? T('div', 'mute', def.description) : '',
      field('Name (how you will recognise it)', E('input', { type: 'text', style: 'width:60%', value: f.name, oninput: (ev) => { f.name = ev.target.value; } })),
      ...(def ? def.config.map((c) => field(label(c), control(c, f.config))) : []),
      def ? T('div', 'mute', 'You add the credentials on the next page.') : '',
      E('div', {}, btn('Add', create, true, S.busy || !def), btn('Cancel', () => { S.creating = false; draw(); })));
  }
  function card(i) {
    const cfg = Object.entries(i.config).map(([k, v]) => `${k}: ${v}`).join(' · ');
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', i.name), ' ', statusPill(i), T('span', 'mute', i.definition_name)),
      cfg ? T('div', 'mute', cfg) : '',
      E('div', { style: 'margin-top:8px' }, btn('Open', () => openIt(i))));
  }

  // ---- one integration -----------------------------------------------------------------------------------------------------------------
  function detailPage() {
    const i = current();
    const head = [E('div', { style: 'margin:0 0 12px' }, btn('Back to the integrations', back)), message()];
    if (!i) return [...head, T('div', 'mute', 'This integration no longer exists.')];
    const def = defOf(i.definition_id);
    return [...head, T('h2', '', i.name), E('div', {}, statusPill(i), T('span', 'mute', i.definition_name)), def ? T('div', 'mute', def.description) : T('div', 'err', 'ASIX no longer has a description of this product.'),
      i.status === 'not_configured' ? T('div', 'mute', 'Not configured: set every credential marked required.') : '',
      def ? settingsCard(i, def) : '', def ? credentialsCard(i) : '', canWrite ? stateCard(i) : ''];
  }
  function settingsCard(i, def) {
    const save = () => run(async () => {
      const body = {};
      for (const c of def.config) {
        const was = i.config[c.name]; const now = S.cfg[c.name];
        if (c.type === 'boolean') { if (!!was !== !!now) body[c.name] = !!now; continue; }
        const text = typeof now === 'string' ? now.trim() : '';
        if (text !== (was || '')) body[c.name] = text === '' ? null : text;
      }
      if (!Object.keys(body).length) { S.msg = 'Nothing has changed.'; return; }
      await ctx.api('/v1/integrations/' + i.id, { method: 'PUT', body: { config: body } });
      await load(); S.cfg = { ...current().config };
    }, 'Saved');
    return E('div', { className: 'card' }, T('b', '', 'Settings'),
      ...(def.config.length ? def.config.map((c) => field(label(c), canWrite ? control(c, S.cfg) : T('div', '', String(i.config[c.name] == null ? '' : i.config[c.name])))) : [T('div', 'mute', 'This product has no settings besides its credentials.')]),
      canWrite && def.config.length ? E('div', {}, btn('Save settings', save, true, S.busy)) : '');
  }
  function credentialsCard(i) {
    const save = () => run(async () => {
      const values = {};
      for (const [k, v] of Object.entries(S.cred)) if (typeof v === 'string' && v.trim()) values[k] = v;
      if (!Object.keys(values).length) { S.msg = 'Type at least one credential first.'; return; }
      await ctx.api('/v1/integrations/' + i.id + '/credentials', { method: 'PUT', body: { values } });
      S.cred = {};   // dropped at once: nothing typed stays in the page
      await load();
    }, 'Credentials saved');
    const clearAll = () => run(async () => { await ctx.api('/v1/integrations/' + i.id + '/credentials', { method: 'DELETE' }); S.cred = {}; S.confirm = null; await load(); }, 'Credentials cleared');
    const c = S.confirm;
    return E('div', { className: 'card' }, T('b', '', 'Credentials'),
      T('div', 'mute', 'Write-only. They are kept encrypted and are never shown again, not even to you. To change one, type the new value; the old one is replaced.'),
      ...i.credentials.map((f) => E('div', { style: 'margin:6px 0' }, T('b', '', f.label), ' ', pill(f.set ? 'Set' : 'Not set', f.set ? 'ok' : 'off'), f.required ? T('span', 'mute', 'required') : '',
        canWrite ? E('div', {}, E('input', { type: 'password', autocomplete: 'new-password', style: 'width:70%', placeholder: f.set ? 'Type to replace' : 'Type to set', value: S.cred[f.name] || '', oninput: (ev) => { S.cred[f.name] = ev.target.value; } })) : '')),
      i.credential_set_at ? T('div', 'mute', `Last changed ${when(i.credential_set_at)}${i.credential_set_by_name ? ' by ' + i.credential_set_by_name : ''}.`) : '',
      canWrite ? E('div', { style: 'margin-top:8px' }, btn('Save credentials', save, true, S.busy || !S.secretsOk),
        i.credentials.some((f) => f.set) ? (c && c.kind === 'clear' ? E('span', {}, T('span', 'err', 'Remove every credential? '), btn('Yes, clear them', clearAll, true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
          : btn('Clear all credentials…', () => { S.confirm = { kind: 'clear' }; draw(); }, false, S.busy)) : '') : '',
      !S.secretsOk ? T('div', 'err', 'Credentials cannot be saved: the key that protects stored secrets is not configured.') : '');
  }
  function stateCard(i) {
    const toggle = () => run(async () => { await ctx.api('/v1/integrations/' + i.id, { method: 'PUT', body: { enabled: !i.enabled } }); await load(); }, i.enabled ? 'Switched off' : 'Switched on');
    const del = () => run(async () => { await ctx.api('/v1/integrations/' + i.id, { method: 'DELETE' }); ctx.toast('Integration deleted'); S.view = 'index'; S.open = null; S.cred = {}; S.confirm = null; await load(); });
    const c = S.confirm;
    return E('div', { className: 'card' }, T('b', '', 'Switch off or delete'),
      T('div', 'mute', 'Switching off keeps the settings and credentials but nothing will use them. Deleting removes both for good.'),
      E('div', { style: 'margin-top:8px' }, btn(i.enabled ? 'Switch off' : 'Switch on', toggle, false, S.busy),
        c && c.kind === 'delete' ? E('span', {}, T('span', 'err', `Delete "${i.name}" and its credentials? `), btn('Yes, delete', del, true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
          : btn('Delete…', () => { S.confirm = { kind: 'delete' }; draw(); }, false, S.busy)));
  }

  draw();
}

export function unmount() { alive = false; }
