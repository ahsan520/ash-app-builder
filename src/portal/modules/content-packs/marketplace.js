// Marketplace: browse, install and remove content packs. The first module page loaded by the portal shell (docs/portal-shell.md, task MK2).
// Rules of a module page: draw only through ctx.el and the host it is given, talk to the server only through ctx.api, and never use
// document, window, alert, confirm or innerHTML. Everything shown from the server is set as text. That keeps the page testable without a browser.
// Confirmations are drawn inside the page (two steps: a button, then Confirm or Cancel), not as browser dialogs.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('detections:rules:write');
  const S = { tab: 'browse', q: '', deprecated: false, packs: [], open: null, sub: 'details', busy: false, msg: null, confirm: null };

  const refresh = async () => { S.packs = (await ctx.api('/v1/packs')).packs; };
  await refresh();   // a failure here is the shell's error card, with Retry

  const draw = () => { if (alive) host.replaceChildren(...(S.open ? packPage() : listPage())); };
  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const btn = (label, onclick, pri, off) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, style: 'margin-right:6px' });
  const pill = (text, cls) => E('span', { className: 'pill ' + cls, textContent: text });
  const STATE = { available: ['Not installed', 'off'], partial: ['Partly installed', 'off'], installed: ['Installed', 'ok'] };
  const badges = (p) => E('span', {}, pill(...STATE[p.state]), p.certification === 'certified' ? pill('Certified', 'ok') : pill('Community', 'off'),
    p.deprecated ? pill('Deprecated', 'bad') : '', p.core ? pill('Core', 'off') : '');
  const byId = (id) => S.packs.find((x) => x.id === id);
  const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');

  // ---- doing things -----------------------------------------------------------------------------------------------
  const run = async (fn, done) => {
    S.busy = true; S.msg = null; S.confirm = null; draw();
    try { await fn(); await refresh(); if (done) ctx.toast(done); } catch (e) { S.msg = { text: e.message, status: e.status }; }
    S.busy = false; draw();
  };
  const install = (p, body, done) => run(async () => {
    try { await ctx.api('/v1/packs/' + p.id + '/install', { method: 'POST', body: body || {} }); } catch (e) {
      if (/\(PACK_DEPRECATED\)/.test(e.message)) { S.confirm = { type: 'deprecated', id: p.id, text: e.message }; return; }
      throw e;
    }
  }, 'Installed ' + p.name);
  const remove = (p, withAlerts) => run(async () => {
    try { await ctx.api('/v1/packs/' + p.id + (withAlerts ? '?delete_alerts=true' : ''), { method: 'DELETE' }); } catch (e) {
      if (!withAlerts && /\(HAS_ALERTS\)/.test(e.message)) { S.confirm = { type: 'alerts', id: p.id }; return; }
      throw e;
    }
  }, 'Removed ' + p.name);

  const confirmBox = (p) => {
    const c = S.confirm; if (!c || c.id !== p.id) return '';
    const [text, label, go] = {
      remove: [`Remove "${p.name}"? Its rules are deleted.`, 'Remove', () => remove(p, false)],
      restore: [`Put every rule from "${p.name}" back to the version shipped with ASIX? Your edits to these rules will be lost.`, 'Restore', () => install(p, { overwrite: true }, 'Restored ' + p.name)],
      alerts: ['Some of these rules have raised alerts. Removing the pack deletes those alerts too.', 'Remove and delete alerts', () => remove(p, true)],
      deprecated: [c.text + ' Install it anyway?', 'Install anyway', () => install(p, { allow_deprecated: true }, 'Installed ' + p.name)],
    }[c.type];
    return E('div', { className: 'card', style: 'margin:10px 0' }, T('div', '', text), E('div', { style: 'margin-top:8px' }, btn(label, go, true), btn('Cancel', () => { S.confirm = null; draw(); })));
  };
  const actions = (p) => {
    if (!canWrite) return T('div', 'mute', 'Your role can look at packs but not install or remove them.');
    const off = S.busy;
    return E('div', { style: 'margin:10px 0' },
      p.state === 'installed' ? '' : btn(p.state === 'partial' ? 'Add missing rules' : 'Install', () => install(p), true, off),
      p.state === 'available' ? '' : btn('Restore shipped rules', () => { S.confirm = { type: 'restore', id: p.id }; draw(); }, false, off),
      p.state === 'available' ? '' : btn('Remove', () => { S.confirm = { type: 'remove', id: p.id }; draw(); }, false, off));
  };
  const message = () => (S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg.text)) : '');

  // ---- list -------------------------------------------------------------------------------------------------------
  const matches = (p) => {
    const q = S.q.trim().toLowerCase();
    return !q || [p.name, p.description, p.publisher.name, ...p.tags].some((x) => String(x).toLowerCase().includes(q));
  };
  function listPage() {
    const installed = S.packs.filter((p) => p.state !== 'available');
    // Typing in the search box refills only this box: redrawing the whole page would replace the input and drop the cursor after every key.
    const listBox = E('div', {});
    const fill = () => {
      const shown = (S.tab === 'installed' ? installed : S.packs.filter((p) => S.deprecated || !p.deprecated)).filter(matches);
      listBox.replaceChildren(...(shown.length ? shown.map(card) : [T('div', 'mute', S.tab === 'installed' ? 'No packs installed yet.' : 'No packs match.')]));
    };
    fill();
    const tab = (id, label) => btn(label, () => { S.tab = id; S.msg = null; draw(); }, S.tab === id);
    return [
      T('h2', '', 'Marketplace'),
      T('div', 'mute', 'Ready-made detection content. Nothing is installed until you choose it. Installed rules appear in Threat Management, where you can edit, disable or tune them like any other rule.'),
      E('div', { style: 'margin:12px 0' }, tab('browse', 'Browse'), tab('installed', 'Installed (' + installed.length + ')')),
      E('div', { style: 'margin-bottom:12px' },
        E('input', { type: 'text', placeholder: 'Search packs', value: S.q, style: 'margin-right:10px', oninput: (ev) => { S.q = ev.target.value; if (alive) fill(); } }),
        S.tab === 'browse' ? E('label', { className: 'mute' }, E('input', { type: 'checkbox', checked: S.deprecated, onchange: (ev) => { S.deprecated = ev.target.checked; draw(); } }), ' Show deprecated packs') : ''),
      message(),
      listBox,
    ];
  }
  function card(p) {
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', p.name), T('span', 'mute', '  v' + p.version + '  '), badges(p)),
      T('div', '', p.description),
      T('div', 'mute', `${p.publisher.name} · ${plural(p.rule_count, 'rule')}${p.tags.length ? ' · ' + p.tags.join(', ') : ''}${p.state !== 'available' ? ` · ${p.installed_rules} of ${p.rule_count} installed` : ''}`),
      E('div', { style: 'margin-top:10px' },
        canWrite && p.state === 'available' && !p.deprecated ? btn('Install', () => install(p), true, S.busy) : '',
        btn('Details', () => { S.open = p.id; S.sub = 'details'; S.msg = null; S.confirm = null; draw(); })));
  }

  // ---- one pack ---------------------------------------------------------------------------------------------------
  function packPage() {
    const p = byId(S.open);
    if (!p) { S.open = null; return listPage(); }
    const sub = (id, label) => btn(label, () => { S.sub = id; draw(); }, S.sub === id);
    const kv = (k, v) => E('tr', {}, T('td', 'mute', k, { style: 'padding-right:18px' }), E('td', {}, v));
    const rows = {
      details: () => [
        p.deprecated ? E('div', { className: 'card' }, T('div', 'err', 'Deprecated: ' + p.deprecation), p.replaced_by && byId(p.replaced_by) ? T('div', '', 'Use "' + byId(p.replaced_by).name + '" instead.') : '') : '',
        T('p', '', p.description),
        E('table', {}, E('tbody', {},
          kv('Publisher', p.publisher.url ? E('a', { href: p.publisher.url, target: '_blank', rel: 'noopener', textContent: p.publisher.name }) : p.publisher.name),
          kv('Certification', p.certification === 'certified' ? 'Certified' : 'Community'),
          kv('Supported by', { asix: 'ASIX', community: 'The community', none: 'Nobody (as is)' }[p.supported_by]),
          kv('Released', p.released || 'Not recorded'), kv('License', p.license || 'Not stated'),
          kv('Expects', p.sources.length ? p.sources.join('; ') : 'Not stated'), kv('Tags', p.tags.length ? p.tags.join(', ') : 'None'))),
      ],
      content: () => [
        T('div', 'mute', 'This pack contains ' + Object.entries(p.contents).map(([k, n]) => plural(n, k.replace(/s$/, ''))).join(', ') + '.'),
        E('table', {}, E('thead', {}, E('tr', {}, T('th', '', 'Rule'), T('th', '', 'Severity'), T('th', '', 'MITRE'))),
          E('tbody', {}, ...p.rules.map((r) => E('tr', {}, E('td', {}, T('div', '', r.name), T('div', 'mute', r.description, { style: 'font-size:12px' })), T('td', '', r.severity), T('td', '', (r.mitre || []).join(', ')))))),
      ],
      dependencies: () => {
        const users = S.packs.filter((x) => x.requires.packs.includes(p.id));
        const none = !p.requires.modules.length && !p.requires.packs.length;
        return [
          T('h4', '', 'This pack needs'),
          none ? T('div', 'mute', 'Nothing else.') : '',
          ...p.requires.modules.map((m) => E('div', {}, 'Module: ' + m)),
          ...p.requires.packs.map((id) => E('div', {}, 'Pack: ' + (byId(id) ? byId(id).name : id) + '  ', byId(id) ? pill(...STATE[byId(id).state]) : pill('Not in this catalog', 'bad'))),
          T('h4', '', 'Needed by'),
          users.length ? E('div', {}, ...users.map((x) => E('div', {}, x.name + '  ', pill(...STATE[x.state])))) : T('div', 'mute', 'No other pack.'),
        ];
      },
      history: () => (p.history.length ? p.history.map((h) => E('div', { style: 'margin-bottom:8px' }, T('b', '', 'v' + h.version), T('span', 'mute', '  ' + (h.released || 'date not recorded')), T('div', '', h.notes)))
        : [T('div', 'mute', 'No history recorded. Current version: v' + p.version + '.')]),
    };
    return [
      btn('← Back', () => { S.open = null; S.msg = null; S.confirm = null; draw(); }),
      E('div', { style: 'margin:10px 0' }, T('h2', '', p.name, { style: 'display:inline' }), T('span', 'mute', '  v' + p.version + '  '), badges(p)),
      T('div', 'mute', plural(p.installed_rules, 'rule') + ' of ' + p.rule_count + ' installed' + (p.open_alerts ? ' · ' + plural(p.open_alerts, 'open alert') : '')),
      actions(p), confirmBox(p), message(),
      E('div', { style: 'margin:12px 0' }, sub('details', 'Details'), sub('content', 'Content (' + p.rule_count + ')'), sub('dependencies', 'Dependencies'), sub('history', 'Version history')),
      E('div', { className: 'card' }, ...rows[S.sub]()),
    ];
  }

  draw();
}

export function unmount() { alive = false; }
