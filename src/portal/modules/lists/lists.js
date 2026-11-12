// Lists: block, allow and watch lists of addresses, domain names, URLs and file hashes, and the address a firewall polls (docs/lists.md, task L1).
// A page the module brings itself (docs/portal-shell.md). Rules of a module page: draw only through ctx.el and the host it is given, talk to the server only
// through ctx.api, and never use document, window, alert, confirm or innerHTML. Everything shown from the server is set as text. Text a person has typed is kept
// when the page redraws. Taking a list or an entry away, and replacing the address, take two presses.

let alive = false;

export async function mount(host, ctx) {
  alive = true;
  const E = ctx.el;
  const canWrite = ctx.can('soar:lists:write');
  const S = { lists: [], choices: { kinds: [], item_types: [], expires: [] }, view: 'index', open: null, detail: null, q: '', offset: 0, adding: false, creating: false,
    newForm: { name: '', kind: 'block', item_type: 'ip', description: '', allow_private: false }, addForm: { text: '', note: '', expires: 'never' },
    result: null, feedShown: null, confirm: null, busy: false, msg: null };
  const PAGE = 50;
  const KIND = { block: 'Block', allow: 'Allow', watch: 'Watch' };
  const KIND_HELP = { block: 'a firewall should drop these', allow: 'never block these', watch: 'only look out for these' };
  const TYPE = { ip: 'IP addresses and networks', domain: 'Domain names', url: 'URLs', hash: 'File hashes' };
  const EXPIRES_TEXT = { never: 'Never', '1h': '1 hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days', '90d': '90 days' };

  const T = (tag, className, text, extra) => E(tag, { className, textContent: text, ...(extra || {}) });
  const btn = (label, onclick, pri, off) => E('button', { className: 'btn' + (pri ? ' pri' : ''), textContent: label, onclick, disabled: !!off, style: 'margin-right:6px' });
  const pill = (text, cls) => E('span', { className: 'pill ' + cls, textContent: text, style: 'margin-right:6px' });
  const when = (v) => (v ? String(v).replace('T', ' ').slice(0, 16) : '');
  const draw = () => { if (alive) host.replaceChildren(...(S.view === 'detail' ? detailPage() : indexPage())); };
  const message = () => (S.msg ? E('div', { className: 'card' }, T('div', 'err', S.msg)) : '');
  const kindPill = (l) => pill(KIND[l.kind] || l.kind, l.kind === 'block' ? 'bad' : l.kind === 'allow' ? 'ok' : 'off');
  const field = (label, control) => E('div', { style: 'margin:6px 0' }, T('div', 'mute', label), control);

  const loadLists = async () => { const r = await ctx.api('/v1/lists'); S.lists = r.lists; S.choices = { kinds: r.kinds, item_types: r.item_types, expires: r.expires }; };
  const loadEntries = async () => {
    const r = await ctx.api('/v1/lists/' + S.open + '/entries?limit=' + PAGE + '&offset=' + S.offset + (S.q ? '&q=' + encodeURIComponent(S.q) : ''));
    S.detail = { list: r.list, entries: r.entries, total: r.total };
  };
  await loadLists();   // a failure here is the shell's error card, with Retry

  // Runs a change, then shows what the server answered. A failed change keeps what was typed.
  const run = async (fn, done) => {
    S.busy = true; S.msg = null; draw();
    try { await fn(); if (done) ctx.toast(done); } catch (e) { S.msg = e.message; }
    S.busy = false; draw();
  };
  const refresh = async () => { await loadLists(); if (S.view === 'detail') await loadEntries(); };
  const openList = async (id) => {
    S.open = id; S.q = ''; S.offset = 0; S.view = 'detail'; S.adding = false; S.result = null; S.feedShown = null; S.confirm = null; S.msg = null; S.detail = null;
    try { await loadEntries(); } catch (e) { S.msg = e.message; }
    draw();
  };
  const back = async () => { S.view = 'index'; S.open = null; S.detail = null; S.msg = null; S.confirm = null; try { await loadLists(); } catch (e) { S.msg = e.message; } draw(); };

  // ---- the lists -----------------------------------------------------------------------------------------------------------------------
  function indexPage() {
    return [
      T('h2', '', 'Lists'),
      T('div', 'mute', 'A list holds addresses, domain names, URLs or file hashes for one purpose: block (a firewall should drop them), allow (never block them) or watch (only look out for them). A list can be published at a secret address that a firewall polls.'),
      message(),
      canWrite ? E('div', { style: 'margin:10px 0' }, btn(S.creating ? 'Cancel' : 'New list', () => { S.creating = !S.creating; S.msg = null; draw(); }, !S.creating, S.busy)) : '',
      S.creating ? newForm() : '',
      ...(S.lists.length ? S.lists.map(listCard) : [T('div', 'mute', 'There are no lists yet.')]),
    ];
  }
  function newForm() {
    const f = S.newForm;
    const create = () => run(async () => {
      const body = { name: f.name, kind: f.kind, item_type: f.item_type, description: f.description };
      if (f.kind === 'block' && f.item_type === 'ip' && f.allow_private) body.allow_private = true;
      const r = await ctx.api('/v1/lists', { method: 'POST', body });
      S.creating = false; S.newForm = { name: '', kind: 'block', item_type: 'ip', description: '', allow_private: false };
      await loadLists(); ctx.toast('List created'); await openList(r.list.id);
    });
    return E('div', { className: 'card' }, T('b', '', 'New list'),
      field('Name', E('input', { type: 'text', style: 'width:60%', value: f.name, oninput: (ev) => { f.name = ev.target.value; } })),
      field('Purpose', E('select', { onchange: (ev) => { f.kind = ev.target.value; draw(); } }, ...S.choices.kinds.map((k) => E('option', { value: k, textContent: KIND[k] + ': ' + KIND_HELP[k], selected: f.kind === k })))),
      field('What it holds (cannot be changed later)', E('select', { onchange: (ev) => { f.item_type = ev.target.value; draw(); } }, ...S.choices.item_types.map((k) => E('option', { value: k, textContent: TYPE[k], selected: f.item_type === k })))),
      field('Description (optional)', E('input', { type: 'text', style: 'width:80%', value: f.description, oninput: (ev) => { f.description = ev.target.value; } })),
      f.kind === 'block' && f.item_type === 'ip'
        ? E('div', { style: 'margin:6px 0' }, E('label', {}, E('input', { type: 'checkbox', style: 'width:auto;margin-right:8px;vertical-align:middle', checked: !!f.allow_private, onchange: (ev) => { f.allow_private = ev.target.checked; } }), ' Allow private addresses (10.x, 172.16-31.x, 192.168.x and the like). Off by default: blocking one can cut off your own network.'))
        : '',
      E('div', {}, btn('Create', create, true, S.busy), btn('Cancel', () => { S.creating = false; draw(); })));
  }
  function listCard(l) {
    return E('div', { className: 'card' },
      E('div', {}, T('b', '', l.name), ' ', kindPill(l), pill(TYPE[l.item_type] || l.item_type, 'off'), pill(l.feed_enabled ? 'Published' : 'Not published', l.feed_enabled ? 'ok' : 'off'),
        T('span', 'mute', `${l.entry_count} ${l.entry_count === 1 ? 'entry' : 'entries'}`)),
      l.description ? T('div', 'mute', l.description) : '',
      l.feed_enabled ? T('div', 'mute', l.feed_last_fetch_at ? `Last fetched ${when(l.feed_last_fetch_at)}${l.feed_last_fetch_ip ? ' from ' + l.feed_last_fetch_ip : ''}.` : 'Not fetched yet.') : '',
      E('div', { style: 'margin-top:8px' }, btn('Open', () => openList(l.id))));
  }

  // ---- one list ------------------------------------------------------------------------------------------------------------------------
  function detailPage() {
    const d = S.detail;
    const head = [E('div', { style: 'margin:0 0 12px' }, btn('Back to the lists', back)), message()];
    if (!d) return [...head, T('div', 'mute', 'Loading…')];
    const l = d.list;
    return [
      ...head,
      T('h2', '', l.name),
      E('div', {}, kindPill(l), pill(TYPE[l.item_type] || l.item_type, 'off'), l.allow_private ? pill('Private addresses allowed', 'off') : '', T('span', 'mute', `${l.entry_count} ${l.entry_count === 1 ? 'entry' : 'entries'}`)),
      l.description ? T('div', 'mute', l.description) : '',
      feedCard(l),
      canWrite ? addCard(l) : '',
      entriesCard(l, d),
      canWrite ? dangerCard(l) : '',
    ];
  }

  function feedCard(l) {
    const make = () => run(async () => {
      const r = await ctx.api('/v1/lists/' + l.id + '/feed', { method: 'POST', body: {} });
      S.feedShown = { url: r.feed_url, path: r.feed_path }; S.confirm = null; await refresh();
    }, 'Address made');
    const stop = () => run(async () => { await ctx.api('/v1/lists/' + l.id + '/feed', { method: 'DELETE' }); S.feedShown = null; S.confirm = null; await refresh(); }, 'Address turned off');
    const c = S.confirm;
    return E('div', { className: 'card' }, T('b', '', 'Address for a firewall'),
      T('div', 'mute', 'A plain text page, one value per line, that a firewall can poll. Whoever has the address can read the list, so treat it like a password. Entries that have expired are left out.'),
      l.feed_enabled
        ? T('div', 'mute', `On (ends in …${l.feed_token_hint || ''}), made ${when(l.feed_created_at)}. ` + (l.feed_last_fetch_at ? `Last fetched ${when(l.feed_last_fetch_at)}${l.feed_last_fetch_ip ? ' from ' + l.feed_last_fetch_ip : ''}.` : 'Not fetched yet.'))
        : T('div', 'mute', 'Off: nothing is published.'),
      S.feedShown ? E('div', { style: 'margin:8px 0' }, T('div', 'err', 'Copy this address now. It is not shown again.'),
        E('input', { type: 'text', readOnly: true, style: 'width:100%', value: S.feedShown.url || S.feedShown.path }),
        S.feedShown.url ? '' : T('div', 'mute', 'Put the address of ASIX in front of this path (the address your firewall reaches ASIX by).')) : '',
      canWrite ? E('div', { style: 'margin-top:8px' },
        !l.feed_enabled ? btn('Make the address', make, true, S.busy)
          : c && c.kind === 'rotate' ? E('span', {}, T('span', 'err', 'The old address stops working at once. '), btn('Yes, make a new one', make, true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
            : btn('Make a new address', () => { S.confirm = { kind: 'rotate' }; draw(); }, false, S.busy),
        l.feed_enabled ? (c && c.kind === 'revoke' ? E('span', {}, T('span', 'err', 'The firewall will stop getting this list. '), btn('Yes, turn it off', stop, true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
          : btn('Turn the address off', () => { S.confirm = { kind: 'revoke' }; draw(); }, false, S.busy)) : '') : '');
  }

  function addCard(l) {
    const f = S.addForm;
    const send = () => { if (!f.text.trim()) { S.msg = 'Type or paste at least one value first.'; draw(); return; } return go(); };
    const go = () => run(async () => {
      const body = { text: f.text, expires: f.expires }; if (f.note.trim()) body.note = f.note.trim();
      const r = await ctx.api('/v1/lists/' + l.id + '/entries', { method: 'POST', body });
      S.result = { added: r.added.length, existing: r.existing.length, refused: r.refused };
      if (!r.refused.length) f.text = '';   // everything went in: clear the box; with refusals the text stays so it can be fixed
      await refresh();
    });
    const hint = l.item_type === 'ip' ? 'one address or network per line, such as 203.0.113.7 or 198.51.100.0/24' : l.item_type === 'domain' ? 'one domain name per line, such as example.com' : l.item_type === 'url' ? 'one URL per line, starting with http:// or https://' : 'one MD5, SHA-1 or SHA-256 hash per line';
    const res = S.result;
    return E('div', { className: 'card' }, T('b', '', 'Add entries'),
      field('Values: ' + hint + '. Lines starting with # are ignored.', E('textarea', { rows: 4, style: 'width:100%', value: f.text, oninput: (ev) => { f.text = ev.target.value; } })),
      field('Note (optional)', E('input', { type: 'text', style: 'width:60%', value: f.note, oninput: (ev) => { f.note = ev.target.value; } })),
      field('Stays for', E('select', { onchange: (ev) => { f.expires = ev.target.value; } }, ...S.choices.expires.map((k) => E('option', { value: k, textContent: EXPIRES_TEXT[k] || k, selected: f.expires === k })))),
      E('div', {}, btn('Add', send, true, S.busy)),
      l.kind === 'block' ? T('div', 'mute', 'A block list refuses networks that are too wide, private addresses (unless the list allows them) and anything an allow list covers.') : '',
      res ? E('div', { style: 'margin-top:8px' },
        T('div', res.refused.length ? 'err' : 'mute', `Added ${res.added}. Already on the list: ${res.existing}. Refused: ${res.refused.length}.`),
        ...res.refused.slice(0, 20).map((x) => T('div', 'err', x.value + ': ' + x.message)),
        res.refused.length > 20 ? T('div', 'mute', `…and ${res.refused.length - 20} more.`) : '') : '');
  }

  function entriesCard(l, d) {
    const search = () => run(async () => { S.offset = 0; await loadEntries(); });
    const page = (n) => run(async () => { S.offset = Math.max(0, n); await loadEntries(); });
    const c = S.confirm;
    const rm = (e) => run(async () => { await ctx.api('/v1/lists/' + l.id + '/entries/remove', { method: 'POST', body: { values: [e.value] } }); S.confirm = null; await refresh(); }, 'Entry removed');
    return E('div', { className: 'card' }, T('b', '', 'Entries'),
      E('div', { style: 'margin:6px 0' }, E('input', { type: 'text', style: 'width:40%', placeholder: 'Search', value: S.q, oninput: (ev) => { S.q = ev.target.value; } }), ' ', btn('Search', search, false, S.busy)),
      ...(d.entries.length ? d.entries.map((e) => E('div', { style: 'padding:4px 0;border-top:1px solid var(--line)' },
        T('b', '', e.value), ' ', e.source === 'action' ? pill('by an action', 'off') : '',
        T('span', 'mute', `added ${when(e.added_at)} by ${e.added_by_name}; ${e.expires_at ? 'expires ' + when(e.expires_at) : 'does not expire'}`),
        e.note ? T('div', 'mute', e.note) : '',
        canWrite ? (c && c.kind === 'entry' && c.value === e.value ? E('span', {}, T('span', 'err', 'Take it off the list? '), btn('Yes, remove', () => rm(e), true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
          : btn('Remove', () => { S.confirm = { kind: 'entry', value: e.value }; draw(); }, false, S.busy)) : '')) : [T('div', 'mute', S.q ? 'No entry matches.' : 'This list is empty.')]),
      d.total > PAGE ? E('div', { style: 'margin-top:8px' }, T('span', 'mute', `Showing ${S.offset + 1} to ${Math.min(S.offset + PAGE, d.total)} of ${d.total}. `),
        btn('Previous', () => page(S.offset - PAGE), false, S.busy || S.offset === 0), btn('Next', () => page(S.offset + PAGE), false, S.busy || S.offset + PAGE >= d.total)) : '');
  }

  function dangerCard(l) {
    const c = S.confirm;
    const del = () => run(async () => { await ctx.api('/v1/lists/' + l.id, { method: 'DELETE' }); ctx.toast('List deleted'); S.view = 'index'; S.open = null; S.detail = null; S.confirm = null; await loadLists(); });
    return E('div', { className: 'card' }, T('b', '', 'Delete this list'),
      T('div', 'mute', 'Deleting removes every entry and turns the firewall address off. It cannot be undone.'),
      c && c.kind === 'delete' ? E('div', { style: 'margin-top:8px' }, T('span', 'err', `Delete "${l.name}" and its ${l.entry_count} entries? `), btn('Yes, delete', del, true, S.busy), btn('No', () => { S.confirm = null; draw(); }))
        : E('div', { style: 'margin-top:8px' }, btn('Delete the list…', () => { S.confirm = { kind: 'delete' }; draw(); }, false, S.busy)));
  }

  draw();
}

export function unmount() { alive = false; }
