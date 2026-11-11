'use strict';
// Two actions on lists (task L1, docs/lists.md), added to the action registry (task SR2, docs/actions.md) when the Lists routes load: list.add_entry and
// list.remove_entry. They are what a playbook (SR3) and a person pressing Run use to put an address on a block list or take it off. Like every action they are
// off until an administrator enables them for the tenant, medium risk (a block list that a firewall polls is a block), reversible, and no higher than level 3:
// automation asking for one waits for approval. They call the same service as the Lists page, so every rule of lists applies: a block list refuses too-wide
// networks, private addresses and anything an allow list covers.
// Added entries expire after 30 days unless the request says otherwise: what automation blocks is meant to come off by itself.
const catalog = require('../actions/catalog');
const model = require('./model');
const service = require('./service');

const LIST_ID = { name: 'list_id', type: 'uuid', required: true, description: 'The list (its id, from the Lists page or the API).' };
const base = { publisher: 'ASIX', kind: 'builtin', source: 'ASIX built-in (src/lists/actions.js)', risk: 'medium', reversible: true, max_autonomy: 3, default_autonomy: 2 };
const MESSAGES = { NOT_FOUND: 'List not found', LIST_FULL: 'The list is full', ALLOW_SET_TOO_LARGE: 'The allow lists are too large to check against' };
const refusal = (out) => ({ ok: false, code: out.code, message: out.message || MESSAGES[out.code] || out.code });

const DEFAULT_EXPIRES = '30d';

const ADD = {
  ...base, id: 'list.add_entry', name: 'Add an entry to a list',
  description: 'Puts one value (an address or network, a domain name, a URL or a file hash) on a list. On a block list this is a block as soon as the firewall next polls it; the list refuses what is too wide, private, or covered by an allow list. Expires after 30 days unless told otherwise. Undo takes the entry off again.',
  parameters: [
    LIST_ID,
    { name: 'value', type: 'string', required: true, max: model.LIMITS.valueMax, description: 'The value, in the form the list holds (an address, a domain name, a URL or a hash).' },
    { name: 'note', type: 'string', max: model.LIMITS.noteMax, description: 'Why it is on the list (shown next to the entry).' },
    { name: 'expires', type: 'enum', values: Object.keys(model.EXPIRES), description: `How long it stays. Left out: ${DEFAULT_EXPIRES}.` },
    { name: 'expires_at', type: 'string', max: 19, description: 'An exact time (2026-12-31T23:59:59, server clock, UTC) instead of expires. Used when a removal is undone.' },
  ],
  async execute({ client, tenantId, userId }, p) {
    let expires;
    if (p.expires_at) { const r = model.parseExpiresAt(p.expires_at); if (r.error) return { ok: false, code: r.error.code, message: r.error.message }; expires = { at: r.value }; }
    else expires = model.parseExpires(p.expires || DEFAULT_EXPIRES).value;
    const out = await service.addEntries(client, tenantId, userId, p.list_id, { values: [p.value], note: p.note || null, expires, source: 'action' });
    if (out.code === 'ALREADY_EXPIRED') return { ok: true, result: { list_id: p.list_id, added: 0, already: 0, note: 'The expiry time had already passed, so nothing was added' }, undo: null };
    if (out.code) return refusal(out);
    if (out.refused.length) return refusal(out.refused[0]);
    const added = out.added.length;
    return { ok: true, result: { list_id: p.list_id, list_name: out.list.name, value: (out.added[0] || out.existing[0]), added, already: out.existing.length },
      undo: added ? { action: 'list.remove_entry', params: { list_id: p.list_id, value: out.added[0] } } : null };
  },
};

const REMOVE = {
  ...base, id: 'list.remove_entry', name: 'Remove an entry from a list',
  description: 'Takes one value off a list. On a block list the firewall stops blocking it at its next poll; on an allow list it is no longer protected. Undo puts it back with its note and its expiry time.',
  parameters: [
    LIST_ID,
    { name: 'value', type: 'string', required: true, max: model.LIMITS.valueMax, description: 'The value to take off.' },
  ],
  async execute({ client, tenantId, userId }, p) {
    const out = await service.removeEntries(client, tenantId, userId, p.list_id, [p.value]);
    if (out.code) return refusal(out);
    if (!out.removed.length) return { ok: true, result: { list_id: p.list_id, list_name: out.list.name, removed: 0, note: 'It was not on the list' }, undo: null };
    const r = out.removed[0];
    const params = { list_id: p.list_id, value: r.value, ...(r.note ? { note: r.note } : {}), ...(r.expires_at ? { expires_at: r.expires_at } : { expires: 'never' }) };
    return { ok: true, result: { list_id: p.list_id, list_name: out.list.name, value: r.value, removed: 1 }, undo: { action: 'list.add_entry', params } };
  },
};

for (const def of [ADD, REMOVE]) if (!catalog.get(def.id)) catalog.register(def);   // a second require (the test loads it twice) must not register twice

module.exports = { ADD, REMOVE, DEFAULT_EXPIRES };
