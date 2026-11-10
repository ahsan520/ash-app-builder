'use strict';
// The actions ASIX knows (task SR2, docs/actions.md). Definitions live in code, not in the database: a tenant does not create actions, it switches
// them on (src/actions/service.js). The built-in actions act on cases, which is the only thing SR2 can change on its own; actions that need an
// account on another product (a firewall, a ticket system) are added with register() once credentials and integrations exist (SR1), and actions on
// machines through the endpoint manager come last (SR5). Nothing here is installed "on" by default: until an administrator enables an action for a
// tenant, a request for it is refused and recorded.
//
// An executor is `execute({ client, tenantId, userId }, params)` and answers one of:
//   { ok: true, result: {...}, undo: { action: '<id>', params: {...} } | null }
//   { ok: false, code, message }       (the run is recorded as failed and anything it changed is rolled back)
// `params` have already been checked against the definition. An executor runs inside the request's tenant-scoped transaction and filters by
// tenantId itself, because the API connects as the table owner, which bypasses row-level security (same rule as src/cases/service.js).
const model = require('./model');
const casesModel = require('../cases/model');
const casesService = require('../cases/service');

const defs = new Map();

// Adds a definition. Throws (at start, never at a request) when it is malformed or the id is taken.
function register(def) {
  const problems = model.checkDefinition(def);
  if (problems.length) throw new Error(`action ${def && def.id}: ${problems.join('; ')}`);
  if (defs.has(def.id)) throw new Error(`action ${def.id} is already registered`);
  defs.set(def.id, Object.freeze({ ...def, parameters: def.parameters.map((q) => Object.freeze({ ...q })) }));
  return def.id;
}
const get = (id) => defs.get(id) || null;
const list = () => [...defs.values()].sort((a, b) => a.id.localeCompare(b.id));

// What a client may see of a definition: everything but the functions.
function publicView(def) {
  return {
    id: def.id, name: def.name, description: def.description, publisher: def.publisher, kind: def.kind, source: def.source,
    risk: def.risk, reversible: def.reversible, append_only: !!def.append_only, max_autonomy: def.max_autonomy, default_autonomy: def.default_autonomy,
    parameters: def.parameters.map((q) => ({ name: q.name, type: q.type, required: !!q.required, nullable: !!q.nullable, values: q.values || null, max: q.max || null, description: q.description })),
  };
}

// ---- built-in actions on cases ---------------------------------------------------------------------------------------------------
const CASE_ID = { name: 'case_id', type: 'uuid', required: true, description: 'The case (its id, from the Cases page or the API).' };
const SOURCE = 'ASIX built-in (src/actions/catalog.js)';
const base = { publisher: 'ASIX', kind: 'builtin', source: SOURCE, default_autonomy: 2 };

const MESSAGES = {
  NOT_FOUND: 'Case not found',
  CASE_CLOSED: 'This case is closed. Reopen it before changing anything else.',
  OWNER_NOT_FOUND: 'User not found in this tenant',
  ALERTS_NOT_FOUND: 'Some alerts were not found',
  ALERTS_TAKEN: 'An alert belongs to one case only, and one of these is already in a case',
  NOT_ATTACHED: 'An alert is not in this case',
};
const refusal = (out) => ({ ok: false, code: out.code, message: MESSAGES[out.code] || out.code });
const parsed = (p) => (p.error ? { ok: false, code: p.error.code, message: p.error.message } : null);

// The current value of one column of a case, or null when there is no such case in this tenant.
async function caseColumn(client, tenantId, caseId, col) {
  if (!['status', 'owner_id', 'severity'].includes(col)) throw new Error('column not allowed');   // a fixed list: a name is never taken from a request
  const r = await client.query(`SELECT ${col} AS v FROM cases WHERE id = $1 AND tenant_id = $2`, [caseId, tenantId]);
  return r.rows.length ? { value: r.rows[0].v } : null;
}

// One action that changes one field of a case and can put it back. `param` is the one parameter besides case_id; its name is the case's column.
const fieldAction = (id, field, over, param) => ({
  ...base, id, risk: 'low', reversible: true, max_autonomy: 4, ...over,
  parameters: [CASE_ID, param],
  async execute({ client, tenantId, userId }, p) {
    const before = await caseColumn(client, tenantId, p.case_id, field);
    if (!before) return refusal({ code: 'NOT_FOUND' });
    const pr = casesModel.parsePatch({ [field]: p[field] }); const bad = parsed(pr); if (bad) return bad;
    const out = await casesService.update(client, tenantId, userId, p.case_id, pr.value);
    if (out.code) return refusal(out);
    if (out.unchanged) return { ok: true, result: { case_id: p.case_id, changed: false }, undo: null };
    return { ok: true, result: { case_id: p.case_id, changed: true, from: before.value, to: pr.value[field] }, undo: { action: id, params: { case_id: p.case_id, [field]: before.value } } };
  },
});

const BUILTIN = [
  {
    ...base, id: 'case.create', name: 'Open a case', risk: 'low', reversible: false, append_only: true, max_autonomy: 4,
    description: 'Opens a new case, optionally with alerts already attached. Adds a case; changes nothing that exists.',
    parameters: [
      { name: 'title', type: 'string', required: true, max: 200, description: 'The case title (1 to 200 characters).' },
      { name: 'description', type: 'string', max: 5000, description: 'What this is about.' },
      { name: 'severity', type: 'enum', values: ['critical', 'high', 'medium', 'low'], description: 'Left out: the worst severity of the alerts, else medium.' },
      { name: 'alert_ids', type: 'uuid_list', max: 50, description: 'Alerts to attach (each alert belongs to one case only).' },
    ],
    async execute({ client, tenantId, userId }, p) {
      const pr = casesModel.parseCreate(p); const bad = parsed(pr); if (bad) return bad;
      const out = await casesService.create(client, tenantId, userId, pr.value);
      if (out.code) return refusal(out);
      return { ok: true, result: { case_id: out.id, case_number: out.case_number }, undo: null };
    },
  },
  {
    ...base, id: 'case.add_note', name: 'Add a note to a case', risk: 'low', reversible: false, append_only: true, max_autonomy: 4,
    description: 'Adds a note to the case timeline (allowed on a closed case). A note cannot be removed afterwards.',
    parameters: [CASE_ID, { name: 'body', type: 'string', required: true, max: 2000, description: 'The note (1 to 2000 characters).' }],
    async execute({ client, tenantId, userId }, p) {
      const pr = casesModel.parseNote({ body: p.body }); const bad = parsed(pr); if (bad) return bad;
      const out = await casesService.addNote(client, tenantId, userId, p.case_id, pr.value);
      if (out.code) return refusal(out);
      return { ok: true, result: { case_id: p.case_id }, undo: null };
    },
  },
  fieldAction('case.set_severity', 'severity',
    { name: 'Set the severity of a case', description: 'Changes the severity of a case. Undo puts the previous severity back.' },
    { name: 'severity', type: 'enum', required: true, values: ['critical', 'high', 'medium', 'low'], description: 'The new severity.' }),
  fieldAction('case.set_owner', 'owner_id',
    { name: 'Set the owner of a case', description: 'Gives a case to a user of this tenant, or to nobody (null). Undo puts the previous owner back.' },
    { name: 'owner_id', type: 'uuid', required: true, nullable: true, description: 'The user, or null for nobody.' }),
  fieldAction('case.set_status', 'status',
    // Medium risk: closing a case takes it out of every active list and every "mine only" view, so a playbook closing cases by itself should be a decision.
    { name: 'Set the status of a case', risk: 'medium', max_autonomy: 3, description: 'Opens, investigates, closes or reopens a case. Closing takes it out of the active lists. Undo puts the previous status back.' },
    { name: 'status', type: 'enum', required: true, values: ['open', 'investigating', 'closed'], description: 'The new status.' }),
  {
    ...base, id: 'case.add_alerts', name: 'Add alerts to a case', risk: 'low', reversible: true, max_autonomy: 4,
    description: 'Attaches alerts to a case (an alert belongs to one case only; one already in another case refuses the whole request). Undo takes the added alerts out again.',
    parameters: [CASE_ID, { name: 'alert_ids', type: 'uuid_list', required: true, max: 50, description: 'The alerts to attach.' }],
    async execute({ client, tenantId, userId }, p) {
      const pr = casesModel.parseAlertIds({ alert_ids: p.alert_ids }); const bad = parsed(pr); if (bad) return bad;
      const had = await client.query('SELECT alert_id FROM case_alerts WHERE case_id = $1 AND tenant_id = $2 AND alert_id = ANY($3::uuid[])', [p.case_id, tenantId, pr.value]);
      const already = new Set(had.rows.map((r) => r.alert_id));
      const out = await casesService.attachAlerts(client, tenantId, userId, p.case_id, pr.value);
      if (out.code) return refusal(out);
      const added = pr.value.filter((id) => !already.has(id));
      return { ok: true, result: { case_id: p.case_id, added: out.added, already: out.already }, undo: added.length ? { action: 'case.remove_alerts', params: { case_id: p.case_id, alert_ids: added } } : null };
    },
  },
  {
    ...base, id: 'case.remove_alerts', name: 'Remove alerts from a case', risk: 'low', reversible: true, max_autonomy: 4,
    description: 'Takes alerts out of a case. All or none: an alert that is not in the case refuses the request. Undo adds them back.',
    parameters: [CASE_ID, { name: 'alert_ids', type: 'uuid_list', required: true, max: 50, description: 'The alerts to take out.' }],
    async execute({ client, tenantId, userId }, p) {
      const pr = casesModel.parseAlertIds({ alert_ids: p.alert_ids }); const bad = parsed(pr); if (bad) return bad;
      for (const id of pr.value) {
        const out = await casesService.detachAlert(client, tenantId, userId, p.case_id, id);
        if (out.code) return refusal(out);   // the run is rolled back as a whole, so the alerts taken out before this one come back
      }
      return { ok: true, result: { case_id: p.case_id, removed: pr.value.length }, undo: { action: 'case.add_alerts', params: { case_id: p.case_id, alert_ids: pr.value } } };
    },
  },
];

for (const def of BUILTIN) register(def);

module.exports = { register, get, list, publicView };
