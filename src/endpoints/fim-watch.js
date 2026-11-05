'use strict';
// E10b: an ASIX alert when a file changes in a folder an operator chose under Endpoints, Group settings (docs/endpoints.md, "E10b as built").
//
// Why: the manager reports a file added, changed or deleted at level 5 to 7, and the built-in endpoint rules raise alerts from level 8 (plus a short list of sensitive paths), so a change
// in a folder an operator asked to watch showed only on the File integrity tab. One detection rule per agent group, key `endpoint-fim-watched:<group>`, whose query is the folders of
// that group's ASIX block; it is written when Group settings applies a change (or applies nothing new: Apply again to bring an older group up to date).
//
// The query only names paths (file_path, set by the parsing rule wazuh_alert from the alert's syscheck path). Level 8 and up are left to the level rules, so one change is one alert.
const KEY_PREFIX = 'endpoint-fim-watched:';
const NO_FOLDERS = 'file_path = "asix-no-watched-folders"';   // a group with no ASIX folders keeps its rule (and its alerts) but nothing can match

const ruleKey = (group) => KEY_PREFIX + group;

// A regex for one path: the path itself or anything under it. XQL's `~=` ignores letter case (xql-eval.js), so no case handling is needed; Windows paths also take either slash.
function pathRegex(e) {
  const win = e.system === 'windows';
  const trimmed = e.path.replace(win ? /[\\/]+$/ : /\/+$/, '');
  let out = '';
  for (const ch of trimmed) {
    if (win && (ch === '\\' || ch === '/')) out += '[\\\\/]';
    else if (/[.*+?^${}()|[\]\\]/.test(ch)) out += '\\' + ch;
    else out += ch;
  }
  return out + (win ? '([\\\\/].*)?' : '(/.*)?');
}

// entries: [{ system, path, realtime }] (as group-config.js keeps them) -> the xql of the rule.
function queryFor(entries) {
  const list = (entries || []).filter((e) => e && typeof e.path === 'string' && e.path);
  if (!list.length) return NO_FOLDERS;
  const re = '^(' + list.map(pathRegex).join('|') + ')$';
  // the xql string is double-quoted: its own escapes are \\ and \"
  return 'alert_level < 8 and file_path ~= "' + re.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

const description = (group) => 'A file was added, changed or deleted in a folder watched for agent group "' + group + '" (Endpoints, Group settings). ASIX keeps this query in step with that list: applying a folder change rewrites it.';

function definition(entries) {
  return {
    source_type: 'endpoint-alert', group_by: 'field:alert_key', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
    suppression: { enabled: true, minutes: 15 },
    xql: queryFor(entries),
  };
}

// Writes the group's rule. Inserts it when missing; otherwise only the query and the description change (a switch an operator turned off stays off, severity edits stay).
// `client` is a tenant-scoped database client (db.withTenant).
async function sync(client, tenantId, group, entries) {
  const d = definition(entries);
  await client.query(
    `INSERT INTO detection_rules (tenant_id, name, description, severity, builtin_key, mitre, definition, kind, category)
     VALUES ($1, $2, $3, 'medium', $4, ARRAY['T1565.001'], $5::jsonb, 'bioc', 'Endpoint Security')
     ON CONFLICT (tenant_id, builtin_key) DO UPDATE
        SET definition = jsonb_set(detection_rules.definition, '{xql}', to_jsonb($6::text)), description = $3, updated_at = CURRENT_TIMESTAMP`,
    [tenantId, 'Watched folder changed on an endpoint (' + group + ')', description(group), ruleKey(group), JSON.stringify(d), d.xql]
  );
  return d.xql;
}

// E10c: what the Group settings tab says about the group's rule. `row` is { id, enabled, severity, xql } or null; `entries` the folders the manager holds now (sorted, as group-config.js
// keeps them). state: none (no rule yet), on, off (an operator switched it off on the Detections page), idle (no folders: the rule is kept and matches nothing) or out_of_step (its query is
// not the one these folders give: written before a hand change on the manager, or edited on the Detections page). needs_apply: Apply would (re)write the query.
function view(row, entries) {
  const list = (entries || []).filter((e) => e && typeof e.path === 'string' && e.path);
  const out = { state: 'none', folders: list.length, without_real_time: list.filter((e) => !e.realtime).length, rule_id: null, enabled: null, severity: null, needs_apply: list.length > 0 };
  if (!row) return out;
  out.rule_id = row.id; out.enabled = !!row.enabled; out.severity = row.severity || null;
  if (row.xql !== queryFor(list)) { out.state = 'out_of_step'; out.needs_apply = true; return out; }
  out.needs_apply = false;
  out.state = !list.length ? 'idle' : (row.enabled ? 'on' : 'off');
  return out;
}

// Reads the group's rule (tenant-scoped client) and describes it for `entries`. Read only.
async function status(client, tenantId, group, entries) {
  const r = await client.query(`SELECT id, enabled, severity, definition->>'xql' AS xql FROM detection_rules WHERE tenant_id = $1 AND builtin_key = $2`, [tenantId, ruleKey(group)]);
  return view(r.rows && r.rows[0] ? r.rows[0] : null, entries);
}

module.exports = { KEY_PREFIX, NO_FOLDERS, ruleKey, pathRegex, queryFor, definition, description, sync, view, status };
