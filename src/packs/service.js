'use strict';
// Database side of content packs. Every function takes an open tenant-scoped client (from
// db.withTenant) and filters on tenant_id explicitly, because the API connects as the table owner,
// which bypasses RLS.
const { PREFIX } = require('./index');

const prefixOf = (packId) => `${PREFIX}${packId}:`;

// { [packId]: { installed, enabled, open_alerts } } for the tenant
async function status(client, tenantId) {
  const r = await client.query(
    `SELECT r.builtin_key, r.enabled,
            (SELECT COUNT(*)::int FROM alerts a WHERE a.rule_id = r.id AND a.status <> 'closed') AS open_alerts
     FROM detection_rules r WHERE r.tenant_id = $1 AND left(r.builtin_key, ${PREFIX.length}) = $2`,
    [tenantId, PREFIX]);
  const out = {};
  for (const row of r.rows) {
    const id = row.builtin_key.slice(PREFIX.length).split(':')[0];
    const s = (out[id] = out[id] || { installed: 0, enabled: 0, open_alerts: 0, keys: new Set() });
    s.installed += 1; s.enabled += row.enabled ? 1 : 0; s.open_alerts += row.open_alerts;
    s.keys.add(row.builtin_key);
  }
  return out;
}

// Adds the pack's rules. Existing rules are kept as the user left them unless overwrite is true,
// which puts every rule back to the shipped definition (their enabled/disabled state is kept).
async function install(client, tenantId, pack, { enabled = true, overwrite = false } = {}) {
  const res = { added: 0, kept: 0, restored: 0 };
  for (const r of pack.rules) {
    const params = [tenantId, r.name, r.description, r.severity, enabled, r.builtin_key, r.mitre, JSON.stringify(r.definition), r.kind, r.category];
    const insert = `INSERT INTO detection_rules (tenant_id, name, description, severity, enabled, builtin_key, mitre, definition, kind, category)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)`;
    if (overwrite) {
      const q = await client.query(
        `${insert}
         ON CONFLICT (tenant_id, builtin_key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
           severity = EXCLUDED.severity, mitre = EXCLUDED.mitre, definition = EXCLUDED.definition, kind = EXCLUDED.kind,
           category = EXCLUDED.category, last_error = NULL, updated_at = localtimestamp
         RETURNING (xmax = 0) AS inserted`, params);
      if (q.rows[0].inserted) res.added += 1; else res.restored += 1;
    } else {
      const q = await client.query(`${insert} ON CONFLICT (tenant_id, builtin_key) DO NOTHING RETURNING id`, params);
      if (q.rows.length) res.added += 1; else res.kept += 1;
    }
  }
  return res;
}

// Removes the pack's rules. Alerts raised by those rules are deleted with them (alerts.rule_id is
// ON DELETE CASCADE), so this refuses unless deleteAlerts is set when any alerts exist.
async function uninstall(client, tenantId, packId, { deleteAlerts = false } = {}) {
  const p = prefixOf(packId);
  const where = 'r.tenant_id = $1 AND left(r.builtin_key, $3::int) = $2';
  const n = await client.query(
    `SELECT COUNT(DISTINCT r.id)::int AS rules, COUNT(a.id)::int AS alerts
     FROM detection_rules r LEFT JOIN alerts a ON a.rule_id = r.id WHERE ${where}`, [tenantId, p, p.length]);
  const { rules, alerts } = n.rows[0];
  if (!rules) return { removed: 0, alerts: 0, notInstalled: true };
  if (alerts > 0 && !deleteAlerts) return { blocked: true, rules, alerts };
  await client.query('DELETE FROM detection_rules WHERE tenant_id = $1 AND left(builtin_key, $3::int) = $2', [tenantId, p, p.length]);
  return { removed: rules, alerts };
}

module.exports = { status, install, uninstall };
