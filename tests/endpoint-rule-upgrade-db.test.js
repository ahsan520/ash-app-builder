'use strict';
// E4k: a built-in rule whose shipped query changed is upgraded on existing tenants, but only while nobody edited it.
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/endpoint-rule-upgrade-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const db = require('../src/db');
const { ensureBuiltinRules, BUILTIN_RULES } = require('../src/detection/rule-runner');

const OLD = 'alert_level >= 5 and alert_level < 8';
const KEY = 'endpoint-alert-repeated';
const NEW = BUILTIN_RULES.find((r) => r.key === KEY);

async function main() {
  const stamp = Date.now();
  const mk = async (n) => (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['ruleup-' + n + '-' + stamp])).rows[0].id;
  const fresh = await mk('fresh'); const stale = await mk('stale'); const edited = await mk('edited'); const disabled = await mk('disabled'); const other = await mk('other');
  const rule = async (t, k = KEY) => (await db.query('SELECT definition, description, enabled, severity FROM detection_rules WHERE tenant_id = $1 AND builtin_key = $2', [t, k])).rows[0];
  const run = (t) => db.withTenant(t, (c) => ensureBuiltinRules(c, t));
  const setXql = (t, xql) => db.query("UPDATE detection_rules SET definition = jsonb_set(definition, '{xql}', to_jsonb($2::text)) WHERE tenant_id = $1 AND builtin_key = $3", [t, xql, KEY]);

  try {
    // a new tenant gets the new rule straight away
    await run(fresh);
    assert.strictEqual((await rule(fresh)).definition.xql, NEW.definition.xql);

    // a tenant that stored the OLD shipped rule is upgraded; threshold, window, grouping and suppression stay
    await run(stale); await setXql(stale, OLD);
    await db.query('UPDATE detection_rules SET enabled = false, description = $2 WHERE tenant_id = $1 AND builtin_key = $3', [stale, 'old text', KEY]);
    await run(stale);
    let r = await rule(stale);
    assert.strictEqual(r.definition.xql, NEW.definition.xql);
    assert.strictEqual(r.description, NEW.description);
    assert.strictEqual(r.enabled, false, 'a rule the customer switched off stays off');
    assert.deepStrictEqual([r.definition.threshold, r.definition.window_minutes, r.definition.group_by, r.definition.source_type, r.definition.suppression, r.severity],
      [10, 15, 'field:alert_key', 'endpoint-alert', { enabled: true, minutes: 60 }, 'medium']);

    // a tenant that EDITED the query keeps it, description included
    await run(edited); await setXql(edited, 'alert_level >= 6 and alert_level < 8');
    await db.query('UPDATE detection_rules SET description = $2 WHERE tenant_id = $1 AND builtin_key = $3', [edited, 'my text', KEY]);
    await run(edited);
    r = await rule(edited);
    assert.strictEqual(r.definition.xql, 'alert_level >= 6 and alert_level < 8'); assert.strictEqual(r.description, 'my text');

    // a second run changes nothing, and only the one rule is touched in other tenants
    await run(disabled); await setXql(disabled, OLD); await run(disabled);
    const once = JSON.stringify(await rule(disabled)); await run(disabled);
    assert.strictEqual(JSON.stringify(await rule(disabled)), once);
    await run(other); await setXql(other, OLD);
    await run(stale);                                   // running one tenant never touches another
    assert.strictEqual((await rule(other)).definition.xql, OLD);
    for (const k of ['endpoint-alert-critical', 'endpoint-alert-high', 'endpoint-fim-sensitive']) {
      const b = BUILTIN_RULES.find((x) => x.key === k);
      assert.strictEqual((await rule(stale, k)).definition.xql, b.definition.xql, k);
    }
    console.log('endpoint-rule-upgrade-db: ok');
  } finally {
    for (const t of [fresh, stale, edited, disabled, other]) {
      await db.query('DELETE FROM detection_rules WHERE tenant_id = $1', [t]).catch(() => {});
      await db.query('DELETE FROM tenants WHERE id = $1', [t]).catch(() => {});
    }
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
