'use strict';
// E6k wiring: the watchdog cycle runs the daily findings summary in its OWN try block (so an unreachable indexer never stops the alerts before it), and the manifest and the rule list carry
// what the docs say. The cycle itself needs a database (runOnce takes an advisory lock), so this reads the source as text, the way tests/api-readiness.test.js reads the manifest.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

describe('the findings summary is part of the watchdog cycle', () => {
  const w = read('src/collectors/watchdog.js');
  it('is required inside runOnce and run per tenant in its own try, after the endpoint agent check, counting a failure as an error', () => {
    assert.match(w, /const findingsSummary = require\('\.\.\/endpoints\/findings-summary'\);/);
    const i = w.indexOf('await findingsSummary.runTenant(t.id, opts)'); assert.ok(i > w.indexOf('await agentWatch.runTenant(t.id, opts)'), 'after the agent check');
    const block = w.slice(w.lastIndexOf('try {', i), w.indexOf('\n', w.indexOf('catch', i)));
    assert.match(block, /^try \{ await findingsSummary\.runTenant\(t\.id, opts\); \}\s*catch \(e\) \{ total\.errors \+= 1;/);
  });
  it('the manifest sets both variables, on and at 03 UTC', () => {
    const y = read('k8s/30-asix-api.yaml');
    assert.match(y, /- name: ASIX_VULN_SUMMARY\n\s+value: "true"/); assert.match(y, /- name: ASIX_VULN_SUMMARY_HOUR\n\s+value: "3"/);
  });
  it('the route is mounted before the readiness route, and the rule is among the built-in rules', () => {
    const g = read('src/gateway/index.js'); assert.ok(g.indexOf("routes/vuln-trend") > 0 && g.indexOf("routes/vuln-trend") < g.indexOf('/v1/health/ready'));
    assert.ok(require('../src/detection/rule-runner').BUILTIN_RULES.some((r) => r.key === 'vuln-new-critical'));
  });
});
