'use strict';
// Static checks on the broker's syslog-over-TLS files (no Vector needed; CI has no Vector binary). They catch drift between
// the three places that must agree: deploy/broker/vector-tls.yaml (reads settings), broker.env.example (documents them) and
// scripts/deploy/bootstrap-broker.sh (writes them). The real behaviour (TLS handshake, both framings, mutual TLS, the
// bootstrap script) was run against Vector 0.47.0, see docs/broker-vm.md. Run those again after changing any of these files:
//   vector validate --no-environment deploy/broker/vector.yaml deploy/broker/vector-tls.yaml
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const tlsCfg = read('deploy/broker/vector-tls.yaml');
const baseCfg = read('deploy/broker/vector.yaml');
const envExample = read('deploy/broker/broker.env.example');
const bootstrap = read('scripts/deploy/bootstrap-broker.sh');

const envVars = (text) => [...new Set([...text.matchAll(/\$\{(ASIX_[A-Z_]+)/g)].map((m) => m[1]))];

describe('broker syslog over TLS files', () => {
  it('the TLS source is a TLS-enabled syslog tcp source named syslog_*, so the base transform picks it up', () => {
    assert.match(tlsCfg, /^sources:\n {2}syslog_tls:\n {4}type: syslog\n {4}mode: tcp\n/m);
    assert.match(tlsCfg, /tls:\n {6}enabled: true/);
    assert.match(baseCfg, /inputs: \["syslog_\*"\]/);
    const code = baseCfg.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');   // comments may name the TLS file
    assert.ok(!/syslog_tls/.test(code), 'the base config must work without the TLS file');
  });
  it('the base config has no TLS listener of its own (TLS stays opt-in)', () => {
    assert.ok(!/enabled: true/.test(baseCfg.split('sources:')[1].split('transforms:')[0]));
  });
  it('every setting vector-tls.yaml reads is documented in broker.env.example and written by the bootstrap script', () => {
    const vars = envVars(tlsCfg);
    assert.ok(vars.length >= 5, 'expected the port, certificate, key, CA and verify settings: ' + vars);
    for (const v of vars) {
      assert.ok(envExample.includes(v), v + ' is missing from broker.env.example');
      assert.ok(bootstrap.includes(v), v + ' is never written by bootstrap-broker.sh');
    }
  });
  it('the bootstrap script sets VECTOR_CONFIG to both files, and only with a certificate', () => {
    assert.match(bootstrap, /VECTOR_CONFIG=\/etc\/vector\/vector\.yaml,\/etc\/vector\/vector-tls\.yaml/);
    assert.match(envExample, /#VECTOR_CONFIG=\/etc\/vector\/vector\.yaml,\/etc\/vector\/vector-tls\.yaml/);
    assert.match(bootstrap, /rm -f \/etc\/vector\/vector-tls\.yaml/, 're-running without TLS must remove the listener');
  });
  it('the bootstrap script is valid bash and refuses bad TLS arguments before changing anything', () => {
    assert.strictEqual(spawnSync('bash', ['-n', path.join(root, 'scripts/deploy/bootstrap-broker.sh')]).status, 0);
    if (process.getuid && process.getuid() !== 0) return;   // the script checks for root first; the argument checks below need it
    const run = (...args) => spawnSync('bash', [path.join(root, 'scripts/deploy/bootstrap-broker.sh'), '--url', 'https://x/v1/ingest/http', '--key', 'asix_ik_x', '--name', 'b', '--no-install', ...args], { encoding: 'utf8' });
    const a = run('--tls-cert', '/nonexistent.crt');
    assert.strictEqual(a.status, 2); assert.match(a.stderr, /needed together/);
    const b = run('--tls-port', 'abc');
    assert.strictEqual(b.status, 2); assert.match(b.stderr, /--tls-port must be a number/);
  });
});
