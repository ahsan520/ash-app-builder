'use strict';
// ASIX_SYSLOG_TIMEZONE: the broker reads RFC 3164 syslog times (no zone in the line; Vector takes them as UTC) in the zone the senders use.
// Static checks that the files agree (no Vector in CI), the bootstrap flag's validation, and, when a Vector binary is on the machine
// (VECTOR_BIN or `vector` on PATH), the real Vector tests in deploy/broker (run on Vector 0.59.0 when this was written).
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const vectorYaml = read('deploy/broker/vector.yaml');
const envExample = read('deploy/broker/broker.env.example');
const bootstrap = read('scripts/deploy/bootstrap-broker.sh');

describe('broker syslog time zone: the files agree', () => {
  it('vector.yaml reads ASIX_SYSLOG_TIMEZONE with UTC as the default (nothing changes unless it is set)', () => {
    assert.match(vectorYaml, /tz = "\$\{ASIX_SYSLOG_TIMEZONE:-UTC\}"/);
    assert.match(vectorYaml, /if tz != "UTC"/);
  });
  it('only lines without a version (RFC 3164) that have a timestamp are re-read; a bad zone or a missing local time keeps the UTC reading', () => {
    assert.match(vectorYaml, /if !exists\(\.version\) && exists\(\.timestamp\)/);
    assert.match(vectorYaml, /t = parse_timestamp\(wall, format: "%Y-%m-%dT%H:%M:%S", timezone: tz\) \?\? t/);
  });
  it('it is documented in broker.env.example and written by the bootstrap script, and only when it is not UTC', () => {
    assert.match(envExample, /#ASIX_SYSLOG_TIMEZONE=America\/Toronto/);
    assert.match(bootstrap, /\[ "\$TIMEZONE" = "UTC" \] \|\| echo "ASIX_SYSLOG_TIMEZONE=\$TIMEZONE"/);
    assert.match(bootstrap, /--timezone\) TIMEZONE="\$2"; shift 2;;/);
    assert.match(bootstrap, /^# --timezone /m);
  });
  it('the Vector test files exist: the default one stays UTC, the zone one needs the zone set', () => {
    assert.match(read('deploy/broker/vector-tests-timezone.yaml'), /ASIX_SYSLOG_TIMEZONE=America\/Toronto/);
    assert.ok(!/ASIX_SYSLOG_TIMEZONE/.test(read('deploy/broker/vector-tests.yaml')));
  });
});

describe('bootstrap --timezone validation', () => {
  it('the script is valid bash', () => { assert.strictEqual(spawnSync('bash', ['-n', path.join(root, 'scripts/deploy/bootstrap-broker.sh')]).status, 0); });
  // Run only the two validation lines, so nothing is installed or written.
  const lines = bootstrap.split('\n').filter((l) => /^\[.*TIMEZONE/.test(l)).join('\n');
  const check = (tz) => spawnSync('bash', ['-c', `${lines}\n`], { env: { ...process.env, TIMEZONE: tz }, encoding: 'utf8' });
  it('finds both validation lines', () => { assert.strictEqual(lines.split('\n').length, 2); });
  it('accepts UTC and real zone names', () => {
    for (const tz of ['UTC', 'America/Toronto', 'Europe/London', 'Etc/GMT+5', 'America/Argentina/Buenos_Aires']) {
      if (tz !== 'UTC' && fs.existsSync('/usr/share/zoneinfo') && !fs.existsSync('/usr/share/zoneinfo/' + tz)) continue;   // a slim image without that file
      assert.strictEqual(check(tz).status, 0, tz + ' ' + check(tz).stderr);
    }
  });
  it('refuses names that are not zone names, with a message, before anything is changed', () => {
    for (const tz of ['', 'a b', '../etc/passwd', 'America/../x', 'x;rm -rf /', '$(id)', 'a'.repeat(65)]) {
      const r = check(tz); assert.strictEqual(r.status, 2, JSON.stringify(tz)); assert.match(r.stderr, /--timezone must be an IANA zone name/);
    }
  });
  it('refuses a well-formed name that is not a zone on this machine', () => {
    if (!fs.existsSync('/usr/share/zoneinfo')) return;
    const r = check('Not/AZone'); assert.strictEqual(r.status, 2); assert.match(r.stderr, /is not a time zone on this machine/);
  });
});

describe('real Vector (skipped when there is no Vector binary)', () => {
  const bin = process.env.VECTOR_BIN || 'vector';
  const have = spawnSync(bin, ['--version'], { encoding: 'utf8' }).status === 0;
  const env = { ...process.env, VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION: 'true', ASIX_SYSLOG_PORT: '5514', ASIX_INGEST_URL: 'http://x/v1/ingest/http', ASIX_INGEST_KEY: 'asix_ik_x', ASIX_BROKER_NAME: 'b' };
  const vt = (file, extra = {}) => spawnSync(bin, ['test', path.join(root, 'deploy/broker/vector.yaml'), path.join(root, file)], { env: { ...env, ...extra }, encoding: 'utf8' });
  it('with no zone set the shipped line-format tests still pass (UTC, as before)', { skip: !have && 'no vector binary' }, () => {
    const r = vt('deploy/broker/vector-tests.yaml', { ASIX_SYSLOG_TIMEZONE: '' }); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });
  it('a zone the broker cannot use changes nothing', { skip: !have && 'no vector binary' }, () => {
    const r = vt('deploy/broker/vector-tests.yaml', { ASIX_SYSLOG_TIMEZONE: 'Not/AZone' }); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });
  it('with America/Toronto, RFC 3164 times are read in that zone (summer and winter) and RFC 5424 ones are untouched', { skip: !have && 'no vector binary' }, () => {
    const r = vt('deploy/broker/vector-tests-timezone.yaml', { ASIX_SYSLOG_TIMEZONE: 'America/Toronto' }); assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.strictEqual((r.stdout.match(/\.\.\. passed/g) || []).length, 4);
  });
});
