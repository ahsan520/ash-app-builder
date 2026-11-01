'use strict';
// The PostgreSQL pod must start as the image's postgres user, not root: as root the image runs `gosu`, which hung
// at 100% CPU on kernel 7.0.0-42 (2026-11-01) and left the whole platform on 502. See docs/postgres-gosu-hang.md.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const text = fs.readFileSync(path.join(__dirname, '..', 'k8s', '10-postgresql.yaml'), 'utf8');
const sts = text.split(/^---\s*$/m).find((d) => /^kind:\s*StatefulSet\s*$/m.test(d));

test('the postgresql StatefulSet exists', () => {
  assert.ok(sts, 'StatefulSet not found in k8s/10-postgresql.yaml');
});

test('the pod runs as uid 70 (postgres on postgres:16-alpine), so the image does not use gosu', () => {
  assert.match(sts, /image:\s*postgres:16-alpine/);
  assert.match(sts, /^\s{6}securityContext:\s*\n\s{8}runAsUser:\s*70\s*\n\s{8}runAsGroup:\s*70\s*$/m);
});

test('the securityContext is on the pod, before the containers (not inside one)', () => {
  assert.ok(sts.indexOf('securityContext:') < sts.indexOf('containers:'));
});
