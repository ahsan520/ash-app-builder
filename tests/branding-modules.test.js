'use strict';
// Branding rules (docs/branding.md) for the pages modules bring themselves (src/portal/modules/<id>/, docs/portal-shell.md).
// tests/branding.test.js scans src/portal/index.html; module pages are separate files, so they are scanned here, with no allowed
// exceptions: a module page is all person-facing text, so the open source product behind Endpoint Security is never named in it and
// the product is never called "EDR".
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '../src/portal/modules');
const files = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(path.join(d, e.name)) : /\.(js|css)$/.test(e.name) ? [path.join(d, e.name)] : []));
const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/\s\/\/\s.*$/gm, '');   // comments are not shown to anyone

describe('module pages', () => {
  const list = files(DIR);
  it('finds the page files it is meant to check (so the scan cannot silently find none)', () => {
    assert.ok(list.length >= 1);
    assert.ok(list.some((f) => f.endsWith(path.join('content-packs', 'marketplace.js'))));
  });
  it('none names the product behind Endpoint Security, or calls the product EDR', () => {
    const bad = [];
    for (const f of list) {
      code(fs.readFileSync(f, 'utf8')).split('\n').forEach((l, i) => {
        if (/wazuh|ossec/i.test(l)) bad.push(`${path.relative(DIR, f)}:${i + 1}: names the product: ${l.trim().slice(0, 100)}`);
        if (/\bEDR\b/.test(l)) bad.push(`${path.relative(DIR, f)}:${i + 1}: calls the product EDR: ${l.trim().slice(0, 100)}`);
      });
    }
    assert.deepStrictEqual(bad, [], bad.join('\n'));
  });
});
