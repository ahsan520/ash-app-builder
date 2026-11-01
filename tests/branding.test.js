'use strict';
// E7 branding rules (docs/branding.md; decisions 2 and 3 in docs/endpoints.md): the open source product behind ASIX Endpoint Security is named in ONE place in the product
// (the third-party notices, src/endpoints/notices.js) plus the places where the name is a fact about a file, a package, a service or an address. It is never an ASIX name, and
// the product is never called "EDR". Each allowed place below has a reason; to add one, add it here AND to the table in docs/branding.md.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const NAME = /wazuh|ossec/i;
const notices = require('../src/endpoints/notices');
const installer = require('../src/endpoints/agent-installer');

// Remove every allowed snippet from a line; what still matches NAME is a violation. Returns the leftover text.
const leftover = (line, allowed) => allowed.reduce((s, re) => s.replace(re, ' '), line);
const violations = (lines, allowed, isComment) => lines.map((l, i) => [i + 1, l]).filter(([, l]) => !isComment(l) && NAME.test(leftover(l, allowed))).map(([n, l]) => n + ': ' + l.trim().slice(0, 160));

describe('the portal', () => {
  // Allowed in src/portal/index.html (anything else that matches the name is shown to a person and must not name the product):
  const ALLOWED = [
    /\b'?wazuh(alerts)?'?(?=\s*[:,\]])/g,                                  // internal input keys the broker heartbeat reports ('wazuh', 'wazuhalerts'); the page shows the label next to them
    /wazuh_managers table/g, /wazuh_indexers table/g,                                              // operator text: the database table an operator has to create by running the schema job
    /src\/endpoints\/wazuh-(manager|indexer)-cli\.js/g, /asix-wazuh-registration\.json/g,   // operator text: the command that registers a manager, and its input file
    /\/var\/ossec\/etc\/authd\.pass/g,                                    // operator text: the path of the enrolment password file on the manager VM
  ];
  const lines = read('src/portal/index.html').split('\n');
  const comment = (l) => /^\s*\/\//.test(l);
  const stripTail = (l) => l.replace(/\s\/\/\s.*$/, '');   // a trailing comment is not shown
  it('names the product only in operator text and internal keys, not in anything a person reads', () => {
    const v = violations(lines.map(stripTail), ALLOWED, comment); assert.deepStrictEqual(v, [], 'the product name is shown to a person here:\n' + v.join('\n'));
  });
  it('does not keep its own copy of the notices (the tab reads the route)', () => {
    const html = lines.join('\n'); assert.ok(!/EP_NOTICES/.test(html)); assert.match(html, /api\('\/v1\/endpoints\/notices'\)/);
    assert.ok(!/GNU General Public License/.test(html), 'the licence text lives in src/endpoints/notices.js only');
  });
  it('never calls the product EDR or XDR, or an ASIX-branded copy of the vendor name', () => {
    const html = lines.join('\n'); assert.ok(!/ASIX (Wazuh|EDR)|Wazuh by ASIX|Endpoint Security EDR/i.test(html)); assert.ok(!/\bEDR\b/.test(html.replace(/\/\/.*$/gm, '')), 'decision 2: the name is ASIX Endpoint Security, not EDR');
  });
});

describe('messages the API sends to the portal', () => {
  const files = ['src/gateway/routes', 'src/endpoints'].flatMap((d) => fs.readdirSync(path.join(root, d)).filter((f) => f.endsWith('.js')).map((f) => d + '/' + f));
  const STR = "'(?:[^'\\\\\\n]|\\\\.)*'|\"(?:[^\"\\\\\\n]|\\\\.)*\"";
  // apiError(res, 404, 'CODE', 'message') and new SomeError('CODE', 'message'): the message is what a person reads. Codes (WAZUH_...) are part of the API and may keep the name.
  const MSG = [new RegExp("apiError\\([^,]+,\\s*\\d+,\\s*(?:" + STR + "),\\s*(" + STR + ")", 'g'), new RegExp("new \\w*Error\\(\\s*(?:" + STR + "),\\s*(" + STR + ")", 'g')];
  const ALLOWED_MESSAGES = [/The database has no wazuh_(managers|indexers) table yet/];   // operator text: the table the schema job creates
  it('finds the messages it is meant to check (so the scan itself cannot silently find none)', () => {
    const n = files.map((f) => { const s = read(f); return MSG.map((re) => (s.match(re) || []).length).reduce((a, b) => a + b, 0); }).reduce((a, b) => a + b, 0); assert.ok(n > 40, 'only ' + n + ' messages found');
  });
  it('none of them names the product (except operator text about a table)', () => {
    const bad = [];
    for (const f of files) { const s = read(f); for (const re of MSG) for (const m of s.matchAll(re)) if (NAME.test(m[1]) && !ALLOWED_MESSAGES.some((a) => a.test(m[1]))) bad.push(f + ': ' + m[1].slice(0, 120)); }
    assert.deepStrictEqual(bad, [], 'user-visible message names the product:\n' + bad.join('\n'));
  });
});

describe('the installers (as a person runs them)', () => {
  // Allowed in the scripts: names of packages, services, files, folders, environment variables and addresses that the machine itself uses, the vendor's own documentation
  // (the person is told to compare a fingerprint with it), and the notices block.
  const ALLOWED = [
    /https?:\/\/[^\s"')]*(wazuh|ossec)[^\s"')]*/gi, /documentation\.wazuh\.com/g, /packages\.wazuh\.com\S*/g,   // addresses
    /\bwazuh-(agent|manager)[\w.\-$]*/g, /\bwazuh\.(gpg|list|repo)\b/g, /\bGPG-KEY-WAZUH\b/g, /\bWazuhSvc\b/g, /\bWAZUH_[A-Z_]+/g, /\[wazuh\]/g,   // package, repository, service, variable names
    /\/var\/ossec|\$OSSEC\b|\bossec(-agent|\.log)?\b/gi,                  // the agent's own folder and log
    /EL-\$releasever - Wazuh/g,                                           // the repository's display name inside the repository file
    /Installation guide, Wazuh agent/g, /'Wazuh Agent\*'/g,               // pointing the person to the vendor's guide; matching the installed program's name
  ];
  const noticeLines = new Set(notices.text().split('\n'));
  const isComment = (l) => /^\s*#/.test(l) || noticeLines.has(l);
  for (const [label, render] of [['Linux', installer.render], ['Windows', installer.renderWindows]]) {
    it(label + ': names the product only as a package, service, path or address, or in the notices block', () => {
      const s = render({ host: '192.168.68.54', group: 'default', managerVersion: 'v4.14.9' }).script;
      const v = violations(s.split('\n'), ALLOWED, isComment); assert.deepStrictEqual(v, [], 'the product name is shown to a person here:\n' + v.join('\n'));
    });
    it(label + ': says it is ASIX Endpoint Security and never presents the vendor name as an ASIX name', () => {
      const s = render({ host: '192.168.68.54', group: 'default', managerVersion: 'v4.14.9' }).script; assert.match(s, /ASIX Endpoint Security agent/); assert.ok(!/ASIX (Wazuh|EDR)|Wazuh by ASIX|\bEDR\b/i.test(s));
    });
  }
});

describe('the whole shipped tree', () => {
  const dirs = ['src', 'deploy', 'scripts', 'k8s'];
  const walk = (d) => fs.readdirSync(path.join(root, d), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(d + '/' + e.name) : [d + '/' + e.name]));
  it('has no ASIX-branded copy of the vendor name (the file names asix-wazuh-* are listed in docs/branding.md)', () => {
    const bad = dirs.flatMap(walk).filter((f) => /\.(js|html|sh|ps1|yaml|yml|service|timer|py|json|md)$/.test(f)).flatMap((f) => read(f).split('\n').map((l, i) => [f + ':' + (i + 1), l]).filter(([, l]) => /ASIX Wazuh|Wazuh by ASIX|ASIX['\u2019]s Wazuh|ASIX EDR|ASIX Endpoint Security EDR/i.test(l)).map(([w]) => w));
    assert.deepStrictEqual(bad, []);
  });
  it('the ASIX-prefixed file and unit names that contain the vendor name are exactly the ones listed in docs/branding.md', () => {
    const found = dirs.flatMap(walk).map((f) => path.basename(f)).filter((n) => /^asix-wazuh-/.test(n)).sort(); const doc = read('docs/branding.md');
    assert.ok(found.length >= 3); for (const n of found) assert.ok(doc.includes('`' + n + '`'), n + ' is not listed in docs/branding.md');
  });
});

describe('the rules document', () => {
  const doc = read('docs/branding.md');
  it('exists, lists the rules, the allowed places and the questions for the lawyer', () => {
    for (const h of ['## Rules', '## Where the product name may appear', '## Questions for the lawyer', '## Before the first client install']) assert.ok(doc.includes(h), h);
  });
  it('says the same thing about the review as the notices module does', () => {
    assert.strictEqual(/Lawyer read: \*\*not done\*\*/.test(doc), notices.REVIEWED === false, 'update docs/branding.md when REVIEWED changes');
  });
});
