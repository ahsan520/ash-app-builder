#!/usr/bin/env node
'use strict';
// Vendor-side license tool (docs/licensing.md). Keep the PRIVATE key off every platform server and out of Git.
//   node scripts/license-tool.js keygen <dir> [kid]
//       writes license-private.pem (secret) and license-public.pem, and prints the line to paste into src/modules/vendor-keys.js
//   node scripts/license-tool.js sign <private.pem> <kid> <customer> <days> <installation-id|*> <@residential|@enterprise|feature,feature,...> [tenants|unlimited] [retention_days|unlimited] [grace_days 0-90, default 30]
//       prints the license. The installation id is shown on the Modules page and by scripts/deploy/install-license.sh --id; "*" makes a license that works on any installation (use sparingly).
//   node scripts/license-tool.js inspect <license>      shows what a license says (does not verify it)
const fs = require('fs');
const path = require('path');
const { generateKeyPair, exportPKCS8, exportSPKI, importPKCS8, SignJWT, decodeJwt, decodeProtectedHeader } = require('jose');
const { BUNDLES, ENTERPRISE_ONLY, ALL } = require('../src/licensing/bundles');

const num = (v) => (v === undefined ? undefined : v === 'unlimited' ? null : parseInt(v, 10));
const IID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\*)$/;

function expandFeatures(spec) {
  const out = new Set();
  for (const part of String(spec).split(',').map((x) => x.trim()).filter(Boolean)) {
    if (BUNDLES[part]) BUNDLES[part].forEach((f) => out.add(f));
    else if (ALL.includes(part)) out.add(part);
    else throw new Error('unknown feature or bundle "' + part + '" (bundles: ' + Object.keys(BUNDLES).join(', ') + '; features: ' + ALL.join(', ') + ')');
  }
  return [...out];
}

async function main() {
  const [cmd, ...a] = process.argv.slice(2);
  if (cmd === 'keygen' && a[0]) {
    const kid = a[1] || 'asix-' + new Date().getFullYear() + '-1';
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    fs.mkdirSync(a[0], { recursive: true });
    const pub = await exportSPKI(publicKey);
    fs.writeFileSync(path.join(a[0], 'license-private.pem'), await exportPKCS8(privateKey), { mode: 0o600 });
    fs.writeFileSync(path.join(a[0], 'license-public.pem'), pub);
    console.log('Wrote license-private.pem (keep secret, never on a server) and license-public.pem.\nPaste this into KEYS in src/modules/vendor-keys.js and commit it:\n');
    console.log("  { kid: '" + kid + "', pem: '" + pub.trim().replace(/\n/g, '\\n') + "\\n' },");
  } else if (cmd === 'sign' && a.length >= 6) {
    const [keyFile, kid, customer, days, iid, spec, tenants, retention, graceArg] = a;
    if (!IID_RE.test(iid)) throw new Error('the installation id must be the id shown on the Modules page (a UUID), or *');
    if (!(parseInt(days, 10) > 0)) throw new Error('days must be a positive number');
    const features = expandFeatures(spec);
    const limits = {};
    if (tenants !== undefined) limits.tenants = num(tenants);
    if (retention !== undefined) limits.retention_days_max = num(retention);
    const kind = features.some((f) => ENTERPRISE_ONLY.includes(f)) ? 'enterprise' : 'residential';
    const key = await importPKCS8(fs.readFileSync(keyFile, 'utf8'), 'EdDSA');
    const claims = { features, limits, iid, kind };
    if (graceArg !== undefined) { const g = parseInt(graceArg, 10); if (!(g >= 0 && g <= 90)) throw new Error('grace_days must be 0 to 90'); claims.grace_days = g; }
    const jwt = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA', kid }).setIssuer('asix').setSubject(customer)
      .setIssuedAt().setExpirationTime(`${parseInt(days, 10)}d`).sign(key);
    process.stdout.write(jwt + '\n');
  } else if (cmd === 'inspect' && a[0]) {
    const t = a[0].trim(); const p = decodeJwt(t);
    console.log(JSON.stringify({ kid: decodeProtectedHeader(t).kid, customer: p.sub, kind: p.kind, installation: p.iid, features: p.features, limits: p.limits, grace_days: p.grace_days === undefined ? 'default (30)' : p.grace_days, issued: new Date(p.iat * 1000).toISOString(), expires: new Date(p.exp * 1000).toISOString() }, null, 2));
  } else {
    console.error('usage:\n  license-tool.js keygen <dir> [kid]\n  license-tool.js sign <private.pem> <kid> <customer> <days> <installation-id|*> <@residential|@enterprise|features,comma> [tenants|unlimited] [retention_days|unlimited] [grace_days]\n  license-tool.js inspect <license>');
    process.exit(2);
  }
}
main().catch((e) => { console.error('failed:', e.message); process.exit(1); });
