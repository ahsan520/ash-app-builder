#!/usr/bin/env node
'use strict';
// Vendor-side license tool. Keep the PRIVATE key off the platform VM and out of Git.
//   node scripts/license-tool.js keygen  <dir>
//   node scripts/license-tool.js sign    <private.pem> <customer> <days> <feature,feature,...> [tenants|unlimited] [retention_days|unlimited]
// The platform only needs the public key (ASIX_LICENSE_PUBKEY_FILE, default /etc/asix/license.pub)
// and the signed file (ASIX_LICENSE_FILE, default /etc/asix/license.jwt).
const fs = require('fs');
const path = require('path');
const { generateKeyPair, exportPKCS8, exportSPKI, importPKCS8, SignJWT } = require('jose');

const num = (v) => (v === undefined ? undefined : v === 'unlimited' ? null : parseInt(v, 10));

async function main() {
  const [cmd, ...a] = process.argv.slice(2);
  if (cmd === 'keygen' && a[0]) {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    fs.mkdirSync(a[0], { recursive: true });
    fs.writeFileSync(path.join(a[0], 'license-private.pem'), await exportPKCS8(privateKey), { mode: 0o600 });
    fs.writeFileSync(path.join(a[0], 'license-public.pem'), await exportSPKI(publicKey));
    console.log('Wrote license-private.pem (keep secret) and license-public.pem (install on the platform).');
  } else if (cmd === 'sign' && a.length >= 4) {
    const [keyFile, customer, days, features, tenants, retention] = a;
    const limits = {};
    if (tenants !== undefined) limits.tenants = num(tenants);
    if (retention !== undefined) limits.retention_days_max = num(retention);
    const key = await importPKCS8(fs.readFileSync(keyFile, 'utf8'), 'EdDSA');
    const jwt = await new SignJWT({ features: features ? features.split(',').filter(Boolean) : [], limits })
      .setProtectedHeader({ alg: 'EdDSA' }).setIssuer('asix').setSubject(customer)
      .setIssuedAt().setExpirationTime(`${parseInt(days, 10)}d`).sign(key);
    process.stdout.write(jwt + '\n');
  } else {
    console.error('usage:\n  license-tool.js keygen <dir>\n  license-tool.js sign <private.pem> <customer> <days> <features,comma> [tenants|unlimited] [retention_days|unlimited]');
    process.exit(2);
  }
}
main().catch((e) => { console.error('failed:', e.message); process.exit(1); });
