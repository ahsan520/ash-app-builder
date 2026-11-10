'use strict';
// The vendor public keys a license is verified against (docs/licensing.md). A license names the key that signed it (header `kid`).
// Licenses are NEVER verified against a key taken from the environment or a file on the server: whoever has the repo could otherwise sign their own.
// To set up: `node scripts/license-tool.js keygen ./keys` prints the lines to paste into KEYS below; commit them, keep license-private.pem off every server and out of Git.
// To rotate: add the new key, sign new licenses with it, remove the old key when the last license signed with it has expired.
// While KEYS is empty no license can be verified and only the baseline modules run (fail closed).
const KEYS = [
  // { kid: 'asix-2026-1', pem: '-----BEGIN PUBLIC KEY-----\nMCow...\n-----END PUBLIC KEY-----\n' },
];
module.exports = { KEYS };
