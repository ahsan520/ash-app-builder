'use strict';
// File encryption for backups: AES-256-GCM (authenticated), key from a passphrase via scrypt.
// Layout: "ASIXBK01" | salt(16) | iv(12) | ciphertext... | auth tag(16). Streams, so big dumps are fine.
const fs = require('fs');
const crypto = require('crypto');

const MAGIC = Buffer.from('ASIXBK01'), HEAD = MAGIC.length + 16 + 12, TAG = 16;
const deriveKey = (pass, salt) => crypto.scryptSync(String(pass), salt, 32);

async function encryptFile(src, dest, passphrase) {
  if (!passphrase) throw new Error('backup passphrase is not set');
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(passphrase, salt), iv);
  const out = fs.createWriteStream(dest, { mode: 0o600 }), hash = crypto.createHash('sha256');
  const write = (buf) => new Promise((res, rej) => out.write(buf, (e) => (e ? rej(e) : res())));
  const head = Buffer.concat([MAGIC, salt, iv]); hash.update(head); await write(head);
  for await (const chunk of fs.createReadStream(src)) { const enc = cipher.update(chunk); hash.update(enc); await write(enc); }
  const tail = Buffer.concat([cipher.final(), cipher.getAuthTag()]); hash.update(tail); await write(tail);
  await new Promise((res, rej) => out.end((e) => (e ? rej(e) : res())));
  return { sha256: hash.digest('hex'), bytes: fs.statSync(dest).size };
}

async function decryptFile(src, dest, passphrase) {
  const size = fs.statSync(src).size;
  if (size < HEAD + TAG) throw new Error('not a valid backup file (too short)');
  const fd = fs.openSync(src, 'r'); const head = Buffer.alloc(HEAD), tag = Buffer.alloc(TAG);
  fs.readSync(fd, head, 0, HEAD, 0); fs.readSync(fd, tag, 0, TAG, size - TAG); fs.closeSync(fd);
  if (!head.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('not an ASIX backup file (bad header)');
  const d = crypto.createDecipheriv('aes-256-gcm', deriveKey(passphrase, head.subarray(8, 24)), head.subarray(24, HEAD)); d.setAuthTag(tag);
  const out = fs.createWriteStream(dest, { mode: 0o600 });
  const write = (buf) => new Promise((res, rej) => out.write(buf, (e) => (e ? rej(e) : res())));
  try {
    if (size - TAG > HEAD) for await (const chunk of fs.createReadStream(src, { start: HEAD, end: size - TAG - 1 })) await write(d.update(chunk));
    await write(d.final());
    await new Promise((res, rej) => out.end((e) => (e ? rej(e) : res())));
  } catch (e) {
    out.destroy(); fs.rmSync(dest, { force: true });
    throw new Error('cannot decrypt: wrong passphrase or the file is damaged');
  }
}

const sha256File = (p) => new Promise((res, rej) => { const h = crypto.createHash('sha256'); fs.createReadStream(p).on('data', (c) => h.update(c)).on('end', () => res(h.digest('hex'))).on('error', rej); });

module.exports = { encryptFile, decryptFile, sha256File };
