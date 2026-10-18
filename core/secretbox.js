import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * AES-256-GCM for secrets held by the platform (TOTP seeds today, vault material in C3).
 * The master key comes from the host (`AT_MASTER_KEY`) or, in local development, a 0600
 * file. Production without a host-supplied key refuses to start.
 */
export function loadMasterKey(dir) {
  const fromEnv = process.env.AT_MASTER_KEY;
  if (fromEnv) {
    const buf = Buffer.from(fromEnv, 'base64');
    if (buf.length !== 32) throw new Error('AT_MASTER_KEY must decode to 32 bytes');
    return buf;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('AT_MASTER_KEY is required in production — the key must not live beside the database');
  }
  const file = path.join(dir, 'master.key');
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
  const buf = crypto.randomBytes(32);
  fs.writeFileSync(file, buf.toString('base64'), { mode: 0o600 });
  return buf;
}

const b64 = (b) => Buffer.from(b).toString('base64url');

export function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(String(aad)));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return JSON.stringify({ iv: b64(iv), tag: b64(cipher.getAuthTag()), ct: b64(ct) });
}

export function open(key, sealed, aad) {
  const { iv, tag, ct } = JSON.parse(sealed);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  if (aad) decipher.setAAD(Buffer.from(String(aad)));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}
