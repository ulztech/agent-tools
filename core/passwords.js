import crypto from 'node:crypto';

const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 32;

/** NIST-style policy: length, not composition rules. */
export function assertPasswordPolicy(password, username = '') {
  if (typeof password !== 'string') throw new Error('Password is required.');
  if (password.length < 12) throw new Error('Password must be at least 12 characters.');
  if (password.length > 200) throw new Error('Password is too long.');
  if (username && password.toLowerCase() === String(username).toLowerCase()) {
    throw new Error('Password must not be the username.');
  }
}

export function hashPassword(password, username = '') {
  assertPasswordPolicy(password, username);
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64, 'base64url');
  const expected = Buffer.from(hashB64, 'base64url');
  let actual;
  try {
    actual = crypto.scryptSync(String(password || ''), salt, expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
    });
  } catch {
    return false;
  }
  return actual.length === expected.length && crypto.timingSafeEqual(expected, actual);
}
