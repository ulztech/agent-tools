import crypto from 'node:crypto';

// Ambiguous characters (0/O, 1/I) are excluded so a code can be read off paper.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function normalize(code) {
  return String(code || '')
    .toUpperCase()
    .replace(/[^A-Z2-9]/g, '');
}

export function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    const raw = Array.from(crypto.randomBytes(10))
      .map((byte) => ALPHABET[byte % ALPHABET.length])
      .join('');
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

export function hashCode(code) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(normalize(code), salt, 32);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export function verifyCode(code, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const salt = Buffer.from(parts[1], 'base64url');
  const expected = Buffer.from(parts[2], 'base64url');
  const actual = crypto.scryptSync(normalize(code), salt, expected.length);
  return crypto.timingSafeEqual(expected, actual);
}

export function storeCodes(db, userId, codes) {
  const insert = db.prepare(
    'INSERT INTO recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES (?,?,?,NULL,?)',
  );
  for (const code of codes) {
    insert.run(`rc_${crypto.randomBytes(9).toString('base64url')}`, userId, hashCode(code), new Date().toISOString());
  }
}

/**
 * Consume a recovery code. Single use: the row is marked before the caller acts, and a
 * second attempt with the same code finds nothing.
 */
export function consumeCode(db, userId, code) {
  const rows = db
    .prepare('SELECT * FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
    .all(userId);
  for (const row of rows) {
    if (!verifyCode(code, row.code_hash)) continue;
    const info = db
      .prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL')
      .run(new Date().toISOString(), row.id);
    if (Number(info.changes) === 1) return true;
  }
  return false;
}

export function remainingCodes(db, userId) {
  return db
    .prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
    .get(userId).n;
}
