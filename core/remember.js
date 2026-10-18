import crypto from 'node:crypto';

export const REMEMBER_COOKIE = '__Host-at_remember';
export const REMEMBER_DAYS = 30;

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

/**
 * A "remembered browser" token. It identifies the account so the password can be skipped
 * on the next sign-in. It never authenticates on its own: the authenticator code is still
 * required, and the token grants no session.
 */
export function issueRememberToken(db, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare(
    `INSERT INTO remember_tokens (id, user_id, token_hash, created_at, expires_at, last_used_at, revoked_at)
     VALUES (?,?,?,?,?,NULL,NULL)`,
  ).run(
    `rem_${crypto.randomBytes(9).toString('base64url')}`,
    userId,
    sha256(token),
    new Date().toISOString(),
    new Date(Date.now() + REMEMBER_DAYS * 86_400_000).toISOString(),
  );
  return token;
}

export function resolveRememberToken(db, token) {
  if (!token) return null;
  const row = db.prepare('SELECT * FROM remember_tokens WHERE token_hash = ?').get(sha256(token));
  if (!row || row.revoked_at) return null;
  if (Date.parse(row.expires_at) < Date.now()) return null;
  db.prepare('UPDATE remember_tokens SET last_used_at = ? WHERE id = ?').run(
    new Date().toISOString(),
    row.id,
  );
  return row;
}

export function listRemembered(db, userId) {
  return db
    .prepare(
      `SELECT id, created_at, last_used_at, expires_at FROM remember_tokens
        WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC`,
    )
    .all(userId, new Date().toISOString());
}

export function revokeRememberToken(db, id, userId) {
  const info = db
    .prepare('UPDATE remember_tokens SET revoked_at = ? WHERE id = ? AND user_id = ?')
    .run(new Date().toISOString(), id, userId);
  return Number(info.changes) === 1;
}

export function revokeAllRemembered(db, userId) {
  db.prepare('UPDATE remember_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(
    new Date().toISOString(),
    userId,
  );
}
