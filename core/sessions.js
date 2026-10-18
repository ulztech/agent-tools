import crypto from 'node:crypto';

export const SESSION_COOKIE = '__Host-at_session';
export const IDLE_MS = 15 * 60 * 1000;
export const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
export const STEP_UP_MS = 5 * 60 * 1000;

const randomId = () => crypto.randomBytes(32).toString('base64url');

/**
 * Create a session. `authLevel` 1 = a verified passkey assertion (reaches nothing but
 * the TOTP step); 2 = passkey + TOTP.
 */
export function createSession(db, { userId, authLevel = 1, ip = null, uaHash = null }) {
  const id = randomId();
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions
       (id, user_id, auth_level, csrf_token, created_at, last_seen_at,
        idle_expires_at, absolute_expires_at, step_up_until, ip, ua_hash, revoked_at)
     VALUES (?,?,?,?,?,?,?,?,NULL,?,?,NULL)`,
  ).run(
    id,
    userId,
    authLevel,
    crypto.randomBytes(24).toString('base64url'),
    new Date(now).toISOString(),
    new Date(now).toISOString(),
    new Date(now + IDLE_MS).toISOString(),
    new Date(now + ABSOLUTE_MS).toISOString(),
    ip,
    uaHash,
  );
  return loadSession(db, id, now);
}

export function loadSession(db, id, now = Date.now()) {
  if (!id) return null;
  const row = db
    .prepare(
      `SELECT s.*, u.username, u.role, u.status, u.display_name
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id = ?`,
    )
    .get(id);
  if (!row) return null;
  if (row.revoked_at) return null;
  if (row.status !== 'active') return null;
  if (now >= Date.parse(row.absolute_expires_at)) return null;
  if (now >= Date.parse(row.idle_expires_at)) return null;
  return row;
}

export function touchSession(db, id, now = Date.now()) {
  db.prepare('UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?').run(
    new Date(now).toISOString(),
    new Date(now + IDLE_MS).toISOString(),
    id,
  );
}

/**
 * L1 -> L2. The session id rotates, so a cookie captured before the second factor is
 * useless afterwards.
 */
export function elevateSession(db, id) {
  const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  if (!row) return null;
  const newId = randomId();
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions
       (id, user_id, auth_level, csrf_token, created_at, last_seen_at,
        idle_expires_at, absolute_expires_at, step_up_until, ip, ua_hash, revoked_at)
     VALUES (?,?,2,?,?,?,?,?,NULL,?,?,NULL)`,
  ).run(
    newId,
    row.user_id,
    crypto.randomBytes(24).toString('base64url'),
    row.created_at,
    new Date(now).toISOString(),
    new Date(now + IDLE_MS).toISOString(),
    row.absolute_expires_at,
    row.ip,
    row.ua_hash,
  );
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(new Date(now).toISOString(), id);
  return loadSession(db, newId, now);
}

export function markStepUp(db, id, now = Date.now()) {
  db.prepare('UPDATE sessions SET step_up_until = ? WHERE id = ?').run(
    new Date(now + STEP_UP_MS).toISOString(),
    id,
  );
}

export function isStepUpFresh(session, now = Date.now()) {
  return Boolean(session?.step_up_until && Date.parse(session.step_up_until) > now);
}

export function revokeSession(db, id) {
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(new Date().toISOString(), id);
}

export function revokeAllForUser(db, userId) {
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(
    new Date().toISOString(),
    userId,
  );
}

export function liveSessions(db) {
  return db
    .prepare(
      `SELECT s.id, s.auth_level, s.created_at, s.last_seen_at, s.idle_expires_at,
              u.username, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.revoked_at IS NULL
        ORDER BY s.last_seen_at DESC`,
    )
    .all();
}
