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
export function createSession(db, { userId, authLevel = 1, ip = null, uaHash = null, idleMs = IDLE_MS }) {
  const id = randomId();
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions
       (id, user_id, auth_level, csrf_token, created_at, last_seen_at,
        idle_expires_at, absolute_expires_at, step_up_until, idle_ms, ip, ua_hash, revoked_at)
     VALUES (?,?,?,?,?,?,?,?,NULL,?,?,?,NULL)`,
  ).run(
    id,
    userId,
    authLevel,
    crypto.randomBytes(24).toString('base64url'),
    new Date(now).toISOString(),
    new Date(now).toISOString(),
    new Date(now + idleMs).toISOString(),
    new Date(now + ABSOLUTE_MS).toISOString(),
    idleMs,
    ip,
    uaHash,
  );

  // Max three concurrent sessions per user: the oldest is retired.
  const extra = db
    .prepare('SELECT id FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC')
    .all(userId)
    .slice(3);
  for (const row of extra) {
    db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(new Date(now).toISOString(), row.id);
  }

  return loadSession(db, id, now);
}

/**
 * Rotate a session id without changing its level. Used on step-up, so a cookie captured
 * before the fresh passkey check cannot ride the elevated state.
 */
export function rotateSession(db, id, now = Date.now()) {
  const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  if (!row) return null;
  const newId = randomId();
  db.prepare(
    `INSERT INTO sessions
       (id, user_id, auth_level, csrf_token, created_at, last_seen_at,
        idle_expires_at, absolute_expires_at, step_up_until, idle_ms, ip, ua_hash, revoked_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
  ).run(
    newId,
    row.user_id,
    row.auth_level,
    crypto.randomBytes(24).toString('base64url'),
    row.created_at,
    new Date(now).toISOString(),
    new Date(now + (row.idle_ms || IDLE_MS)).toISOString(),
    row.absolute_expires_at,
    row.step_up_until,
    row.idle_ms || IDLE_MS,
    row.ip,
    row.ua_hash,
  );
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(new Date(now).toISOString(), id);
  return loadSession(db, newId, now);
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
  const row = db.prepare('SELECT idle_ms FROM sessions WHERE id = ?').get(id);
  const idleMs = row?.idle_ms || IDLE_MS;
  db.prepare('UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?').run(
    new Date(now).toISOString(),
    new Date(now + idleMs).toISOString(),
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
        idle_expires_at, absolute_expires_at, step_up_until, idle_ms, ip, ua_hash, revoked_at)
     VALUES (?,?,2,?,?,?,?,?,NULL,?,?,?,NULL)`,
  ).run(
    newId,
    row.user_id,
    crypto.randomBytes(24).toString('base64url'),
    row.created_at,
    new Date(now).toISOString(),
    new Date(now + IDLE_MS).toISOString(),
    row.absolute_expires_at,
    IDLE_MS,
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

/** Retire every session except the one making the request. */
export function revokeOtherSessions(db, userId, keepId) {
  db.prepare(
    'UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL',
  ).run(new Date().toISOString(), userId, keepId);
}

export function liveSessions(db, now = Date.now()) {
  const iso = new Date(now).toISOString();
  return db
    .prepare(
      `SELECT s.id, s.auth_level, s.created_at, s.last_seen_at, s.idle_expires_at,
              u.username, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.revoked_at IS NULL
          AND s.idle_expires_at > ?
          AND s.absolute_expires_at > ?
          AND u.status = 'active'
        ORDER BY s.last_seen_at DESC`,
    )
    .all(iso, iso);
}
