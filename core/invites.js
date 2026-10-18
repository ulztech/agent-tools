import crypto from 'node:crypto';
import { audit } from './db.js';

export const newId = (prefix) => `${prefix}_${crypto.randomBytes(9).toString('base64url')}`;
export const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

/**
 * Create (or re-invite) a user and return a one-time enrolment token. The token is shown
 * once and stored only as a hash.
 */
export function issueInvite(db, { username = null, role, displayName, createdBy = 'cli', ttlMinutes = 60 }) {
  let userId;

  if (username) {
    const name = String(username).trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(name)) {
      throw new Error('username must be 1-64 chars: a-z, 0-9, dot, underscore, hyphen');
    }
    const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(name);
    if (existing && existing.status === 'active') throw new Error(`user is already active: ${name}`);
    userId = existing ? existing.id : newId('usr');
    if (!existing) {
      db.prepare(
        `INSERT INTO users (id, username, display_name, role, status, created_at)
         VALUES (?,?,?,?, 'invited', ?)`,
      ).run(userId, name, displayName || username, role, new Date().toISOString());
    } else {
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, userId);
    }
  } else {
    // Open invite: the account has no login name until the invitee chooses one.
    userId = newId('usr');
    db.prepare(
      `INSERT INTO users (id, username, display_name, role, status, created_at)
       VALUES (?,?,?,?, 'invited', ?)`,
    ).run(userId, `pending_${userId.slice(-10)}`, 'Pending', role, new Date().toISOString());
  }

  const token = crypto.randomBytes(32).toString('base64url');
  // A re-invite invalidates any earlier open invite for that user.
  db.prepare('UPDATE invites SET used_at = ? WHERE user_id = ? AND used_at IS NULL').run(
    new Date().toISOString(),
    userId,
  );
  db.prepare(
    `INSERT INTO invites (id, user_id, token_hash, created_by, created_at, expires_at, used_at)
     VALUES (?,?,?,?,?,?,NULL)`,
  ).run(
    newId('inv'),
    userId,
    sha256(token),
    createdBy,
    new Date().toISOString(),
    new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
  );

  audit(db, { userId, event: 'user.invite', result: 'ok', detail: `role=${role}` });
  return {
    userId,
    username: username ? String(username).trim().toLowerCase() : null,
    role,
    token,
    expiresInMinutes: ttlMinutes,
    path: `/enroll?token=${token}`,
  };
}

export function inviteByToken(db, token) {
  const row = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(sha256(token));
  if (!row || row.used_at) return null;
  if (Date.parse(row.expires_at) < Date.now()) return null;
  return row;
}

/**
 * Consume an invite atomically. Two concurrent enrolments with the same token: exactly
 * one wins.
 */
export function consumeInvite(db, token) {
  const row = inviteByToken(db, token);
  if (!row) return null;
  const info = db
    .prepare('UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL')
    .run(new Date().toISOString(), row.id);
  return Number(info.changes) === 1 ? row : null;
}

export function pendingInvites(db) {
  return db
    .prepare(
      `SELECT i.id, i.expires_at,
              CASE WHEN u.username LIKE 'pending_%' THEN '(chosen at enrolment)' ELSE u.username END AS username,
              u.role
         FROM invites i JOIN users u ON u.id = i.user_id
        WHERE i.used_at IS NULL AND i.expires_at > ?
        ORDER BY i.expires_at`,
    )
    .all(new Date().toISOString());
}
