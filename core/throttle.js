export const MAX_FAILURES = 5;
export const WINDOW_MS = 5 * 60 * 1000;
export const BASE_LOCK_MS = 60 * 1000;
export const MAX_LOCK_MS = 30 * 60 * 1000;

function read(db, key) {
  return db.prepare('SELECT * FROM auth_throttle WHERE key = ?').get(key) || null;
}

function write(db, key, failures, windowStartedAt, lockedUntil) {
  db.prepare(
    `INSERT INTO auth_throttle (key, failures, window_started_at, locked_until)
     VALUES (?,?,?,?)
     ON CONFLICT(key) DO UPDATE SET
       failures = excluded.failures,
       window_started_at = excluded.window_started_at,
       locked_until = excluded.locked_until`,
  ).run(key, failures, windowStartedAt, lockedUntil);
}

export function isLocked(db, key, now = Date.now()) {
  const row = read(db, key);
  return Boolean(row?.locked_until && Date.parse(row.locked_until) > now);
}

export function lockRemainingMs(db, key, now = Date.now()) {
  const row = read(db, key);
  if (!row?.locked_until) return 0;
  return Math.max(0, Date.parse(row.locked_until) - now);
}

/**
 * Count a failure. The first `MAX_FAILURES` inside the window are free; after that the
 * delay grows exponentially, capped at 30 minutes.
 */
export function recordFailure(db, key, now = Date.now()) {
  const row = read(db, key);
  const inWindow = row && now - Date.parse(row.window_started_at) < WINDOW_MS;
  const failures = inWindow ? row.failures + 1 : 1;
  const windowStartedAt = inWindow ? row.window_started_at : new Date(now).toISOString();

  let lockedUntil = null;
  if (failures >= MAX_FAILURES) {
    const delay = Math.min(BASE_LOCK_MS * 2 ** (failures - MAX_FAILURES), MAX_LOCK_MS);
    lockedUntil = new Date(now + delay).toISOString();
  }
  write(db, key, failures, windowStartedAt, lockedUntil);
  return { failures, lockedUntil };
}

export function clearFailures(db, key) {
  db.prepare('DELETE FROM auth_throttle WHERE key = ?').run(key);
}
