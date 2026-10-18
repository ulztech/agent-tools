import { DatabaseSync } from 'node:sqlite';
import { appendEvent } from './chain.js';
import fs from 'node:fs';
import path from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'auditor', 'member')),
  status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'suspended')),
  created_at TEXT NOT NULL,
  last_login_at TEXT,
  disabled_at TEXT,
  totp_secret TEXT,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  totp_confirmed_at TEXT
);

CREATE TABLE IF NOT EXISTS webauthn_creds (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  aaguid TEXT,
  backup_eligible INTEGER NOT NULL DEFAULT 0,
  backup_state INTEGER NOT NULL DEFAULT 0,
  nickname TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_level INTEGER NOT NULL DEFAULT 1,
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  step_up_until TEXT,
  idle_ms INTEGER NOT NULL DEFAULT 900000,
  ip TEXT,
  ua_hash TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_by TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge TEXT PRIMARY KEY,
  user_id TEXT,
  type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS auth_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  user_id TEXT,
  event TEXT NOT NULL,
  factor TEXT,
  result TEXT NOT NULL,
  ip TEXT,
  detail TEXT,
  prev_hash TEXT,
  row_hash TEXT
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  upstream_url TEXT NOT NULL,
  auth_mode TEXT NOT NULL DEFAULT 'forward-auth',
  allowed_roles TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_rules (
  role TEXT NOT NULL,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  PRIMARY KEY (role, application_id)
);

CREATE TABLE IF NOT EXISTS platform_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_throttle (
  key TEXT PRIMARY KEY,
  failures INTEGER NOT NULL DEFAULT 0,
  window_started_at TEXT NOT NULL,
  locked_until TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events (ts);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
`;

export function dataDir() {
  const dir = path.resolve(process.env.AT_DATA || '.data/platform');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function openPlatformDb(dir = dataDir()) {
  const db = new DatabaseSync(path.join(dir, 'platform.sqlite'));
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return { db, dir };
}

export const nowIso = () => new Date().toISOString();

export function audit(db, event) {
  return appendEvent(db, event);
}

export function findUser(db, username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || '').toLowerCase()) || null;
}

export function userById(db, id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
}

export function credentialsFor(db, userId) {
  return db.prepare('SELECT * FROM webauthn_creds WHERE user_id = ? ORDER BY created_at').all(userId);
}

export function listApplications(db) {
  return db.prepare('SELECT * FROM applications ORDER BY name').all();
}

export function seedDurablePi(db) {
  const existing = db.prepare("SELECT id FROM applications WHERE name = 'durable-pi'").get();
  if (existing) return existing.id;
  const id = 'app_durable_pi';
  db.prepare(
    `INSERT INTO applications (id, name, upstream_url, auth_mode, allowed_roles, status, created_at)
     VALUES (?,?,?,?,?, 'active', ?)`,
  ).run(id, 'durable-pi', 'http://durable-pi:4781', 'forward-auth', JSON.stringify(['member', 'admin', 'owner']), nowIso());
  for (const role of ['member', 'admin', 'owner']) {
    db.prepare('INSERT OR IGNORE INTO access_rules (role, application_id) VALUES (?,?)').run(role, id);
  }
  return id;
}
