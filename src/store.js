import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { canonicalJson, newId, nowIso, sha256Hex } from './util.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tools (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  profile TEXT NOT NULL CHECK (profile IN ('local', 'network')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_keys (
  tool_id TEXT PRIMARY KEY REFERENCES tools(id) ON DELETE CASCADE,
  iv TEXT NOT NULL,
  tag TEXT NOT NULL,
  ct TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  engine TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  database_name TEXT NOT NULL,
  tool_id TEXT NOT NULL REFERENCES tools(id),
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connection_secrets (
  connection_id TEXT PRIMARY KEY REFERENCES connections(id) ON DELETE CASCADE,
  iv TEXT NOT NULL,
  tag TEXT NOT NULL,
  ct TEXT NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS service_credentials (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  kid TEXT NOT NULL UNIQUE,
  alg TEXT NOT NULL CHECK (alg = 'ES256'),
  public_key_jwk TEXT NOT NULL,
  envelope TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  last_minted_at TEXT,
  minted_today INTEGER NOT NULL DEFAULT 0,
  quota_day TEXT
);

CREATE TABLE IF NOT EXISTS service_mint_nonces (
  nonce TEXT PRIMARY KEY,
  svc_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capability_nonces (
  nonce TEXT PRIMARY KEY,
  cap_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pii_registry (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  table_name TEXT NOT NULL,
  column_name TEXT NOT NULL,
  strategy TEXT NOT NULL CHECK (strategy IN ('redact', 'mask', 'hash', 'null')),
  params TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  UNIQUE (connection_id, table_name, column_name)
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  connection_id TEXT,
  query_shape TEXT,
  query_hash TEXT,
  row_count INTEGER,
  masked_columns TEXT,
  decision TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detector_flags (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_seq INTEGER,
  connection_id TEXT,
  table_name TEXT,
  column_name TEXT NOT NULL,
  detector TEXT NOT NULL,
  reason TEXT,
  ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_lookup
  ON pii_registry (connection_id, column_name, enabled);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events (ts);
`;

export const GENESIS_HASH = '0'.repeat(64);

export function resolveDataDir(dataDir) {
  const dir = path.resolve(dataDir || process.env.AGENT_TOOLS_DATA || '.data');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function openDb(dataDir) {
  const dir = resolveDataDir(dataDir);
  const db = new DatabaseSync(path.join(dir, 'gateway.sqlite'));
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return { db, dir };
}

export function getMeta(db, key) {
  const row = db.prepare('SELECT value FROM meta WHERE key = ?').get(key);
  return row ? row.value : null;
}

export function setMeta(db, key, value) {
  db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run(key, String(value));
}

/* ------------------------------------------------------------------ */
/* Audit — hash chained, values never stored                           */
/* ------------------------------------------------------------------ */

export function lastAuditHash(db) {
  const row = db.prepare('SELECT row_hash FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  return row ? row.row_hash : GENESIS_HASH;
}

/**
 * Append an audit event. Must be called *before* the result is released.
 * The payload is hashed; only the hash, shape and column names are persisted.
 */
export function appendAudit(db, event) {
  const ts = event.ts || nowIso();
  const prev = lastAuditHash(db);
  const payload = {
    ts,
    actor_type: event.actorType,
    actor_id: event.actorId,
    action: event.action,
    connection_id: event.connectionId ?? null,
    query_shape: event.queryShape ?? null,
    query_hash: event.queryHash ?? null,
    row_count: event.rowCount ?? null,
    masked_columns: event.maskedColumns ?? [],
    decision: event.decision,
    prev_hash: prev,
  };
  const rowHash = sha256Hex(`${prev}${canonicalJson(payload)}`);
  const info = db
    .prepare(
      `INSERT INTO audit_events
        (ts, actor_type, actor_id, action, connection_id, query_shape, query_hash,
         row_count, masked_columns, decision, prev_hash, row_hash)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(
      payload.ts,
      payload.actor_type,
      payload.actor_id,
      payload.action,
      payload.connection_id,
      payload.query_shape,
      payload.query_hash,
      payload.row_count,
      JSON.stringify(payload.masked_columns),
      payload.decision,
      prev,
      rowHash,
    );
  return { seq: Number(info.lastInsertRowid), rowHash };
}

/** Recompute the chain. Returns { ok, brokenAt, checked }. */
export function verifyAudit(db) {
  const rows = db.prepare('SELECT * FROM audit_events ORDER BY seq ASC').all();
  let prev = GENESIS_HASH;
  for (const row of rows) {
    if (row.prev_hash !== prev) return { ok: false, brokenAt: row.seq, checked: rows.length };
    const payload = {
      ts: row.ts,
      actor_type: row.actor_type,
      actor_id: row.actor_id,
      action: row.action,
      connection_id: row.connection_id,
      query_shape: row.query_shape,
      query_hash: row.query_hash,
      row_count: row.row_count,
      masked_columns: JSON.parse(row.masked_columns || '[]'),
      decision: row.decision,
      prev_hash: row.prev_hash,
    };
    const expected = sha256Hex(`${prev}${canonicalJson(payload)}`);
    if (expected !== row.row_hash) return { ok: false, brokenAt: row.seq, checked: rows.length };
    prev = row.row_hash;
  }
  return { ok: true, brokenAt: null, checked: rows.length };
}

export function recordDetectorFlag(db, flag) {
  db.prepare(
    `INSERT INTO detector_flags (audit_seq, connection_id, table_name, column_name, detector, reason, ts)
     VALUES (?,?,?,?,?,?,?)`,
  ).run(
    flag.auditSeq ?? null,
    flag.connectionId ?? null,
    flag.tableName ?? null,
    flag.columnName,
    flag.detector,
    flag.reason ?? null,
    nowIso(),
  );
}

/* ------------------------------------------------------------------ */
/* Tools                                                               */
/* ------------------------------------------------------------------ */

export function ensureTool(db, { name, profile }) {
  const existing = db.prepare('SELECT * FROM tools WHERE name = ?').get(name);
  if (existing) return existing;
  const id = newId('tool');
  db.prepare('INSERT INTO tools (id, name, profile, created_at) VALUES (?,?,?,?)').run(
    id,
    name,
    profile,
    nowIso(),
  );
  return db.prepare('SELECT * FROM tools WHERE id = ?').get(id);
}
