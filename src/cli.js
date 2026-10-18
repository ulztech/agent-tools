#!/usr/bin/env node
import { parseArgs } from 'node:util';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { appendAudit, ensureTool, openDb, verifyAudit } from './store.js';
import {
  getToolDek,
  hashAccessKey,
  jwksOf,
  loadMasterKey,
  loadSigningKey,
  mintCapability,
  sealWithDek,
} from './crypto.js';
import { buildRedactionPlan, listRegistry, removeRegistryRule, setRegistryRule } from './masking.js';
import { TOOL_NAME, RESOURCE_PREFIX, runQuery } from './query.js';
import { GatewayError, newId, nowIso, parseTtl } from './util.js';

const OPTIONS = {
  data: { type: 'string' },
  name: { type: 'string' },
  connection: { type: 'string' },
  engine: { type: 'string' },
  host: { type: 'string' },
  port: { type: 'string' },
  user: { type: 'string' },
  password: { type: 'string' },
  database: { type: 'string' },
  table: { type: 'string' },
  column: { type: 'string' },
  strategy: { type: 'string' },
  params: { type: 'string' },
  label: { type: 'string' },
  ttl: { type: 'string' },
  id: { type: 'string' },
  key: { type: 'string' },
  cap: { type: 'string' },
  sql: { type: 'string' },
  'max-rows': { type: 'string' },
  json: { type: 'boolean' },
};

function out(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function ctx(values) {
  const { db, dir } = openDb(values.data || process.env.AGENT_TOOLS_DATA || '.data');
  const masterKey = loadMasterKey(dir);
  const signing = loadSigningKey(dir);
  const tool = ensureTool(db, { name: TOOL_NAME, profile: 'network' });
  return { db, dir, masterKey, signing, tool };
}

function requireOpt(values, key) {
  if (!values[key]) throw new GatewayError('E_USAGE', `missing --${key}`);
  return values[key];
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

function cmdInit(values) {
  const { db, dir, signing } = ctx(values);
  out({
    ok: true,
    dataDir: dir,
    kid: signing.kid,
    versions: { node: process.version, schema: 1 },
    note: 'Master key and signing key created if absent. Supply AGENT_TOOLS_MASTER_KEY in production.',
  });
  db.close();
}

function cmdConnection(values, sub) {
  const { db, masterKey, tool } = ctx(values);

  if (sub === 'add') {
    const name = requireOpt(values, 'name');
    if (db.prepare('SELECT id FROM connections WHERE name = ?').get(name)) {
      throw new GatewayError('E_DUPLICATE', `connection already exists: ${name}`);
    }
    const id = newId('conn');
    const secret = {
      host: requireOpt(values, 'host'),
      port: Number(values.port || 3306),
      user: requireOpt(values, 'user'),
      password: requireOpt(values, 'password'),
      database: requireOpt(values, 'database'),
    };
    db.prepare(
      `INSERT INTO connections (id, name, engine, host, port, database_name, tool_id, status, created_at)
       VALUES (?,?,?,?,?,?,?,'active',?)`,
    ).run(id, name, values.engine || 'mysql', secret.host, secret.port, secret.database, tool.id, nowIso());
    const dek = getToolDek(db, masterKey, tool.id);
    const sealed = sealWithDek(dek, JSON.stringify(secret), id);
    db.prepare(
      'INSERT INTO connection_secrets (connection_id, iv, tag, ct, key_version) VALUES (?,?,?,?,1)',
    ).run(id, sealed.iv, sealed.tag, sealed.ct);
    out({ ok: true, id, name, engine: values.engine || 'mysql', note: 'secret stored sealed; never printed again' });
    return db.close();
  }

  if (sub === 'list') {
    const rows = db
      .prepare('SELECT id, name, engine, host, port, database_name, status, created_at FROM connections ORDER BY name')
      .all();
    out(rows);
    return db.close();
  }

  if (sub === 'remove') {
    const name = requireOpt(values, 'name');
    const info = db.prepare('DELETE FROM connections WHERE name = ?').run(name);
    out({ ok: Number(info.changes) > 0 });
    return db.close();
  }

  throw new GatewayError('E_USAGE', `unknown connection subcommand: ${sub}`);
}

function connectionByName(db, name) {
  const row = db.prepare('SELECT * FROM connections WHERE name = ?').get(name);
  if (!row) throw new GatewayError('E_UNKNOWN_CONNECTION', `unknown connection: ${name}`);
  return row;
}

function cmdRegistry(values, sub) {
  const { db } = ctx(values);
  if (sub === 'set') {
    const conn = connectionByName(db, requireOpt(values, 'connection'));
    const id = setRegistryRule(db, {
      connectionId: conn.id,
      table: requireOpt(values, 'table'),
      column: requireOpt(values, 'column'),
      strategy: requireOpt(values, 'strategy'),
      params: values.params ? JSON.parse(values.params) : null,
    });
    out({ ok: true, id, table: values.table, column: values.column, strategy: values.strategy });
    return db.close();
  }
  if (sub === 'list') {
    const conn = connectionByName(db, requireOpt(values, 'connection'));
    out(listRegistry(db, conn.id));
    return db.close();
  }
  if (sub === 'remove') {
    const conn = connectionByName(db, requireOpt(values, 'connection'));
    const ok = removeRegistryRule(db, {
      connectionId: conn.id,
      table: requireOpt(values, 'table'),
      column: requireOpt(values, 'column'),
    });
    out({ ok });
    return db.close();
  }
  throw new GatewayError('E_USAGE', `unknown registry subcommand: ${sub}`);
}

function cmdKey(values, sub) {
  const { db } = ctx(values);
  if (sub === 'mint') {
    const conn = connectionByName(db, requireOpt(values, 'connection'));
    const plaintext = `dbg_${crypto.randomBytes(24).toString('base64url')}`;
    const ttl = parseTtl(values.ttl, 30 * 86400);
    const id = newId('key');
    db.prepare(
      `INSERT INTO access_keys (id, connection_id, label, key_hash, key_prefix, scopes, created_at, expires_at)
       VALUES (?,?,?,?,?,?,?,?)`,
    ).run(
      id,
      conn.id,
      values.label || 'default',
      hashAccessKey(plaintext),
      plaintext.slice(0, 12),
      JSON.stringify(['read']),
      nowIso(),
      new Date(Date.now() + ttl * 1000).toISOString(),
    );
    out({ ok: true, id, connection: conn.name, key: plaintext, note: 'shown once — store it in the client host, never in chat' });
    return db.close();
  }
  if (sub === 'list') {
    const rows = db
      .prepare(
        `SELECT k.id, c.name AS connection, k.label, k.key_prefix, k.scopes, k.created_at, k.expires_at, k.revoked_at
           FROM access_keys k JOIN connections c ON c.id = k.connection_id ORDER BY k.created_at DESC`,
      )
      .all();
    out(rows);
    return db.close();
  }
  if (sub === 'revoke') {
    const id = requireOpt(values, 'id');
    const info = db.prepare('UPDATE access_keys SET revoked_at = ? WHERE id = ?').run(nowIso(), id);
    out({ ok: Number(info.changes) > 0 });
    return db.close();
  }
  throw new GatewayError('E_USAGE', `unknown key subcommand: ${sub}`);
}

function cmdCap(values, sub) {
  const { db, signing } = ctx(values);
  if (sub === 'mint') {
    const plain = requireOpt(values, 'key');
    const row = db
      .prepare(
        `SELECT k.*, c.name AS connection_name, c.status AS connection_status
           FROM access_keys k JOIN connections c ON c.id = k.connection_id
          WHERE k.key_hash = ?`,
      )
      .get(hashAccessKey(plain));
    if (!row) throw new GatewayError('E_KEY_UNKNOWN', 'access key not recognised');
    if (row.revoked_at) throw new GatewayError('E_KEY_REVOKED', 'access key has been revoked');
    if (new Date(row.expires_at).getTime() < Date.now()) throw new GatewayError('E_KEY_EXPIRED', 'access key has expired');
    if (row.connection_status !== 'active') throw new GatewayError('E_CONNECTION_INACTIVE', 'connection is not active');

    const ttl = Math.min(parseTtl(values.ttl, 900), 900);
    const plan = buildRedactionPlan(db, row.connection_id);
    const { token, payload } = mintCapability({
      privateKey: signing.privateKey,
      kid: signing.kid,
      ttlSeconds: ttl,
      claims: {
        capId: newId('cap'),
        subject: `key:${row.id}`,
        resource: `${RESOURCE_PREFIX}${row.connection_name}`,
        action: 'query.read',
        audience: TOOL_NAME,
        sessionRef: newId('sess'),
        nonce: newId('n'),
        redactionPlan: plan,
        channelProfile: 'network',
      },
    });
    appendAudit(db, {
      actorType: 'admin',
      actorId: 'cli',
      action: 'capability.mint',
      connectionId: row.connection_id,
      decision: 'allow',
      maskedColumns: Object.keys(plan),
    });
    out({ ok: true, token, exp: payload.exp, ttl, resource: payload.res, audience: payload.aud, planEntries: Object.keys(plan).length });
    return db.close();
  }
  if (sub === 'plan') {
    const conn = connectionByName(db, requireOpt(values, 'connection'));
    out(buildRedactionPlan(db, conn.id));
    return db.close();
  }
  throw new GatewayError('E_USAGE', `unknown cap subcommand: ${sub}`);
}

async function cmdQuery(values) {
  const { db, masterKey, signing } = ctx(values);
  const result = await runQuery({
    db,
    masterKey,
    publicKey: signing.publicKey,
    kid: signing.kid,
    connectionName: requireOpt(values, 'connection'),
    token: requireOpt(values, 'cap'),
    sql: requireOpt(values, 'sql'),
    params: values.params ? JSON.parse(values.params) : [],
    maxRows: Number(values['max-rows'] || 100),
  });
  out(result);
  db.close();
}

function cmdAudit(values, sub) {
  const { db } = ctx(values);
  if (sub === 'verify') {
    out(verifyAudit(db));
    return db.close();
  }
  throw new GatewayError('E_USAGE', `unknown audit subcommand: ${sub}`);
}

function cmdJwks(values) {
  const { signing } = ctx(values);
  out(jwksOf(signing));
}

function cmdStatus(values) {
  const { db, dir, signing } = ctx(values);
  out({
    dataDir: dir,
    kid: signing.kid,
    connections: db.prepare('SELECT COUNT(*) AS n FROM connections').get().n,
    registryRules: db.prepare('SELECT COUNT(*) AS n FROM pii_registry WHERE enabled = 1').get().n,
    auditEvents: db.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n,
    audit: verifyAudit(db),
  });
  db.close();
}

/* ------------------------------------------------------------------ */

async function main() {
  const { values, positionals } = parseArgs({ options: OPTIONS, allowPositionals: true, strict: true });
  const [command, sub] = positionals;
  switch (command) {
    case 'init':
      return cmdInit(values);
    case 'connection':
      return cmdConnection(values, sub);
    case 'registry':
      return cmdRegistry(values, sub);
    case 'key':
      return cmdKey(values, sub);
    case 'cap':
      return cmdCap(values, sub);
    case 'query':
      return cmdQuery(values);
    case 'audit':
      return cmdAudit(values, sub);
    case 'jwks':
      return cmdJwks(values);
    case 'status':
      return cmdStatus(values);
    default:
      process.stderr.write(
        'usage: agent-tools <init|connection|registry|key|cap|query|audit|jwks|status> [subcommand] [--options]\n',
      );
      process.exitCode = 2;
  }
}

main().catch((err) => {
  const payload = { ok: false, code: err.code ?? 'E_UNKNOWN', message: err.message };
  process.stderr.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exitCode = 1;
});
