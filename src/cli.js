#!/usr/bin/env node
import { parseArgs } from 'node:util';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { appendAudit, ensureTool, openDb, verifyAudit } from './store.js';
import {
  generateServiceCredential,
  getToolDek,
  jwksOf,
  loadMasterKey,
  loadSigningKey,
  mintCapability,
  sealWithDek,
  signMintRequest,
  verifyServiceMint,
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
  svc: { type: 'string' },
  'key-file': { type: 'string' },
  session: { type: 'string' },
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
  const { db, dir, masterKey, tool } = ctx(values);

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

    // D28: the connection is created together with its first service passkey.
    const svc = issueServiceCredential(db, {
      connectionId: id,
      label: `svc-${name}`,
      ttl: values.ttl || '90d',
      delegatedBy: 'cli:local',
      dir,
      fileName: name,
    });

    out({
      ok: true,
      id,
      name,
      engine: values.engine || 'mysql',
      service_passkey: { svc_id: svc.id, kid: svc.kid, key_file: svc.keyFile, expires_at: svc.expiresAt },
      note: 'secret stored sealed; the private key is in the key file and is never printed again',
    });
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

/**
 * Issue a service passkey bound to one connection (D28). The private key is written to
 * the data dir with 0600 and never stored anywhere else; the gateway keeps the public key.
 */
function issueServiceCredential(db, { connectionId, label, ttl, delegatedBy, dir, fileName }) {
  const cred = generateServiceCredential();
  const envelope = {
    connection_id: connectionId,
    action: 'query.read',
    max_ttl: 900,
    daily_quota: 2000,
    delegated_by: delegatedBy,
  };
  const id = newId('svc');
  const expiresAt = new Date(Date.now() + parseTtl(ttl, 90 * 86400) * 1000).toISOString();
  db.prepare(
    `INSERT INTO service_credentials
       (id, connection_id, label, kid, alg, public_key_jwk, envelope, created_at, expires_at)
     VALUES (?,?,?,?,?,?,?,?,?)`,
  ).run(
    id,
    connectionId,
    label,
    cred.kid,
    'ES256',
    JSON.stringify(cred.publicKeyJwk),
    JSON.stringify(envelope),
    nowIso(),
    expiresAt,
  );

  const keysDir = path.join(dir, 'keys');
  fs.mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(keysDir, `${fileName || id}.pem`);
  fs.writeFileSync(keyFile, cred.privateKeyPem, { mode: 0o600 });

  return { id, kid: cred.kid, keyFile, expiresAt };
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

function cmdSvc(values, sub) {
  const { db, dir } = ctx(values);

  if (sub === 'enroll') {
    const conn = connectionByName(db, requireOpt(values, 'connection'));
    const label = values.label || `svc-${conn.name}`;
    const svc = issueServiceCredential(db, {
      connectionId: conn.id,
      label,
      ttl: values.ttl || '90d',
      delegatedBy: 'cli:local',
      dir,
      fileName: `${conn.name}-${label}`.replace(/[^a-z0-9._-]+/gi, '-'),
    });
    out({
      ok: true,
      svc_id: svc.id,
      kid: svc.kid,
      connection: conn.name,
      key_file: svc.keyFile,
      expires_at: svc.expiresAt,
      envelope: { action: 'query.read', max_ttl: 900, daily_quota: 2000 },
      note: 'private key written to key_file (0600); the gateway stores only the public key',
    });
    return db.close();
  }

  if (sub === 'list') {
    const rows = db
      .prepare(
        `SELECT s.id, c.name AS connection, s.label, s.kid, s.envelope,
                s.created_at, s.expires_at, s.revoked_at, s.last_minted_at, s.minted_today
           FROM service_credentials s JOIN connections c ON c.id = s.connection_id
          ORDER BY s.created_at DESC`,
      )
      .all();
    out(rows);
    return db.close();
  }

  if (sub === 'revoke') {
    const id = requireOpt(values, 'id');
    const info = db.prepare('UPDATE service_credentials SET revoked_at = ? WHERE id = ?').run(nowIso(), id);
    out({ ok: Number(info.changes) > 0 });
    return db.close();
  }

  throw new GatewayError('E_USAGE', `unknown svc subcommand: ${sub}`);
}

function cmdCap(values, sub) {
  const { db, signing } = ctx(values);

  if (sub === 'mint') {
    const svcId = requireOpt(values, 'svc');
    const keyFile = requireOpt(values, 'key-file');
    const sessionRef = values.session || newId('sess');

    if (!fs.existsSync(keyFile)) {
      throw new GatewayError('E_SVC_KEY_FILE', `key file not found: ${keyFile}`);
    }
    const privateKeyPem = fs.readFileSync(keyFile, 'utf8');

    const svcRow = db
      .prepare(
        `SELECT s.id, s.kid, s.connection_id, c.name AS connection_name
           FROM service_credentials s JOIN connections c ON c.id = s.connection_id
          WHERE s.id = ?`,
      )
      .get(svcId);
    if (!svcRow) throw new GatewayError('E_SVC_UNKNOWN', 'service credential not recognised');

    const ttl = Math.min(parseTtl(values.ttl, 900), 900);
    const request = {
      svc_id: svcId,
      kid: svcRow.kid,
      nonce: newId('n'),
      ts: Math.floor(Date.now() / 1000),
      session_ref: sessionRef,
      resource: `${RESOURCE_PREFIX}${svcRow.connection_name}`,
      action: 'query.read',
      ttl,
    };

    let verified;
    try {
      const signature = signMintRequest(privateKeyPem, request);
      verified = verifyServiceMint({ db, payload: request, signature });
    } catch (err) {
      appendAudit(db, {
        actorType: 'agent',
        actorId: `svc:${svcId}`,
        action: 'capability.mint',
        connectionId: svcRow.connection_id,
        decision: `deny:${err.code ?? 'mint'}`,
      });
      throw err;
    }

    const plan = buildRedactionPlan(db, svcRow.connection_id);
    const { token, payload } = mintCapability({
      privateKey: signing.privateKey,
      kid: signing.kid,
      ttlSeconds: ttl,
      claims: {
        capId: newId('cap'),
        subject: `svc:${verified.svc.id}`,
        resource: `${RESOURCE_PREFIX}${verified.connectionName}`,
        action: 'query.read',
        audience: TOOL_NAME,
        sessionRef,
        nonce: newId('capn'),
        redactionPlan: plan,
        channelProfile: 'network',
      },
    });

    appendAudit(db, {
      actorType: 'agent',
      actorId: `svc:${verified.svc.id}`,
      action: 'capability.mint',
      connectionId: svcRow.connection_id,
      decision: 'allow',
      maskedColumns: Object.keys(plan),
    });

    out({
      ok: true,
      token,
      exp: payload.exp,
      ttl,
      session_ref: sessionRef,
      resource: payload.res,
      audience: payload.aud,
      planEntries: Object.keys(plan).length,
    });
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
    case 'svc':
      return cmdSvc(values, sub);
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
        'usage: agent-tools <init|connection|registry|svc|cap|query|audit|jwks|status> [subcommand] [--options]\n',
      );
      process.exitCode = 2;
  }
}

main().catch((err) => {
  const payload = { ok: false, code: err.code ?? 'E_UNKNOWN', message: err.message };
  process.stderr.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exitCode = 1;
});
