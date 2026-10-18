import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb, ensureTool } from '../src/store.js';
import { generateServiceCredential, getToolDek, loadMasterKey, loadSigningKey, mintCapability, sealWithDek } from '../src/crypto.js';
import { setRegistryRule } from '../src/masking.js';
import { projectionOf } from '../src/sqlgate.js';
import { stubDriver } from '../src/drivers.js';
import { newId } from '../src/util.js';

export const CONNECTION = 'hris';
export const TOOL = 'database-gateway';

export const PII = {
  email: 'juan.dela.cruz@example.com',
  first: 'Juan',
  sss: '12-3456789-0',
};

export function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tools-'));
}

export function setup({ registry = [] } = {}) {
  const dir = tempDir();
  const { db } = openDb(dir);
  const masterKey = loadMasterKey(dir);
  const signing = loadSigningKey(dir);
  const tool = ensureTool(db, { name: TOOL, profile: 'network' });

  const connId = newId('conn');
  db.prepare(
    `INSERT INTO connections (id, name, engine, host, port, database_name, tool_id, status, created_at)
     VALUES (?,?,?,?,?,?,?,'active',?)`,
  ).run(connId, CONNECTION, 'mysql', '127.0.0.1', 3306, 'fixture', tool.id, new Date().toISOString());

  const dek = getToolDek(db, masterKey, tool.id);
  const sealed = sealWithDek(
    dek,
    JSON.stringify({ host: '127.0.0.1', port: 3306, user: 'u', password: 'p', database: 'fixture' }),
    connId,
  );
  db.prepare('INSERT INTO connection_secrets (connection_id, iv, tag, ct, key_version) VALUES (?,?,?,?,1)').run(
    connId,
    sealed.iv,
    sealed.tag,
    sealed.ct,
  );

  for (const rule of registry) {
    setRegistryRule(db, { connectionId: connId, ...rule });
  }

  return { dir, db, masterKey, signing, tool, connId };
}

export function mint(signing, overrides = {}) {
  const { claims = {}, ttl = 900, plan = {} } = overrides;
  return mintCapability({
    privateKey: signing.privateKey,
    kid: signing.kid,
    ttlSeconds: ttl,
    claims: {
      capId: newId('cap'),
      subject: 'key:test',
      resource: `db:${CONNECTION}`,
      action: 'query.read',
      audience: TOOL,
      sessionRef: newId('sess'),
      nonce: newId('n'),
      redactionPlan: plan,
      channelProfile: 'network',
      ...claims,
    },
  });
}

/**
 * A stub driver that derives its result columns from the query itself, so the fixture
 * cannot accidentally hide a leak: if the query selects email (directly, aliased, wrapped
 * or via CONCAT), the row really does contain the email sentinel.
 */
export function smartStub(sql, { rows = 1 } = {}) {
  let proj;
  try {
    proj = projectionOf(sql);
  } catch {
    proj = { items: [], star: true };
  }

  const starFields = ['employee_id', 'email', 'first_name', 'sss_no'];
  const fields = proj.star ? starFields : proj.items.map((i) => i.out).filter(Boolean);

  const valueFor = (sources, r) => {
    const s = (sources || []).map((x) => String(x).toLowerCase());
    if (s.includes('email')) return PII.email;
    if (s.includes('first_name') || s.includes('last_name')) return PII.first;
    if (s.includes('sss_no')) return PII.sss;
    if (s.includes('employee_id') || s.includes('id')) return `emp-${r + 1}`;
    return 'plain-ok';
  };

  const data = [];
  for (let r = 0; r < rows; r += 1) {
    const row = {};
    fields.forEach((f, i) => {
      if (proj.star) {
        if (f === 'email') row[f] = PII.email;
        else if (f === 'first_name') row[f] = PII.first;
        else if (f === 'sss_no') row[f] = PII.sss;
        else row[f] = `emp-${r + 1}`;
      } else {
        row[f] = valueFor(proj.items[i]?.sources, r);
      }
    });
    data.push(row);
  }

  return stubDriver({ fields, rows: data });
}

export const DEFAULT_REGISTRY = [
  { table: 'employee', column: 'email', strategy: 'redact' },
  { table: 'employee', column: 'first_name', strategy: 'redact' },
  { table: 'employee', column: 'last_name', strategy: 'redact' },
  { table: 'employee', column: 'sss_no', strategy: 'hash' },
  { table: 'employee', column: 'bank_account', strategy: 'mask' },
];

/**
 * Insert a service passkey row and return the material a test needs to sign a mint
 * request. The gateway stores only the public key — same as the CLI path.
 */
export function enrollService(s, overrides = {}) {
  const {
    connectionId = s.connId,
    label = 'svc-test',
    ttlDays = 90,
    envelope = {},
    expiresAt = new Date(Date.now() + ttlDays * 86_400_000).toISOString(),
  } = overrides;

  const cred = generateServiceCredential();
  const id = newId('svc');
  const env = {
    connection_id: connectionId,
    action: 'query.read',
    max_ttl: 900,
    daily_quota: 2000,
    delegated_by: 'test',
    ...envelope,
  };

  s.db
    .prepare(
      `INSERT INTO service_credentials
         (id, connection_id, label, kid, alg, public_key_jwk, envelope, created_at, expires_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    )
    .run(
      id,
      connectionId,
      label,
      cred.kid,
      'ES256',
      JSON.stringify(cred.publicKeyJwk),
      JSON.stringify(env),
      new Date().toISOString(),
      expiresAt,
    );

  return { id, kid: cred.kid, privateKeyPem: cred.privateKeyPem, envelope: env };
}
