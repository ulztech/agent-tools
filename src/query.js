import { appendAudit, recordDetectorFlag } from './store.js';
import { getToolDek, openWithDek, verifyCapability } from './crypto.js';
import { buildRedactionPlan, loadRegistryIndex, maskRows } from './masking.js';
import { GatewayError, queryShape, sha256Hex } from './util.js';

export const TOOL_NAME = 'database-gateway';
export const RESOURCE_PREFIX = 'db:';
export const DEFAULT_MAX_ROWS = 100;
export const HARD_MAX_ROWS = 1000;

export function readConnectionSecret(db, masterKey, connection) {
  const row = db.prepare('SELECT * FROM connection_secrets WHERE connection_id = ?').get(connection.id);
  if (!row) throw new GatewayError('E_NO_SECRET', 'connection has no stored secret');
  const dek = getToolDek(db, masterKey, connection.tool_id);
  const json = openWithDek(dek, row).toString('utf8');
  return JSON.parse(json);
}

/**
 * The data path. Order matters:
 *   1. verify the capability (deterministic, local — D20)
 *   2. read-only gate (refusing a write is not blocking a result)
 *   3. run
 *   4. mask from the registry inventory (never blocks, never suppresses)
 *   5. audit, durably, before the rows are released
 */
export async function runQuery({
  db,
  masterKey,
  publicKey,
  kid,
  connectionName,
  token,
  sql,
  params = [],
  maxRows = DEFAULT_MAX_ROWS,
  audience = TOOL_NAME,
  actorId = 'agent',
  driverFactory,
}) {
  if (typeof sql !== 'string' || sql.trim() === '') {
    throw new GatewayError('E_SQL_EMPTY', 'sql is empty');
  }
  const limit = Math.min(Number(maxRows) || DEFAULT_MAX_ROWS, HARD_MAX_ROWS);
  const connection = db.prepare('SELECT * FROM connections WHERE name = ?').get(connectionName);
  const base = {
    actorType: 'agent',
    actorId,
    action: 'query.read',
    connectionId: connection ? connection.id : null,
    queryShape: queryShape(sql),
    queryHash: sha256Hex(sql),
  };

  // 1. Capability. Denials are audited (a grant *and* a denial is a decision worth keeping).
  let payload;
  try {
    payload = verifyCapability({
      db,
      publicKey,
      kid,
      token,
      expectedAudience: audience,
      expectedResource: `${RESOURCE_PREFIX}${connectionName}`,
      action: 'query.read',
    });
  } catch (err) {
    appendAudit(db, { ...base, decision: `deny:${err.code ?? 'auth'}` });
    throw err;
  }

  if (!connection) {
    appendAudit(db, { ...base, decision: 'deny:unknown-connection' });
    throw new GatewayError('E_UNKNOWN_CONNECTION', `unknown connection: ${connectionName}`);
  }
  if (connection.status !== 'active') {
    appendAudit(db, { ...base, decision: 'deny:connection-inactive' });
    throw new GatewayError('E_CONNECTION_INACTIVE', `connection is not active: ${connectionName}`);
  }

  // 2. Read-only gate.
  let tokens;
  try {
    const { assertReadOnly } = await import('./sqlgate.js');
    tokens = assertReadOnly(sql);
  } catch (err) {
    appendAudit(db, { ...base, decision: `deny:${err.code ?? 'gate'}` });
    throw err;
  }
  void tokens;

  // 3. Execute.
  const secret = readConnectionSecret(db, masterKey, connection);
  const driver = driverFactory
    ? driverFactory(secret)
    : await (await import('./drivers.js')).createMysqlDriver(secret);

  let result;
  try {
    result = await driver.query({ sql, params, maxRows: limit });
  } catch (err) {
    appendAudit(db, { ...base, decision: 'error:driver' });
    throw new GatewayError('E_DRIVER', 'query failed', { cause: String(err && err.message) });
  } finally {
    if (driver && typeof driver.close === 'function') await driver.close().catch(() => {});
  }

  // 4. Mask. Unresolvable lineage falls back to column-name matching (D16).
  const registry = loadRegistryIndex(db, connection.id);
  // The capability carries a signed masking plan. The live registry is authoritative for
  // new rules; the signed plan is a floor, so a rule deleted after mint still masks until
  // the capability expires (<= 15 min).
  for (const [key, strategy] of Object.entries(payload.red || {})) {
    const [, column] = key.split('.');
    if (!column) continue;
    const lower = column.toLowerCase();
    if (!registry.byColumn.has(lower)) {
      registry.byColumn.set(lower, [{ table: key.split('.')[0], column, strategy, params: null }]);
    }
  }
  const salt = payload.sid || payload.cap_id;
  const { rows, maskedColumns, flagged } = maskRows({
    rows: result.rows || [],
    fields: result.fields || [],
    sql,
    registry,
    salt,
  });

  // 5. Audit before release — the local record is durable even if a remote sink is down.
  const { seq } = appendAudit(db, {
    ...base,
    rowCount: rows.length,
    maskedColumns: maskedColumns.map((m) => `${m.column}:${m.strategy}:${m.matchedBy}`),
    decision: 'allow',
  });
  for (const flag of flagged) {
    recordDetectorFlag(db, { ...flag, auditSeq: seq, connectionId: connection.id, tableName: null });
  }

  return {
    connection: connection.name,
    fields: result.fields || [],
    rows,
    rowCount: rows.length,
    maskedColumns,
    annotations: { pii: { maskedColumns: maskedColumns.map((m) => m.column) } },
    auditSeq: seq,
  };
}

/** Convenience for the CLI: what the signed plan looks like right now. */
export function currentPlan(db, connectionId) {
  return buildRedactionPlan(db, connectionId);
}
