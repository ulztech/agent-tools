import test from 'node:test';
import assert from 'node:assert/strict';
import { runQuery } from '../src/query.js';
import { buildRedactionPlan } from '../src/masking.js';
import { verifyAudit } from '../src/store.js';
import { newId } from '../src/util.js';
import { CONNECTION, DEFAULT_REGISTRY, PII, mint, setup, smartStub } from './helpers.js';

function run(s, { sql, token, connectionName = CONNECTION, driverFactory, maxRows }) {
  return runQuery({
    db: s.db,
    masterKey: s.masterKey,
    publicKey: s.signing.publicKey,
    kid: s.signing.kid,
    connectionName,
    token,
    sql,
    maxRows,
    driverFactory: driverFactory || (() => smartStub(sql)),
  });
}

test('query: an authorised read returns masked rows and audits the grant', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  const result = await run(s, { sql: 'select employee_id, email from employee', token });

  assert.equal(result.rows[0].email, '[REDACTED]');
  assert.equal(result.rows[0].employee_id, 'emp-1');
  assert.deepEqual(result.annotations.pii.maskedColumns, ['email']);

  const audit = s.db.prepare('SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  assert.equal(audit.decision, 'allow');
  assert.equal(audit.row_count, 1);
  assert.equal(verifyAudit(s.db).ok, true);
});

test('query: a write is refused by the gate, audited, and never reaches the driver', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  let driverCalls = 0;
  await assert.rejects(
    () =>
      run(s, {
        sql: 'update employee set email = null',
        token,
        driverFactory: () => {
          driverCalls += 1;
          return smartStub('select 1');
        },
      }),
    /E_SQL_NOT_READ_ONLY/,
  );
  assert.equal(driverCalls, 0);
  const audit = s.db.prepare('SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  assert.equal(audit.decision, 'deny:E_SQL_NOT_READ_ONLY');
});

test('query: an unknown connection is refused after the capability check', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing, { claims: { resource: 'db:missing' } });
  await assert.rejects(() => run(s, { sql: 'select 1 from employee', token, connectionName: 'missing' }), /E_UNKNOWN_CONNECTION/);
  const audit = s.db.prepare('SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  assert.equal(audit.decision, 'deny:unknown-connection');
});

test('query: an inactive connection is refused', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  s.db.prepare("UPDATE connections SET status = 'disabled' WHERE name = ?").run(CONNECTION);
  const { token } = mint(s.signing);
  await assert.rejects(() => run(s, { sql: 'select 1 from employee', token }), /E_CONNECTION_INACTIVE/);
});

test('query: a driver failure is audited as an error', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  await assert.rejects(
    () =>
      run(s, {
        sql: 'select email from employee',
        token,
        driverFactory: () => ({
          query: async () => {
            throw new Error('boom');
          },
          close: async () => {},
        }),
      }),
    /E_DRIVER/,
  );
  const audit = s.db.prepare('SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  assert.equal(audit.decision, 'error:driver');
});

test('query: max rows is honoured', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  const result = await run(s, {
    sql: 'select email from employee',
    token,
    maxRows: 2,
    driverFactory: () => smartStub('select email from employee', { rows: 5 }),
  });
  assert.equal(result.rows.length, 2);
});

test('query: the signed plan is a floor — deleting a rule after mint still masks', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing, { plan: buildRedactionPlan(s.db, s.connId) });
  s.db.prepare('DELETE FROM pii_registry').run();

  const result = await run(s, { sql: 'select email from employee', token });
  assert.equal(result.rows[0].email, '[REDACTED]');
});

test('query: the chain stays valid across grants, denials and errors', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });

  const a = mint(s.signing);
  await run(s, { sql: 'select email from employee', token: a.token });

  const b = mint(s.signing);
  await assert.rejects(() => run(s, { sql: 'drop table employee', token: b.token }));

  const c = mint(s.signing);
  await assert.rejects(() => run(s, { sql: 'select 1', token: c.token, connectionName: 'nope' }));

  const check = verifyAudit(s.db);
  assert.equal(check.ok, true);
  assert.equal(check.checked, 3);
});

test('query: a negative max rows falls back to the default cap rather than removing it', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  const result = await run(s, {
    sql: 'select employee_id from employee',
    token,
    maxRows: -1,
    driverFactory: () => smartStub('select employee_id from employee', { rows: 200 }),
  });
  assert.equal(result.rows.length, 100);
});

test('query: an unmapped personal-data column returns rows and writes a detector flag', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  const result = await run(s, {
    sql: 'select contact_email_2 from employee',
    token,
    driverFactory: () => ({
      query: async () => ({
        fields: ['contact_email_2'],
        rows: [{ contact_email_2: 'someone@example.com' }],
      }),
      close: async () => {},
    }),
  });

  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].contact_email_2, 'someone@example.com');

  const flags = s.db.prepare('SELECT * FROM detector_flags').all();
  assert.equal(flags.length, 1);
  assert.equal(flags[0].column_name, 'contact_email_2');

  const audit = s.db.prepare('SELECT decision FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  assert.equal(audit.decision, 'allow');
});

test('query: a star over a derived table still masks (I10 through the real path)', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  const result = await run(s, {
    sql: 'select * from (select first_name as x from employee) t',
    token,
    driverFactory: () => ({
      query: async () => ({ fields: ['x'], rows: [{ x: PII.first }] }),
      close: async () => {},
    }),
  });
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].x, '[REDACTED]');
});

test('query: revoking the access key kills capabilities minted before revocation', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const keyId = newId('key');
  const now = new Date().toISOString();
  s.db
    .prepare(
      `INSERT INTO access_keys (id, connection_id, label, key_hash, key_prefix, scopes, created_at, expires_at)
       VALUES (?,?,?,?,?,?,?,?)`,
    )
    .run(keyId, s.connId, 'test', `hash-${keyId}`, 'dbg_test', JSON.stringify(['read']), now, new Date(Date.now() + 60_000).toISOString());

  const { token } = mint(s.signing, { claims: { subject: `key:${keyId}` } });
  s.db.prepare('UPDATE access_keys SET revoked_at = ? WHERE id = ?').run(now, keyId);

  await assert.rejects(() => run(s, { sql: 'select employee_id from employee', token }), /E_KEY_REVOKED/);
  const audit = s.db.prepare('SELECT decision FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  assert.equal(audit.decision, 'deny:key-revoked');
});

test('query: no PII value is present anywhere in the audit trail', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const { token } = mint(s.signing);
  await run(s, { sql: "select email from employee where email = 'juan.dela.cruz@example.com'", token });

  const raw = JSON.stringify(s.db.prepare('SELECT * FROM audit_events').all());
  assert.equal(raw.includes(PII.email), false);
  assert.equal(raw.includes('@example.com'), false);
});
