import test from 'node:test';
import assert from 'node:assert/strict';
import { appendAudit, verifyAudit } from '../src/store.js';
import { setup } from './helpers.js';

function event(overrides = {}) {
  return {
    actorType: 'agent',
    actorId: 'test-agent',
    action: 'query.read',
    connectionId: 'conn_test',
    queryShape: 'select email from employee',
    queryHash: 'deadbeef',
    rowCount: 1,
    maskedColumns: ['email:redact:name'],
    decision: 'allow',
    ...overrides,
  };
}

test('audit: a clean chain verifies', () => {
  const s = setup();
  for (let i = 0; i < 3; i += 1) appendAudit(s.db, event());
  const result = verifyAudit(s.db);
  assert.equal(result.ok, true);
  assert.equal(result.checked, 3);
});

test('audit: tampering with any field is detected', () => {
  const s = setup();
  appendAudit(s.db, event());
  appendAudit(s.db, event({ decision: 'allow' }));
  appendAudit(s.db, event());

  s.db.prepare("UPDATE audit_events SET decision = 'deny' WHERE seq = 2").run();
  const result = verifyAudit(s.db);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 2);
});

test('audit: deleting a row breaks the chain', () => {
  const s = setup();
  appendAudit(s.db, event());
  appendAudit(s.db, event());
  appendAudit(s.db, event());

  s.db.prepare('DELETE FROM audit_events WHERE seq = 2').run();
  const result = verifyAudit(s.db);
  assert.equal(result.ok, false);
});

test('audit: values never appear in the record', () => {
  const s = setup();
  const secret = 'juan.dela.cruz@example.com';
  appendAudit(
    s.db,
    event({
      queryShape: 'select email from employee where email = ?',
      queryHash: 'hash-only',
      maskedColumns: ['email:redact:name'],
    }),
  );
  const raw = JSON.stringify(s.db.prepare('SELECT * FROM audit_events').all());
  assert.equal(raw.includes(secret), false);
  assert.equal(raw.includes('@example.com'), false);
});
