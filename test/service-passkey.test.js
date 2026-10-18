import test from 'node:test';
import assert from 'node:assert/strict';
import { signMintRequest, verifyServiceMint } from '../src/crypto.js';
import { CONNECTION, enrollService, setup } from './helpers.js';

const NOW = 1_760_000_000;

function request(svc, overrides = {}) {
  return {
    svc_id: svc.id,
    kid: svc.kid,
    nonce: `n_${Math.random().toString(36).slice(2)}`,
    ts: NOW,
    session_ref: 'sess_test',
    resource: `db:${CONNECTION}`,
    action: 'query.read',
    ttl: 900,
    ...overrides,
  };
}

function verify(s, svc, payload, { signature } = {}) {
  return verifyServiceMint({
    db: s.db,
    payload,
    signature: signature ?? signMintRequest(svc.privateKeyPem, payload),
    nowSeconds: NOW,
  });
}

test('svc: a correctly signed mint request is accepted', () => {
  const s = setup();
  const svc = enrollService(s);
  const verified = verify(s, svc, request(svc));
  assert.equal(verified.svc.id, svc.id);
  assert.equal(verified.connectionName, CONNECTION);
});

test('svc: a tampered payload breaks the signature', () => {
  const s = setup();
  const svc = enrollService(s);
  const payload = request(svc);
  const signature = signMintRequest(svc.privateKeyPem, payload);
  payload.resource = 'db:other';
  assert.throws(() => verify(s, svc, payload, { signature }), /E_SVC_SIGNATURE/);
});

test('svc: a mint request nonce is single use', () => {
  const s = setup();
  const svc = enrollService(s);
  const payload = request(svc);
  const signature = signMintRequest(svc.privateKeyPem, payload);
  verify(s, svc, payload, { signature });
  assert.throws(() => verify(s, svc, payload, { signature }), /E_SVC_REPLAY/);
});

test('svc: a revoked passkey cannot mint', () => {
  const s = setup();
  const svc = enrollService(s);
  s.db.prepare('UPDATE service_credentials SET revoked_at = ? WHERE id = ?').run(new Date().toISOString(), svc.id);
  assert.throws(() => verify(s, svc, request(svc)), /E_SVC_REVOKED/);
});

test('svc: an expired passkey cannot mint', () => {
  const s = setup();
  const svc = enrollService(s, { expiresAt: new Date(Date.now() - 60_000).toISOString() });
  assert.throws(() => verify(s, svc, request(svc)), /E_SVC_EXPIRED/);
});

test('svc: a wrong kid is rejected', () => {
  const s = setup();
  const svc = enrollService(s);
  assert.throws(() => verify(s, svc, request(svc, { kid: 'kdeadbeefdeadbeef' })), /E_SVC_KID/);
});

test('svc: only query.read may be minted', () => {
  const s = setup();
  const svc = enrollService(s);
  assert.throws(() => verify(s, svc, request(svc, { action: 'query.write' })), /E_SVC_ACTION/);
});

test('svc: a request for another connection is rejected', () => {
  const s = setup();
  const svc = enrollService(s);
  assert.throws(() => verify(s, svc, request(svc, { resource: 'db:other' })), /E_SVC_RESOURCE/);
});

test('svc: ttl above the envelope ceiling is rejected', () => {
  const s = setup();
  const svc = enrollService(s, { envelope: { max_ttl: 300 } });
  assert.throws(() => verify(s, svc, request(svc, { ttl: 900 })), /E_SVC_TTL/);
});

test('svc: stale timestamps are rejected', () => {
  const s = setup();
  const svc = enrollService(s);
  assert.throws(() => verify(s, svc, request(svc, { ts: NOW - 600 })), /E_SVC_CLOCK/);
});

test('svc: the daily quota is enforced', () => {
  const s = setup();
  const svc = enrollService(s, { envelope: { daily_quota: 1 } });
  verify(s, svc, request(svc));
  assert.throws(() => verify(s, svc, request(svc)), /E_SVC_QUOTA/);
});

test('svc: the gateway stores no private key material', () => {
  const s = setup();
  const svc = enrollService(s);
  const row = s.db.prepare('SELECT * FROM service_credentials WHERE id = ?').get(svc.id);
  const raw = JSON.stringify(row);
  assert.equal(raw.includes('PRIVATE KEY'), false);
  assert.equal(raw.includes('dbg_'), false);
  assert.equal(typeof JSON.parse(row.public_key_jwk).kty, 'string');
});

test('svc: the legacy bearer prefix is gone from the codebase', async () => {
  const { readFileSync } = await import('node:fs');
  const files = ['src/cli.js', 'src/crypto.js', 'src/query.js', 'src/store.js'];
  for (const f of files) {
    assert.equal(readFileSync(f, 'utf8').includes('dbg_'), false, `${f} still references dbg_`);
  }
});
