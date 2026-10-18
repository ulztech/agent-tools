import test from 'node:test';
import assert from 'node:assert/strict';
import { CONNECTION, TOOL, mint, setup } from './helpers.js';
import { verifyCapability } from '../src/crypto.js';
import { b64url } from '../src/util.js';

function verify(s, token, overrides = {}) {
  return verifyCapability({
    db: s.db,
    publicKey: s.signing.publicKey,
    kid: s.signing.kid,
    token,
    expectedAudience: TOOL,
    expectedResource: `db:${CONNECTION}`,
    action: 'query.read',
    ...overrides,
  });
}

test('capability: a freshly minted token verifies', () => {
  const s = setup();
  const { token, payload } = mint(s.signing);
  const verified = verify(s, token);
  assert.equal(verified.cap_id, payload.cap_id);
  assert.equal(verified.res, `db:${CONNECTION}`);
});

test('capability: alg=none is rejected', () => {
  const s = setup();
  const header = b64url(JSON.stringify({ alg: 'none', kid: s.signing.kid, typ: 'JWT' }));
  const body = b64url(JSON.stringify({ iss: 'agent-tools', typ: 'atk-cap', exp: 9_999_999_999, iat: 1 }));
  assert.throws(() => verify(s, `${header}.${body}.`), /E_CAP_ALG|unsupported alg/);
});

test('capability: HS256 is rejected even when signed with the public key', () => {
  const s = setup();
  const header = b64url(JSON.stringify({ alg: 'HS256', kid: s.signing.kid, typ: 'JWT' }));
  const body = b64url(JSON.stringify({ iss: 'agent-tools', typ: 'atk-cap', exp: 9_999_999_999, iat: 1 }));
  const sig = b64url('signature-made-with-the-public-key');
  assert.throws(() => verify(s, `${header}.${body}.${sig}`), /E_CAP_ALG|unsupported alg/);
});

test('capability: unknown kid is rejected', () => {
  const s = setup();
  const { token } = mint(s.signing);
  assert.throws(() => verify(s, token, { kid: 'kdeadbeefdeadbeef' }), /E_CAP_KID|unknown kid/);
});

test('capability: a tampered payload breaks the signature', () => {
  const s = setup();
  const { token } = mint(s.signing);
  const [h, p, sig] = token.split('.');
  const decoded = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  decoded.res = 'db:other';
  const forged = `${h}.${b64url(JSON.stringify(decoded))}.${sig}`;
  assert.throws(() => verify(s, forged), /E_CAP_SIGNATURE|signature is invalid/);
});

test('capability: single use — replay is rejected', () => {
  const s = setup();
  const { token } = mint(s.signing);
  verify(s, token);
  assert.throws(() => verify(s, token), /E_CAP_REPLAY|already been used/);
});

test('capability: an expired token is rejected', () => {
  const s = setup();
  const { token } = mint(s.signing, { ttl: -600 });
  assert.throws(() => verify(s, token), /E_CAP_EXPIRED|expired/);
});

test('capability: audience mismatch is rejected', () => {
  const s = setup();
  const { token } = mint(s.signing);
  assert.throws(() => verify(s, token, { expectedAudience: 'gmail-gateway' }), /E_CAP_AUDIENCE|audience mismatch/);
});

test('capability: resource mismatch is rejected', () => {
  const s = setup();
  const { token } = mint(s.signing);
  assert.throws(() => verify(s, token, { expectedResource: 'db:other' }), /E_CAP_RESOURCE|resource mismatch/);
});

test('capability: action mismatch is rejected', () => {
  const s = setup();
  const { token } = mint(s.signing);
  assert.throws(() => verify(s, token, { action: 'query.write' }), /E_CAP_ACTION|action mismatch/);
});

test('capability: malformed tokens are rejected', () => {
  const s = setup();
  assert.throws(() => verify(s, 'not-a-token'), /E_CAP_MALFORMED/);
  assert.throws(() => verify(s, 'a.b'), /E_CAP_MALFORMED/);
});
