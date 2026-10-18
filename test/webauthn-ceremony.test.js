import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { openPlatformDb } from '../core/db.js';
import {
  beginAuthentication,
  beginRegistration,
  finishAuthentication,
  finishRegistration,
} from '../core/webauthn.js';
import { VirtualAuthenticator } from './virtual-authenticator.js';

process.env.AT_RP_ID = 'localhost';
process.env.AT_ORIGIN = 'http://localhost:8443';

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'at-ceremony-'));
  const { db } = openPlatformDb(dir);
  const userId = 'usr_ceremony';
  db.prepare(
    `INSERT INTO users (id, username, display_name, role, status, created_at)
     VALUES (?,?,?,?, 'active', ?)`,
  ).run(userId, 'ceremony', 'Ceremony', 'owner', new Date().toISOString());
  return { db, user: db.prepare('SELECT * FROM users WHERE id = ?').get(userId) };
}

test('webauthn: a real registration ceremony verifies and stores the credential', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });

  const options = await beginRegistration(db, user);
  const result = await finishRegistration(db, user, authenticator.registrationResponse(options));
  assert.equal(result.verified, true);

  const stored = db.prepare('SELECT * FROM webauthn_creds WHERE user_id = ?').all(user.id);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].credential_id, authenticator.id);
  assert.equal(stored[0].counter, 0);
});

test('webauthn: a real assertion verifies and advances the counter', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });
  await finishRegistration(db, user, authenticator.registrationResponse(await beginRegistration(db, user)));

  const { options } = await beginAuthentication(db, user.username);
  const { user: authed, verification } = await finishAuthentication(db, authenticator.assertionResponse(options));

  assert.equal(authed.id, user.id);
  assert.equal(verification.verified, true);
  const stored = db.prepare('SELECT counter FROM webauthn_creds WHERE credential_id = ?').get(authenticator.id);
  assert.equal(stored.counter, 1);
});

test('webauthn: a challenge is single use', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });
  const options = await beginRegistration(db, user);
  const response = authenticator.registrationResponse(options);
  await finishRegistration(db, user, response);
  await assert.rejects(() => finishRegistration(db, user, response), /E_CHALLENGE/);
});

test('webauthn: the wrong origin is rejected', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://evil.example' });
  const options = await beginRegistration(db, user);
  await assert.rejects(
    () => finishRegistration(db, user, authenticator.registrationResponse(options)),
    /E_WEBAUTHN/,
  );
});

test('webauthn: user verification is required', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });
  await finishRegistration(db, user, authenticator.registrationResponse(await beginRegistration(db, user)));

  const { options } = await beginAuthentication(db, user.username);
  await assert.rejects(
    () => finishAuthentication(db, authenticator.assertionResponse(options, { userVerification: false })),
    /E_WEBAUTHN/,
  );
});

test('webauthn: an assertion signed by another key is rejected', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });
  await finishRegistration(db, user, authenticator.registrationResponse(await beginRegistration(db, user)));

  const { options } = await beginAuthentication(db, user.username);
  const forged = authenticator.assertionResponse(options);
  // Re-sign nothing: swap the signature for random bytes.
  forged.response.signature = crypto.randomBytes(70).toString('base64url');
  await assert.rejects(() => finishAuthentication(db, forged), /E_WEBAUTHN/);
});

test('webauthn: an assertion for a different credential id is rejected', async () => {
  const { db, user } = fixture();
  const authenticator = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });
  await finishRegistration(db, user, authenticator.registrationResponse(await beginRegistration(db, user)));

  const { options } = await beginAuthentication(db, user.username);
  const other = new VirtualAuthenticator({ rpID: 'localhost', origin: 'http://localhost:8443' });
  await assert.rejects(() => finishAuthentication(db, other.assertionResponse(options)), /E_CREDENTIAL|E_WEBAUTHN/);
});

test('webauthn: an unknown username gets a decoy, not an empty allow list', async () => {
  const { db } = fixture();
  const known = await beginAuthentication(db, 'ceremony');
  const unknown = await beginAuthentication(db, 'nobody-here');
  assert.equal(known.options.allowCredentials.length, 1);
  assert.equal(unknown.options.allowCredentials.length, 1);
  assert.notEqual(known.options.allowCredentials[0].id, unknown.options.allowCredentials[0].id);
});
