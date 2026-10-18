import crypto from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { credentialsFor, findUser, userById } from './db.js';

export function rpConfig() {
  return {
    rpID: process.env.AT_RP_ID || 'localhost',
    rpName: process.env.AT_RP_NAME || 'Agent-tools',
    origin: process.env.AT_ORIGIN || 'http://localhost:8443',
  };
}

export class AuthError extends Error {
  constructor(code, message) {
    super(`[${code}] ${message}`);
    this.code = code;
  }
}

function storeChallenge(db, { challenge, userId, type, ttlMs = 5 * 60_000 }) {
  const now = new Date().toISOString();
  db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(now);
  // Bound the table: /auth/options is unauthenticated, so without a cap a caller could
  // grow it without limit.
  db.prepare(
    `DELETE FROM challenges WHERE challenge IN (
       SELECT challenge FROM challenges ORDER BY created_at DESC LIMIT -1 OFFSET 2000
     )`,
  ).run();
  db.prepare(
    `INSERT OR REPLACE INTO challenges (challenge, user_id, type, created_at, expires_at, used_at)
     VALUES (?,?,?,?,?,NULL)`,
  ).run(challenge, userId, type, now, new Date(Date.now() + ttlMs).toISOString());
}

/** Single use: the row is consumed before verification, so a replay finds nothing. */
function takeChallenge(db, challenge, type) {
  const row = db.prepare('SELECT * FROM challenges WHERE challenge = ?').get(String(challenge || ''));
  if (!row || row.type !== type || row.used_at) return null;
  if (Date.parse(row.expires_at) < Date.now()) return null;
  db.prepare('UPDATE challenges SET used_at = ? WHERE challenge = ?').run(new Date().toISOString(), row.challenge);
  return row;
}

function clientData(response) {
  const json = Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8');
  const parsed = JSON.parse(json);
  return { challenge: parsed.challenge, origin: parsed.origin, type: parsed.type };
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

export async function beginRegistration(db, user) {
  const { rpID, rpName } = rpConfig();
  const creds = credentialsFor(db, user.id);
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.username,
    userDisplayName: user.display_name || user.username,
    attestationType: 'none',
    excludeCredentials: creds.map((c) => ({
      id: c.credential_id,
      transports: JSON.parse(c.transports || '[]'),
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
  });
  storeChallenge(db, { challenge: options.challenge, userId: user.id, type: 'registration' });
  return options;
}

export async function finishRegistration(db, user, response) {
  const { rpID, origin } = rpConfig();
  const cd = clientData(response);
  const stored = takeChallenge(db, cd.challenge, 'registration');
  if (!stored || stored.user_id !== user.id) {
    throw new AuthError('E_CHALLENGE', 'registration challenge is unknown, expired or already used');
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: cd.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (err) {
    throw new AuthError('E_WEBAUTHN', `registration failed: ${err.message}`);
  }
  if (!verification.verified) throw new AuthError('E_WEBAUTHN', 'registration was not verified');

  const { credential, credentialBackedUp, credentialDeviceType } = verification.registrationInfo;
  db.prepare(
    `INSERT INTO webauthn_creds
       (id, user_id, credential_id, public_key, counter, transports, aaguid,
        backup_eligible, backup_state, nickname, created_at, last_used_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)`,
  ).run(
    `cred_${credential.id.slice(0, 18)}`,
    user.id,
    credential.id,
    Buffer.from(credential.publicKey).toString('base64url'),
    credential.counter,
    JSON.stringify(response.response.transports || []),
    credentialDeviceType || null,
    credentialBackedUp ? 1 : 0,
    credentialBackedUp ? 1 : 0,
    'passkey',
    new Date().toISOString(),
  );

  return verification;
}

/* ------------------------------------------------------------------ */
/* Authentication                                                      */
/* ------------------------------------------------------------------ */

export async function beginAuthentication(db, username) {
  const { rpID } = rpConfig();
  const user = findUser(db, username);
  const usable = user && user.status === 'active';
  const creds = usable ? credentialsFor(db, user.id) : [];

  // Unknown or inactive users get a decoy challenge with no allowed credentials, so the
  // response shape and timing do not reveal whether the account exists. The list is never
  // empty: an empty `allowCredentials` would itself be the oracle.
  const allowCredentials =
    creds.length > 0
      ? creds.map((c) => ({ id: c.credential_id, transports: JSON.parse(c.transports || '[]') }))
      : [{ id: crypto.randomBytes(32).toString('base64url'), type: 'public-key', transports: ['internal'] }];

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    allowCredentials,
  });
  storeChallenge(db, {
    challenge: options.challenge,
    userId: usable ? user.id : null,
    type: 'authentication',
  });
  return { options, user: usable ? user : null };
}

export async function finishAuthentication(db, response) {
  const { rpID, origin } = rpConfig();
  const cd = clientData(response);
  const stored = takeChallenge(db, cd.challenge, 'authentication');
  if (!stored || !stored.user_id) throw new AuthError('E_CHALLENGE', 'authentication challenge is not valid');

  const user = userById(db, stored.user_id);
  if (!user || user.status !== 'active') throw new AuthError('E_USER', 'user is not active');

  const cred = db.prepare('SELECT * FROM webauthn_creds WHERE credential_id = ?').get(response.id);
  if (!cred || cred.user_id !== user.id) throw new AuthError('E_CREDENTIAL', 'credential does not belong to this user');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: cd.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.counter,
        transports: JSON.parse(cred.transports || '[]'),
      },
    });
  } catch (err) {
    throw new AuthError('E_WEBAUTHN', `authentication failed: ${err.message}`);
  }
  if (!verification.verified) throw new AuthError('E_WEBAUTHN', 'authentication was not verified');

  const newCounter = verification.authenticationInfo?.newCounter ?? cred.counter;
  db.prepare('UPDATE webauthn_creds SET counter = ?, last_used_at = ? WHERE credential_id = ?').run(
    newCounter,
    new Date().toISOString(),
    cred.credential_id,
  );

  return { user, verification };
}
