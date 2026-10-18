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

/**
 * A stable, secret-derived decoy for accounts that have no credential. Regenerating it per
 * request would itself be an oracle: a real credential id is stable across calls.
 */
function decoyCredential(db, username) {
  let key = db.prepare("SELECT value FROM platform_meta WHERE key = 'decoy_key'").get()?.value;
  if (!key) {
    key = crypto.randomBytes(32).toString('base64url');
    db.prepare("INSERT OR IGNORE INTO platform_meta (key, value) VALUES ('decoy_key', ?)").run(key);
  }

  // Match the shape of the credentials actually deployed: a fixed-length, fixed-transport
  // decoy is distinguishable in any estate where real credentials are homogeneous.
  const rows = db.prepare('SELECT credential_id, transports FROM webauthn_creds').all();
  const mode = (values, fallback) => {
    if (values.length === 0) return fallback;
    const counts = new Map();
    for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
  };
  const length = mode(
    rows.map((r) => r.credential_id.length),
    43,
  );
  const transports = JSON.parse(mode(rows.map((r) => r.transports || '["internal"]'), '["internal"]'));

  let id = crypto
    .createHmac('sha256', Buffer.from(key, 'base64url'))
    .update(String(username || '').toLowerCase())
    .digest('base64url');
  while (id.length < length) {
    id += crypto.createHmac('sha256', Buffer.from(key, 'base64url')).update(id).digest('base64url');
  }
  return { id: id.slice(0, length), type: 'public-key', transports };
}

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
      : [decoyCredential(db, username)];

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
