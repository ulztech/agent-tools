import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { GatewayError, b64url, canonicalJson, fromB64url, nowIso, sha256Hex } from './util.js';

const ISSUER = 'agent-tools';
const CAP_TYPE = 'atk-cap';
const ALG = 'ES256';
export const MAX_CAP_TTL = 900;

/* ------------------------------------------------------------------ */
/* Master key + per-tool DEK                                           */
/* ------------------------------------------------------------------ */

/**
 * Master key from the host (`AGENT_TOOLS_MASTER_KEY`, base64, 32 bytes) or, in local
 * development only, a 0600 file under the data dir. Production must supply it from the
 * host keystore — never the vault volume.
 */
export function loadMasterKey(dir) {
  const fromEnv = process.env.AGENT_TOOLS_MASTER_KEY;
  if (fromEnv) {
    const buf = Buffer.from(fromEnv, 'base64');
    if (buf.length !== 32) throw new GatewayError('E_MASTER_KEY', 'AGENT_TOOLS_MASTER_KEY must decode to 32 bytes');
    return buf;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new GatewayError(
      'E_MASTER_KEY',
      'AGENT_TOOLS_MASTER_KEY is required in production — the master key must not live beside the vault',
    );
  }
  const file = path.join(dir, 'master.key');
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
  const buf = crypto.randomBytes(32);
  fs.writeFileSync(file, buf.toString('base64'), { mode: 0o600 });
  return buf;
}

function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(String(aad)));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return { iv: b64url(iv), tag: b64url(cipher.getAuthTag()), ct: b64url(ct) };
}

function open(key, sealed, aad) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, fromB64url(sealed.iv));
  if (aad) decipher.setAAD(Buffer.from(String(aad)));
  decipher.setAuthTag(fromB64url(sealed.tag));
  return Buffer.concat([decipher.update(fromB64url(sealed.ct)), decipher.final()]);
}

export function getToolDek(db, masterKey, toolId) {
  const row = db.prepare('SELECT * FROM tool_keys WHERE tool_id = ?').get(toolId);
  if (row) return open(masterKey, row);
  const dek = crypto.randomBytes(32);
  const sealed = seal(masterKey, dek);
  db.prepare('INSERT INTO tool_keys (tool_id, iv, tag, ct, created_at) VALUES (?,?,?,?,?)').run(
    toolId,
    sealed.iv,
    sealed.tag,
    sealed.ct,
    nowIso(),
  );
  return dek;
}

export function sealWithDek(dek, plaintext, aad) {
  return seal(dek, plaintext, aad);
}

export function openWithDek(dek, sealed, aad) {
  return open(dek, sealed, aad);
}

/* ------------------------------------------------------------------ */
/* ES256 signing key                                                   */
/* ------------------------------------------------------------------ */

function kidFor(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return `k${sha256Hex(der).slice(0, 16)}`;
}

/**
 * Load or create the ES256 signing key. Asymmetric only — there is no HS256 path
 * anywhere in this codebase, and `alg` is never taken from the token header.
 */
export function loadSigningKey(dir) {
  const privFile = path.join(dir, 'signing.key.pem');
  const pubFile = path.join(dir, 'signing.pub.pem');
  let privateKey;
  let publicKey;
  if (fs.existsSync(privFile)) {
    privateKey = crypto.createPrivateKey(fs.readFileSync(privFile, 'utf8'));
    publicKey = crypto.createPublicKey(privateKey);
  } else {
    ({ privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }));
    fs.writeFileSync(privFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(pubFile, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  }
  return { privateKey, publicKey, kid: kidFor(publicKey) };
}

/** JWKS document, so satellites can bake the key set at enrollment. */
export function jwksOf({ publicKey, kid }) {
  const jwk = publicKey.export({ format: 'jwk' });
  return { keys: [{ ...jwk, kid, alg: ALG, use: 'sig' }] };
}

/* ------------------------------------------------------------------ */
/* Capability mint / verify                                            */
/* ------------------------------------------------------------------ */

function signParts(privateKey, header, payload) {
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${b64url(signature)}`;
}

/**
 * Mint a capability. This is only ever called after a human/vault authorisation has
 * already happened — it is not a request-servicing endpoint. `resource` is derived by
 * the caller from the credential, never from the agent.
 */
export function mintCapability({ privateKey, kid, claims, ttlSeconds }) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + Math.floor(ttlSeconds);
  const payload = {
    iss: ISSUER,
    typ: CAP_TYPE,
    cap_id: claims.capId,
    sub: claims.subject,
    res: claims.resource,
    act: claims.action,
    aud: claims.audience,
    sid: claims.sessionRef,
    jti: claims.nonce,
    red: claims.redactionPlan, // signed masking plan
    chp: claims.channelProfile,
    iat,
    exp,
  };
  return { token: signParts(privateKey, { alg: ALG, kid, typ: 'JWT' }, payload), payload };
}

/**
 * Verify a capability. Deterministic and entirely local: key set is baked in, the nonce
 * store is local, and the clock is monotonic-enough (bounded skew). There is no
 * network fetch and therefore no "uncertain" state to fail open on.
 *
 * D20: never-block applies downstream of this function. An invalid capability is
 * refused because there is no authorised result to return — that is not blocking one.
 */
export function verifyCapability({
  db,
  publicKey,
  kid,
  token,
  expectedAudience,
  expectedResource,
  action,
  nowSeconds = Math.floor(Date.now() / 1000),
  skewSeconds = 60,
}) {
  if (typeof token !== 'string') throw new GatewayError('E_CAP_MALFORMED', 'capability must be a string');
  if (!expectedAudience || !expectedResource || !action) {
    throw new GatewayError('E_CAP_POLICY', 'audience, resource and action are all required to verify a capability');
  }
  const parts = token.split('.');
  if (parts.length !== 3) throw new GatewayError('E_CAP_MALFORMED', 'capability is not a compact JWS');

  let header;
  let payload;
  try {
    header = JSON.parse(fromB64url(parts[0]).toString('utf8'));
    payload = JSON.parse(fromB64url(parts[1]).toString('utf8'));
  } catch {
    throw new GatewayError('E_CAP_MALFORMED', 'capability header or payload is not JSON');
  }

  if (header.alg !== ALG) throw new GatewayError('E_CAP_ALG', `unsupported alg: ${header.alg}`);
  if (header.kid !== kid) throw new GatewayError('E_CAP_KID', `unknown kid: ${header.kid}`);
  if (header.typ !== 'JWT') throw new GatewayError('E_CAP_MALFORMED', 'unexpected header typ');

  const ok = crypto.verify(
    'sha256',
    Buffer.from(`${parts[0]}.${parts[1]}`),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    fromB64url(parts[2]),
  );
  if (!ok) throw new GatewayError('E_CAP_SIGNATURE', 'capability signature is invalid');

  if (payload.iss !== ISSUER) throw new GatewayError('E_CAP_ISS', `unexpected issuer: ${payload.iss}`);
  if (payload.typ !== CAP_TYPE) throw new GatewayError('E_CAP_TYPE', 'unexpected capability type');
  if (!Number.isInteger(payload.exp) || !Number.isInteger(payload.iat)) {
    throw new GatewayError('E_CAP_MALFORMED', 'capability is missing iat/exp');
  }
  if (nowSeconds > payload.exp + skewSeconds) throw new GatewayError('E_CAP_EXPIRED', 'capability has expired');
  if (payload.iat > nowSeconds + skewSeconds) throw new GatewayError('E_CAP_NOT_YET', 'capability is not yet valid');
  if (payload.exp - payload.iat > MAX_CAP_TTL + skewSeconds) {
    throw new GatewayError('E_CAP_TTL', `capability ttl exceeds ${MAX_CAP_TTL}s`);
  }

  if (payload.aud !== expectedAudience) {
    throw new GatewayError('E_CAP_AUDIENCE', `capability audience mismatch: ${payload.aud}`);
  }
  if (payload.res !== expectedResource) {
    throw new GatewayError('E_CAP_RESOURCE', `capability resource mismatch: ${payload.res}`);
  }
  if (payload.act !== action) {
    throw new GatewayError('E_CAP_ACTION', `capability action mismatch: ${payload.act}`);
  }

  // Single use. Written atomically; a replay throws a UNIQUE violation.
  try {
    db.prepare('INSERT INTO capability_nonces (nonce, cap_id, expires_at, used_at) VALUES (?,?,?,?)').run(
      payload.jti,
      payload.cap_id,
      payload.exp + skewSeconds,
      nowIso(),
    );
  } catch {
    throw new GatewayError('E_CAP_REPLAY', 'capability nonce has already been used');
  }

  return payload;
}

export function purgeExpiredNonces(db, nowSeconds = Math.floor(Date.now() / 1000)) {
  db.prepare('DELETE FROM capability_nonces WHERE expires_at < ?').run(nowSeconds);
}

/* ------------------------------------------------------------------ */
/* Access keys (machine credential)                                    */
/* ------------------------------------------------------------------ */

export function hashAccessKey(plaintext) {
  return sha256Hex(plaintext);
}

export function thumbprintOf(obj) {
  return sha256Hex(canonicalJson(obj)).slice(0, 16);
}
