import crypto from 'node:crypto';

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

export function cbor(value) {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const b = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return Buffer.concat(parts);
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  }
  throw new Error('cbor: unsupported value');
}

const b64 = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

/**
 * A minimal software authenticator: enough of the WebAuthn data structures to exercise
 * the real @simplewebauthn/server verification path (ES256, 'none' attestation, UV set).
 * This is a test fixture, not a general implementation.
 */
export class VirtualAuthenticator {
  constructor({ rpID, origin, credentialId = crypto.randomBytes(16) }) {
    this.rpID = rpID;
    this.origin = origin;
    this.credentialId = credentialId;
    this.counter = 0;
    this.keys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  }

  get id() {
    return b64(this.credentialId);
  }

  coseKey() {
    const jwk = this.keys.publicKey.export({ format: 'jwk' });
    return new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x, 'base64url')],
      [-3, Buffer.from(jwk.y, 'base64url')],
    ]);
  }

  registrationResponse(options) {
    const flags = 0x45; // UP | UV | AT
    const authData = Buffer.concat([
      sha256(Buffer.from(this.rpID)),
      Buffer.from([flags]),
      Buffer.alloc(4),
      Buffer.alloc(16),
      (() => {
        const b = Buffer.alloc(2);
        b.writeUInt16BE(this.credentialId.length);
        return b;
      })(),
      this.credentialId,
      cbor(this.coseKey()),
    ]);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin: this.origin,
        crossOrigin: false,
      }),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64(clientDataJSON),
        attestationObject: b64(cbor({ fmt: 'none', attStmt: {}, authData })),
        transports: ['internal'],
      },
    };
  }

  assertionResponse(options, { userVerification = true } = {}) {
    this.counter += 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const flags = 0x01 | (userVerification ? 0x04 : 0x00); // UP | UV
    const authData = Buffer.concat([sha256(Buffer.from(this.rpID)), Buffer.from([flags]), counter]);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge,
        origin: this.origin,
        crossOrigin: false,
      }),
    );
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.keys.privateKey);
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64(clientDataJSON),
        authenticatorData: b64(authData),
        signature: b64(signature),
        userHandle: null,
      },
    };
  }
}
