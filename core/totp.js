import crypto from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

/** RFC 4226 HOTP, 6 digits. */
export function hotp(secretB32, counter, digits = 6) {
  const key = base32Decode(secretB32);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totp(secretB32, { now = Date.now(), period = 30 } = {}) {
  return hotp(secretB32, Math.floor(now / 1000 / period));
}

/**
 * Verify a TOTP code with a ±1 step window and replay protection.
 * Returns the matched step (to be stored as `last_step`), or null.
 */
export function verifyTotp(secretB32, code, lastStep = 0, { now = Date.now(), period = 30, window = 1 } = {}) {
  const input = String(code || '').replace(/\D/g, '');
  if (input.length !== 6) return null;
  const current = Math.floor(now / 1000 / period);
  for (let delta = -window; delta <= window; delta += 1) {
    const step = current + delta;
    if (step <= Number(lastStep || 0)) continue;
    const expected = hotp(secretB32, step);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(input))) return step;
  }
  return null;
}

export function otpauthUri({ issuer = 'Agent-tools', account, secret }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
