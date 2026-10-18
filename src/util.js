import crypto from 'node:crypto';

export const nowIso = () => new Date().toISOString();
export const nowMs = () => Date.now();

/** Prefixed opaque id. */
export function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('base64url')}`;
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

export function fromB64url(input) {
  return Buffer.from(input, 'base64url');
}

/** Stable key order so hashes are reproducible across engines. */
export function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/** Typed error with a stable machine code, surfaced in the message for cheap matching. */
export class GatewayError extends Error {
  constructor(code, message, details) {
    super(`[${code}] ${message}`);
    this.name = 'GatewayError';
    this.code = code;
    this.details = details ?? null;
  }
}

/** Parse `900`, `15m`, `30d` into seconds. */
export function parseTtl(input, fallbackSeconds = 900) {
  if (input === undefined || input === null || input === '') return fallbackSeconds;
  if (typeof input === 'number') return input;
  const m = String(input).trim().match(/^(\d+)\s*(s|m|h|d)?$/i);
  if (!m) throw new GatewayError('E_TTL', `invalid ttl: ${input}`);
  const n = Number(m[1]);
  const unit = (m[2] || 's').toLowerCase();
  const mult = unit === 's' ? 1 : unit === 'm' ? 60 : unit === 'h' ? 3600 : 86400;
  return n * mult;
}

/** Truncate a SQL string into a shape summary safe to store: keywords only. */
export function queryShape(sql) {
  const words = String(sql)
    .replace(/'[^']*'/g, '?')
    .replace(/"[^"]*"/g, '?')
    .replace(/`[^`]*`/g, '?')
    .match(/\b[a-z_]+\b/gi);
  if (!words) return '';
  return words.slice(0, 24).join(' ').toLowerCase();
}
