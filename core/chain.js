import crypto from 'node:crypto';

export const GENESIS = '0'.repeat(64);

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

export function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * Append an auth event and hash-chain it. The chain is the local tamper evidence: editing
 * or removing any existing row breaks verification from that point on.
 */
export function appendEvent(db, event) {
  const payload = {
    ts: event.ts || new Date().toISOString(),
    user_id: event.userId ?? null,
    event: event.event,
    factor: event.factor ?? null,
    result: event.result ?? 'ok',
    ip: event.ip ?? null,
    detail: event.detail ?? null,
  };
  const prev =
    db.prepare('SELECT row_hash FROM auth_events ORDER BY seq DESC LIMIT 1').get()?.row_hash || GENESIS;
  const rowHash = sha256Hex(`${prev}${canonicalJson(payload)}`);
  db.prepare(
    `INSERT INTO auth_events (ts, user_id, event, factor, result, ip, detail, prev_hash, row_hash)
     VALUES (?,?,?,?,?,?,?,?,?)`,
  ).run(
    payload.ts,
    payload.user_id,
    payload.event,
    payload.factor,
    payload.result,
    payload.ip,
    payload.detail,
    prev,
    rowHash,
  );
  return rowHash;
}

export function verifyChain(db) {
  const rows = db.prepare('SELECT * FROM auth_events ORDER BY seq ASC').all();
  let prev = GENESIS;
  for (const row of rows) {
    if (row.prev_hash !== prev) return { ok: false, brokenAt: row.seq, checked: rows.length };
    const expected = sha256Hex(
      `${prev}${canonicalJson({
        ts: row.ts,
        user_id: row.user_id,
        event: row.event,
        factor: row.factor,
        result: row.result,
        ip: row.ip,
        detail: row.detail,
      })}`,
    );
    if (expected !== row.row_hash) return { ok: false, brokenAt: row.seq, checked: rows.length };
    prev = row.row_hash;
  }
  return { ok: true, brokenAt: null, checked: rows.length };
}
