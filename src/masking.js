import crypto from 'node:crypto';
import { GatewayError, newId, nowIso } from './util.js';
import { analyzeProjection } from './sqlgate.js';

export const STRATEGIES = Object.freeze(['redact', 'mask', 'hash', 'null']);
export const REDACTED = '[REDACTED]';

/* ------------------------------------------------------------------ */
/* Registry (the masking inventory)                                    */
/* ------------------------------------------------------------------ */

export function setRegistryRule(db, { connectionId, table, column, strategy, params = null, enabled = true }) {
  if (!STRATEGIES.includes(strategy)) {
    throw new GatewayError('E_STRATEGY', `unknown strategy: ${strategy}`);
  }
  if (!table || !column) throw new GatewayError('E_REGISTRY', 'table and column are required');
  const existing = db
    .prepare('SELECT id FROM pii_registry WHERE connection_id = ? AND table_name = ? AND column_name = ?')
    .get(connectionId, table, column);
  if (existing) {
    db.prepare(
      'UPDATE pii_registry SET strategy = ?, params = ?, enabled = ?, updated_at = ? WHERE id = ?',
    ).run(strategy, params ? JSON.stringify(params) : null, enabled ? 1 : 0, nowIso(), existing.id);
    return existing.id;
  }
  const id = newId('reg');
  db.prepare(
    `INSERT INTO pii_registry (id, connection_id, table_name, column_name, strategy, params, enabled, updated_at)
     VALUES (?,?,?,?,?,?,?,?)`,
  ).run(id, connectionId, table, column, strategy, params ? JSON.stringify(params) : null, enabled ? 1 : 0, nowIso());
  return id;
}

export function listRegistry(db, connectionId) {
  return db
    .prepare(
      `SELECT table_name, column_name, strategy, params, enabled, updated_at
         FROM pii_registry WHERE connection_id = ? ORDER BY table_name, column_name`,
    )
    .all(connectionId);
}

export function removeRegistryRule(db, { connectionId, table, column }) {
  const info = db
    .prepare('DELETE FROM pii_registry WHERE connection_id = ? AND table_name = ? AND column_name = ?')
    .run(connectionId, table, column);
  return Number(info.changes) > 0;
}

/**
 * Build the lookup used at query time: every masked column name for this connection,
 * keyed by lower-case column name so matching is case-insensitive across engines.
 */
export function loadRegistryIndex(db, connectionId) {
  const rows = db
    .prepare(
      `SELECT table_name, column_name, strategy, params FROM pii_registry
        WHERE connection_id = ? AND enabled = 1`,
    )
    .all(connectionId);
  const byColumn = new Map();
  for (const r of rows) {
    const key = String(r.column_name).toLowerCase();
    const entry = {
      table: r.table_name,
      column: r.column_name,
      strategy: r.strategy,
      params: r.params ? JSON.parse(r.params) : null,
    };
    if (!byColumn.has(key)) byColumn.set(key, []);
    byColumn.get(key).push(entry);
  }
  return { byColumn, size: rows.length };
}

/** The signed masking plan embedded in a capability. */
export function buildRedactionPlan(db, connectionId) {
  const rows = db
    .prepare('SELECT table_name, column_name, strategy FROM pii_registry WHERE connection_id = ? AND enabled = 1')
    .all(connectionId)
    .sort((a, b) => `${a.table_name}.${a.column_name}`.localeCompare(`${b.table_name}.${b.column_name}`));
  const plan = {};
  for (const r of rows) plan[`${r.table_name}.${r.column_name}`] = r.strategy;
  return plan;
}

/* ------------------------------------------------------------------ */
/* Strategies                                                          */
/* ------------------------------------------------------------------ */

function maskEmail(value) {
  const [local, domain] = String(value).split('@');
  const domainHead = domain ? domain.split('.')[0] : '';
  const tld = domain && domain.includes('.') ? `.${domain.split('.').slice(1).join('.')}` : '';
  if (!local || !domainHead) return '***';
  return `${local[0]}***@${domainHead[0]}***${tld}`;
}

function maskGeneric(value) {
  const s = String(value);
  const digits = s.replace(/\D/g, '');
  if (digits.length >= 7) return `***${s.slice(-2)}`;
  if (s.includes('@')) return maskEmail(s);
  if (s.length <= 1) return '***';
  return `${s[0]}***`;
}

function hmac(salt, value) {
  return crypto.createHmac('sha256', salt).update(String(value)).digest('base64url').slice(0, 16);
}

export function applyStrategy(strategy, value, { salt, params } = {}) {
  if (value === null || value === undefined) return value;
  switch (strategy) {
    case 'redact':
      return REDACTED;
    case 'null':
      return null;
    case 'hash':
      if (!salt) throw new GatewayError('E_MASK_SALT', 'hash strategy requires a session salt');
      return hmac(salt, value);
    case 'mask':
      if (params?.style === 'last4') return `***${String(value).slice(-4)}`;
      return String(value).includes('@') ? maskEmail(value) : maskGeneric(value);
    default:
      throw new GatewayError('E_STRATEGY', `unknown strategy: ${strategy}`);
  }
}

/* ------------------------------------------------------------------ */
/* Result shaping                                                      */
/* ------------------------------------------------------------------ */

const STRICTNESS = { redact: 0, null: 1, hash: 2, mask: 3 };

/**
 * Mask a result set.
 *
 * Never throws to signal "cannot mask". Resolution order per output column:
 *   1. lineage from the parsed statement, expanded through derived tables / CTEs / UNION
 *   2. column position in the select list
 *   3. the output column's own name
 *
 * No query is denied here (D18), and an unmapped personal-data column is returned as-is
 * with a detector flag (D16 / AR-8).
 */
export function maskRows({ rows, fields, sql, registry, salt }) {
  const maskedColumns = [];
  const flagged = [];

  let analysis;
  try {
    analysis = analyzeProjection(sql);
  } catch {
    analysis = { star: true, byOutput: new Map(), byPosition: [], branches: [] };
  }

  const keys =
    Array.isArray(fields) && fields.length > 0
      ? fields
      : rows.length > 0
        ? Object.keys(rows[0])
        : [];

  const rulesFor = (columnName, index) => {
    const found = [];
    const seen = new Set();

    const collect = (names, matchedBy) => {
      for (const raw of names || []) {
        const key = String(raw).toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        const rules = registry.byColumn.get(key);
        if (rules) for (const r of rules) found.push({ ...r, matchedBy });
      }
    };

    // Transitive lookup through derived tables / CTEs. This is what catches
    // `select * from (select first_name as x from employee) t`, where the outer star
    // produces an output called `x` that appears nowhere in the registry.
    const expandDerived = (start) => {
      const out = new Set();
      const queue = [...start];
      let hops = 0;
      while (queue.length && hops < 6) {
        const next = [];
        for (const raw of queue) {
          const key = String(raw).toLowerCase();
          if (out.has(key)) continue;
          out.add(key);
          const inner = analysis.derived?.get(key);
          if (inner) next.push(...inner);
        }
        queue.length = 0;
        queue.push(...next);
        hops += 1;
      }
      return out;
    };

    collect(analysis.byOutput?.get(String(columnName).toLowerCase()), 'lineage');
    if (found.length === 0) collect(analysis.byPosition?.[index], 'lineage');
    if (found.length === 0) collect(expandDerived([columnName]), 'lineage');
    if (found.length === 0) collect([columnName], 'name');
    return found;
  };

  const masked = rows.map((row) => {
    const next = { ...row };
    keys.forEach((key, index) => {
      if (!(key in next)) return;
      const rules = rulesFor(key, index);
      if (rules.length === 0) return;
      const rule = [...rules].sort((a, b) => STRICTNESS[a.strategy] - STRICTNESS[b.strategy])[0];
      next[key] = applyStrategy(rule.strategy, next[key], { salt, params: rule.params });
      if (!maskedColumns.some((m) => m.column === key)) {
        maskedColumns.push({ column: key, strategy: rule.strategy, matchedBy: rule.matchedBy });
      }
    });
    return next;
  });

  // Detector: audit-only. Never masks, never blocks.
  for (const f of detectPii({ fields: keys, rows })) {
    if (!maskedColumns.some((m) => m.column.toLowerCase() === f.column.toLowerCase())) flagged.push(f);
  }

  return { rows: masked, maskedColumns, flagged };
}

/* ------------------------------------------------------------------ */
/* PII detector (audit only)                                           */
/* ------------------------------------------------------------------ */

const NAME_PATTERNS = [
  { detector: 'email', re: /e?mail/i },
  { detector: 'phone', re: /(phone|mobile|contact_no|cellphone)/i },
  { detector: 'name', re: /(first_name|last_name|middlename|full_?name|surname)/i },
  { detector: 'birthdate', re: /(birth|dob|birthdate)/i },
  { detector: 'address', re: /(address|street|barangay|city|province|zip)/i },
  { detector: 'gov_id', re: /(sss|philhealth|pagibig|pag-ibig|tin|umid|passport|national_id)/i },
  { detector: 'bank_account', re: /(bank|account_no|acct_no|iban|swift)/i },
  { detector: 'salary', re: /(salary|basic_pay|compensation|wage|rate)/i },
];

const VALUE_PATTERNS = [
  { detector: 'email', re: /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i },
  { detector: 'phone', re: /^(\+?\d{1,3}[\s-]?)?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{3,4}$/ },
  { detector: 'gov_id', re: /^\d{2}-\d{7}-\d{1}$|^\d{12}$|^\d{3}-\d{3}-\d{3}-\d{3}$/ },
];

/**
 * Flag columns that look like personal data. Deliberately advisory: the returned flags
 * are written to the audit trail so registry drift is visible, but they never mask and
 * never block (D16).
 */
export function detectPii({ fields, rows }) {
  const out = [];
  for (const field of fields || []) {
    const nameHit = NAME_PATTERNS.find((p) => p.re.test(field));
    if (nameHit) {
      out.push({ column: field, detector: nameHit.detector, reason: 'column-name' });
      continue;
    }
    const sample = (rows || []).map((r) => r[field]).find((v) => typeof v === 'string' && v.length > 0);
    if (!sample) continue;
    const valueHit = VALUE_PATTERNS.find((p) => p.re.test(sample));
    if (valueHit) out.push({ column: field, detector: valueHit.detector, reason: 'value-pattern' });
  }
  return out;
}
