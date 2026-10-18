import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_REGISTRY, PII, setup } from './helpers.js';
import { REDACTED, applyStrategy, detectPii, loadRegistryIndex, maskRows } from '../src/masking.js';

function registryOf(s) {
  return loadRegistryIndex(s.db, s.connId);
}

test('masking: identical inputs produce the same hash, different salts do not', () => {
  const a = applyStrategy('hash', '12-3456789-0', { salt: 's1' });
  const b = applyStrategy('hash', '12-3456789-0', { salt: 's1' });
  const c = applyStrategy('hash', '12-3456789-0', { salt: 's2' });
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.equal(a.length, 16);
});

test('masking: strategies', () => {
  assert.equal(applyStrategy('redact', 'x'), REDACTED);
  assert.equal(applyStrategy('null', 'x'), null);
  assert.equal(applyStrategy('mask', 'juan@example.com'), 'j***@e***.com');
  assert.equal(applyStrategy('mask', '1234567890'), '***90');
  assert.equal(applyStrategy('mask', 'J'), '***');
});

test('masking: direct column is masked by lineage', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ employee_id: 'emp-1', email: PII.email }],
    fields: ['employee_id', 'email'],
    sql: 'select employee_id, email from employee',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].email, REDACTED);
  assert.equal(out.rows[0].employee_id, 'emp-1');
  assert.ok(out.maskedColumns.some((m) => m.column === 'email' && m.matchedBy === 'lineage'));
});

test('masking: aliased column is masked by lineage', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ e: PII.email }],
    fields: ['e'],
    sql: 'select email as e from employee',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].e, REDACTED);
});

test('masking: wrapped and concatenated columns are masked', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ full: `${PII.first} Dela Cruz` }],
    fields: ['full'],
    sql: "select concat(first_name, ' ', last_name) as full from employee",
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].full, REDACTED);
});

test('masking: star query is masked by column name', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ employee_id: 'emp-1', email: PII.email, sss_no: PII.sss }],
    fields: ['employee_id', 'email', 'sss_no'],
    sql: 'select * from employee',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].email, REDACTED);
  assert.notEqual(out.rows[0].sss_no, PII.sss);
  assert.equal(out.rows[0].sss_no.length, 16);
});

test('masking: unresolvable SQL still masks by name — it never blocks', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ email: PII.email }],
    fields: ['email'],
    sql: 'select "unterminated from employee',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].email, REDACTED);
});

test('masking: a star over a derived table cannot launder a masked column', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ x: PII.first }],
    fields: ['x'],
    sql: 'select * from (select first_name as x from employee) t',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].x, REDACTED);
});

test('masking: two derived tables exposing the same output name do not erase each other', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ x: PII.first }],
    fields: ['x'],
    sql: "select x from (select first_name as x from employee) a, (select 1 as x from employee) b",
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].x, REDACTED);
});

test('masking: a derived-table alias cannot launder a masked column', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ x: PII.first }],
    fields: ['x'],
    sql: 'select x from (select first_name as x from employee) t',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].x, REDACTED);
});

test('masking: a CTE alias cannot launder a masked column', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ x: PII.first }],
    fields: ['x'],
    sql: 'with t as (select first_name as x from employee) select x from t',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].x, REDACTED);
});

test('masking: a UNION branch cannot launder a masked column', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ n: PII.first }],
    fields: ['n'],
    sql: 'select 1 as n from employee union select first_name from employee',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].n, REDACTED);
});

test('masking: an unmapped personal-data column is flagged but not masked', () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const out = maskRows({
    rows: [{ contact_email_2: 'someone@example.com' }],
    fields: ['contact_email_2'],
    sql: 'select contact_email_2 from employee',
    registry: registryOf(s),
    salt: 'salt',
  });
  assert.equal(out.rows[0].contact_email_2, 'someone@example.com');
  assert.equal(out.maskedColumns.length, 0);
  assert.ok(out.flagged.some((f) => f.column === 'contact_email_2' && f.detector === 'email'));
});

test('detector: recognises names and values, and never throws', () => {
  const byName = detectPii({ fields: ['sss_no'], rows: [] });
  assert.equal(byName[0].detector, 'gov_id');
  const byValue = detectPii({ fields: ['col_1'], rows: [{ col_1: 'a@b.co' }] });
  assert.equal(byValue[0].detector, 'email');
  assert.deepEqual(detectPii({ fields: [], rows: [] }), []);
});
