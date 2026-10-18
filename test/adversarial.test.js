import test from 'node:test';
import assert from 'node:assert/strict';
import { runQuery } from '../src/query.js';
import { verifyAudit } from '../src/store.js';
import { CONNECTION, DEFAULT_REGISTRY, PII, mint, setup, smartStub } from './helpers.js';

/**
 * Paired assertion (plan I8): for every payload the gateway either
 *   - returns a row set with no personal-data value in it (allow), or
 *   - refuses a non-read statement at the gate (deny),
 * and never the third thing: a denial caused by masking uncertainty.
 */

const ALLOW = [
  ['direct', 'select employee_id, email from employee'],
  ['single', 'select email from employee'],
  ['alias', 'select email as e from employee'],
  ['qualified alias', 'select e.email as x from employee e'],
  ['upper', 'select upper(email) as up from employee'],
  ['lower', 'select lower(email) from employee'],
  ['concat', "select concat(first_name, ' ', last_name) as full from employee"],
  ['concat_ws', "select concat_ws(' ', first_name, last_name) as full from employee"],
  ['replace', "select replace(email, '@', '_at_') as obf from employee"],
  ['substring', 'select substring(email, 1, 3) as pre from employee'],
  ['coalesce', "select coalesce(email, 'none') as em from employee"],
  ['ifnull', "select ifnull(email, '') as ie from employee"],
  ['trim', 'select trim(email) as te from employee'],
  ['case', "select case when email is null then 'x' else email end as c from employee"],
  ['cast', 'select cast(sss_no as char) as c2 from employee'],
  ['star', 'select * from employee'],
  ['table star', 'select employee.* from employee'],
  ['non pii', 'select employee_id from employee'],
  ['count', 'select count(*) as n from employee'],
  ['avg', 'select avg(salary) as a from employee'],
  ['max', 'select max(salary) as m from employee'],
  ['two pii', 'select email, sss_no from employee'],
  ['qualified pii', 'select s.sss_no as s2 from employee s'],
  ['distinct', 'select distinct email from employee'],
  ['where literal', "select email from employee where email = 'x@y.com'"],
  ['like', "select email from employee where email like '%@%'"],
  ['order by', 'select email from employee order by email'],
  ['group by', 'select email from employee group by email'],
  ['having', 'select email from employee having count(*) > 0'],
  ['limit', 'select email from employee limit 1'],
  ['subquery', 'select (select email from employee limit 1) as sub'],
  ['union', 'select email from employee union select email from employee'],
  ['group_concat', 'select group_concat(email) as gc from employee'],
  ['json_object', "select json_object('e', email) as j from employee"],
  ['trailing semicolon', 'select email from employee;'],
  ['nested expr', 'select id, upper(substring(email, 1, 3)) as p from employee'],
  ['cte', 'with x as (select email from employee) select email from x'],
  ['backticked', 'select `email` from employee'],
  ['quoted alias', 'select email as "E" from employee'],
  ['implicit alias', 'select concat(first_name, last_name) nm from employee'],
  ['filtered', "select email from employee where first_name = 'Juan'"],
  ['constant', 'select 1 as one'],
  ['show', 'show tables'],
  ['describe', 'describe employee'],
  ['explain', 'explain select email from employee'],
  ['is not null', 'select e.email as x from employee e where e.email is not null'],
  ['three columns', 'select id, email, first_name from employee'],
];

const DENY = [
  'insert into employee values (1)',
  "update employee set email = 'x'",
  'delete from employee',
  'drop table employee',
  'alter table employee add column x int',
  'create table x (a int)',
  'truncate table employee',
  'replace into employee values (1)',
  'grant select on *.* to x',
  'revoke select on *.* from x',
  'set @a = 1',
  'call proc()',
  'handler employee open',
  'lock tables employee read',
  'unlock tables',
  "select email from employee into outfile '/tmp/x'",
  "select load_file('/etc/passwd')",
  'select email from employee; drop table employee',
  'select email from employee -- trailing',
  'select email from employee /* block */',
  'sel/**/ect email from employee',
  'select email from employee # hash',
  'select @x := email from employee',
  'select email from information_schema.columns',
  'select email from mysql.user',
  'select sleep(10)',
  "prepare s from 'select 1'",
  'select email from employee for update',
  "select get_lock('x', 1)",
  "select email from employee union select email from employee into outfile '/tmp/y'",
  'select 1;;',
  '',
];

const PII_VALUES = [PII.email, PII.first, PII.sss];

test('adversarial: every allowed read returns rows and leaks no personal data', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const failures = [];

  for (const [name, sql] of ALLOW) {
    const { token } = mint(s.signing);
    try {
      const result = await runQuery({
        db: s.db,
        masterKey: s.masterKey,
        publicKey: s.signing.publicKey,
        kid: s.signing.kid,
        connectionName: CONNECTION,
        token,
        sql,
        driverFactory: () => smartStub(sql),
      });
      if (!Array.isArray(result.rows) || result.rows.length === 0) {
        failures.push(`${name}: returned no rows`);
        continue;
      }
      const raw = JSON.stringify(result);
      for (const value of PII_VALUES) {
        if (raw.includes(value)) failures.push(`${name}: leaked ${JSON.stringify(value)}`);
      }
    } catch (err) {
      failures.push(`${name}: was refused (${err.code ?? err.message}) — a read must never be blocked`);
    }
  }

  assert.deepEqual(failures, [], `allowed reads must return masked rows:\n${failures.join('\n')}`);
  assert.equal(verifyAudit(s.db).ok, true);
});

test('adversarial: every non-read is refused by the gate', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  const failures = [];

  for (const sql of DENY) {
    const { token } = mint(s.signing);
    try {
      await runQuery({
        db: s.db,
        masterKey: s.masterKey,
        publicKey: s.signing.publicKey,
        kid: s.signing.kid,
        connectionName: CONNECTION,
        token,
        sql,
        driverFactory: () => smartStub('select 1 as one'),
      });
      failures.push(`${JSON.stringify(sql)}: was allowed`);
    } catch (err) {
      if (!/^E_SQL_/.test(err.code ?? '')) {
        failures.push(`${JSON.stringify(sql)}: wrong error ${err.code ?? err.message}`);
      }
    }
  }

  assert.deepEqual(failures, [], `non-reads must be refused:\n${failures.join('\n')}`);
  assert.equal(verifyAudit(s.db).ok, true);
});

test('adversarial: the audit trail holds no personal data after the whole suite', async () => {
  const s = setup({ registry: DEFAULT_REGISTRY });
  for (const [, sql] of ALLOW) {
    const { token } = mint(s.signing);
    await runQuery({
      db: s.db,
      masterKey: s.masterKey,
      publicKey: s.signing.publicKey,
      kid: s.signing.kid,
      connectionName: CONNECTION,
      token,
      sql,
      driverFactory: () => smartStub(sql),
    });
  }
  const raw = JSON.stringify(s.db.prepare('SELECT * FROM audit_events').all());
  for (const value of PII_VALUES) assert.equal(raw.includes(value), false);
  assert.equal(verifyAudit(s.db).ok, true);
});

test('adversarial: payload coverage is at least 40', () => {
  assert.ok(ALLOW.length + DENY.length >= 40, `only ${ALLOW.length + DENY.length} payloads`);
});
