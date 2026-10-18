import test from 'node:test';
import assert from 'node:assert/strict';
import { assertReadOnly, projectionOf } from '../src/sqlgate.js';

const ALLOWED = [
  'select id from employee',
  'select * from employee',
  'select email from employee;',
  "select email from employee where email = 'a;b'",
  "select email from employee where note = '-- not a comment'",
  'with x as (select email from employee) select email from x',
  'explain select email from employee',
  'describe employee',
  'show tables',
  'show columns from employee',
  'show create table employee',
  'select count(*) from employee',
];

const DENIED = [
  ['insert into employee values (1)', /E_SQL_NOT_READ_ONLY/],
  ['update employee set email = \'x\'', /E_SQL_NOT_READ_ONLY/],
  ['delete from employee', /E_SQL_NOT_READ_ONLY/],
  ['drop table employee', /E_SQL_NOT_READ_ONLY/],
  ['alter table employee add column x int', /E_SQL_NOT_READ_ONLY/],
  ['create table x (a int)', /E_SQL_NOT_READ_ONLY/],
  ['truncate table employee', /E_SQL_NOT_READ_ONLY/],
  ['replace into employee values (1)', /E_SQL_NOT_READ_ONLY/],
  ['grant select on *.* to x', /E_SQL_NOT_READ_ONLY/],
  ['revoke select on *.* from x', /E_SQL_NOT_READ_ONLY/],
  ['set @a = 1', /E_SQL_NOT_READ_ONLY/],
  ['call proc()', /E_SQL_NOT_READ_ONLY/],
  ['handler employee open', /E_SQL_NOT_READ_ONLY/],
  ['lock tables employee read', /E_SQL_NOT_READ_ONLY/],
  ['unlock tables', /E_SQL_NOT_READ_ONLY/],
  ["select email from employee into outfile '/tmp/x'", /E_SQL_NOT_READ_ONLY/],
  ["select load_file('/etc/passwd')", /E_SQL_NOT_READ_ONLY/],
  ['select email from employee; drop table employee', /E_SQL_MULTI/],
  ['select email from employee -- trailing', /E_SQL_COMMENT/],
  ['select email from employee /* block */', /E_SQL_COMMENT/],
  ['sel/**/ect email from employee', /E_SQL_COMMENT/],
  ['select email from employee # hash', /E_SQL_COMMENT/],
  ['select @x := email from employee', /E_SQL_VAR/],
  ['select email from information_schema.columns', /E_SQL_NOT_READ_ONLY/],
  ['select email from mysql.user', /E_SQL_NOT_READ_ONLY/],
  ['select sleep(10)', /E_SQL_NOT_READ_ONLY/],
  ["prepare s from 'select 1'", /E_SQL_NOT_READ_ONLY/],
  ['select email from employee for update', /E_SQL_NOT_READ_ONLY/],
  ["select get_lock('x', 1)", /E_SQL_NOT_READ_ONLY/],
  ["select email from employee where 1=1 union select email from employee into outfile '/tmp/y'", /E_SQL_NOT_READ_ONLY/],
  ['select 1;;', /E_SQL_MULTI/],
  ['', /E_SQL_EMPTY/],
  // backticked identifiers must be denied exactly like bare words
  ["select `load_file`('/etc/passwd')", /E_SQL_NOT_READ_ONLY/],
  ['select * from `mysql`.`user`', /E_SQL_NOT_READ_ONLY/],
  ['select `Password` from `mysql`.`user`', /E_SQL_NOT_READ_ONLY/],
  ['select `sleep`(1)', /E_SQL_NOT_READ_ONLY/],
  ['select * from `information_schema`.`columns`', /E_SQL_NOT_READ_ONLY/],
  ['show processlist', /E_SQL_NOT_READ_ONLY/],
  ['show variables', /E_SQL_NOT_READ_ONLY/],
];

for (const sql of ALLOWED) {
  test(`gate: allows read-only — ${sql}`, () => {
    assert.doesNotThrow(() => assertReadOnly(sql));
  });
}

for (const [sql, pattern] of DENIED) {
  test(`gate: refuses — ${sql}`, () => {
    assert.throws(() => assertReadOnly(sql), pattern);
  });
}

test('gate: unbalanced parentheses are refused', () => {
  assert.throws(() => assertReadOnly('select (1 from employee'), /E_SQL_PARENS/);
});

test('gate: control characters are refused', () => {
  assert.throws(() => assertReadOnly('select\u0000 1'), /E_SQL_CONTROL_CHARS/);
});

test('projection: direct column', () => {
  const p = projectionOf('select email from employee');
  assert.equal(p.star, false);
  assert.deepEqual(p.items[0].sources, ['email']);
  assert.equal(p.items[0].out, 'email');
});

test('projection: alias keeps the source', () => {
  const p = projectionOf('select email as e from employee');
  assert.equal(p.items[0].out, 'e');
  assert.deepEqual(p.items[0].sources, ['email']);
});

test('projection: qualified column', () => {
  const p = projectionOf('select e.email as x from employee e');
  assert.equal(p.items[0].out, 'x');
  assert.ok(p.items[0].sources.includes('email'));
});

test('projection: wrapped expression keeps both sources', () => {
  const p = projectionOf("select concat(first_name, ' ', last_name) as full from employee");
  assert.equal(p.items[0].out, 'full');
  assert.ok(p.items[0].sources.includes('first_name'));
  assert.ok(p.items[0].sources.includes('last_name'));
});

test('projection: implicit alias', () => {
  const p = projectionOf('select concat(first_name, last_name) nm from employee');
  assert.equal(p.items[0].out, 'nm');
  assert.ok(p.items[0].sources.includes('first_name'));
});

test('projection: star is flagged', () => {
  const p = projectionOf('select * from employee');
  assert.equal(p.star, true);
});

test('projection: backticked identifier', () => {
  const p = projectionOf('select `email` from employee');
  assert.equal(p.items[0].out, 'email');
  assert.deepEqual(p.items[0].sources, ['email']);
});

test('projection: multiple columns', () => {
  const p = projectionOf('select employee_id, email, sss_no from employee');
  assert.equal(p.items.length, 3);
  assert.deepEqual(
    p.items.map((i) => i.out),
    ['employee_id', 'email', 'sss_no'],
  );
});
