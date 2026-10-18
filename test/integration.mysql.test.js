import test from 'node:test';
import assert from 'node:assert/strict';
import { createMysqlDriver } from '../src/drivers.js';

/**
 * Opt-in integration test. Skipped by default so `npm test` stays dependency-free.
 *
 *   AGENT_TOOLS_TEST_MYSQL=1 MYSQL_HOST=127.0.0.1 MYSQL_USER=... MYSQL_PASSWORD=... \
 *   MYSQL_DATABASE=... npm run test:integration
 */
const enabled = process.env.AGENT_TOOLS_TEST_MYSQL === '1';

test('mysql: the adapter connects and returns a result shape', { skip: !enabled }, async () => {
  const driver = await createMysqlDriver({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
  });
  try {
    const result = await driver.query({ sql: 'select 1 as one', params: [], maxRows: 1 });
    assert.deepEqual(result.fields, ['one']);
    assert.equal(Number(result.rows[0].one), 1);
  } finally {
    await driver.close();
  }
});
