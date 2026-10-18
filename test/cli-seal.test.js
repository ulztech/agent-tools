import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/store.js';
import { loadMasterKey } from '../src/crypto.js';
import { readConnectionSecret } from '../src/query.js';

/**
 * Regression guard for the AD-mismatch class of bug: a secret written by one entry point
 * must be readable by the other. The CLI seals the connection secret; the data path opens
 * it. If their AAD or key derivation ever drift apart, this fails.
 */
test('cli: a connection created by the CLI can be decrypted by the data path', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tools-cli-'));

  const cli = (...args) => {
    const res = spawnSync(
      process.execPath,
      ['--disable-warning=ExperimentalWarning', '--experimental-sqlite', 'src/cli.js', ...args, '--data', dir],
      { encoding: 'utf8', cwd: process.cwd() },
    );
    assert.equal(res.status, 0, `cli failed: ${res.stderr}`);
    return JSON.parse(res.stdout);
  };

  const init = cli('init');
  assert.ok(init.kid);

  cli(
    'connection',
    'add',
    '--name',
    'smoke',
    '--engine',
    'mysql',
    '--host',
    '127.0.0.1',
    '--port',
    '3306',
    '--user',
    'u',
    '--password',
    'p',
    '--database',
    'd',
  );

  const { db } = openDb(dir);
  const masterKey = loadMasterKey(dir);
  const connection = db.prepare('SELECT * FROM connections WHERE name = ?').get('smoke');
  assert.ok(connection, 'connection row exists');

  const secret = readConnectionSecret(db, masterKey, connection);
  assert.equal(secret.user, 'u');
  assert.equal(secret.password, 'p');
  assert.equal(secret.database, 'd');

  const raw = JSON.stringify(db.prepare('SELECT * FROM connection_secrets').all());
  assert.equal(raw.includes('"p"'), false, 'the password must not be stored in the clear');
});
