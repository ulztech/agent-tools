#!/usr/bin/env node
import { parseArgs } from 'node:util';
import crypto from 'node:crypto';
import path from 'node:path';
import { dataDir, openPlatformDb } from './db.js';
import { issueInvite } from './invites.js';
import { loadMasterKey } from './secretbox.js';
import { createPlatformServer } from './server.js';
import { createAuthzServer } from './authz.js';

const OPTIONS = {
  data: { type: 'string' },
  username: { type: 'string' },
  role: { type: 'string' },
  'display-name': { type: 'string' },
  ttl: { type: 'string' },
  port: { type: 'string' },
  host: { type: 'string' },
};

function out(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function fail(code, message) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: code, message }, null, 2)}\n`);
  process.exitCode = 1;
}

function open(values) {
  const dir = path.resolve(values.data || process.env.AT_DATA || dataDir());
  return openPlatformDb(dir);
}


async function main() {
  const { values, positionals } = parseArgs({ options: OPTIONS, allowPositionals: true, strict: true });
  const [command, sub] = positionals;

  if (command === 'init') {
    const { db, dir } = open(values);
    const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    if (count > 0) {
      db.close();
      return fail('E_INITIALISED', 'this platform already has users; use `invite` instead');
    }
    loadMasterKey(dir);
    const username = values.username || 'owner';
    const invite = issueInvite(db, { username, role: 'owner', displayName: values['display-name'] });
    const port = Number(values.port || 8443);
    out({
      ok: true,
      data_dir: dir,
      ...invite,
      enroll_path: `/enroll?token=${invite.token}`,
      next: `start the console, then open http://localhost:${port}/enroll?token=${invite.token}`,
    });
    db.close();
    return undefined;
  }

  if (command === 'invite') {
    const { db } = open(values);
    const username = values.username;
    if (!username) {
      db.close();
      return fail('E_USAGE', 'invite requires --username');
    }
    const role = values.role || 'member';
    if (!['owner', 'admin', 'auditor', 'member'].includes(role)) {
      db.close();
      return fail('E_ROLE', `unknown role: ${role}`);
    }
    const invite = issueInvite(db, {
      username,
      role,
      displayName: values['display-name'],
      ttlMinutes: Number(values.ttl || 60),
    });
    out({ ok: true, ...invite, enroll_path: `/enroll?token=${invite.token}` });
    db.close();
    return undefined;
  }

  if (command === 'users') {
    const { db } = open(values);
    out(
      db
        .prepare(
          `SELECT u.username, u.role, u.status, u.last_login_at,
                  (SELECT COUNT(*) FROM webauthn_creds c WHERE c.user_id = u.id) AS passkeys,
                  u.totp_confirmed_at IS NOT NULL AS totp
             FROM users u ORDER BY u.username`,
        )
        .all(),
    );
    db.close();
    return undefined;
  }

  if (command === 'serve') {
    const { db, dir } = open(values);
    const masterKey = loadMasterKey(dir);
    const port = Number(values.port || process.env.AT_PORT || 8443);
    const host = values.host || '127.0.0.1';
    const server = createPlatformServer({ db, masterKey });
    await new Promise((resolve) => server.listen(port, host, resolve));

    // The forward-auth endpoint gets its own listener so a proxy on the application
    // network can reach /authz and nothing else.
    const authzPort = Number(values['authz-port'] || process.env.AT_AUTHZ_PORT || 8444);
    const authzHost = values['authz-host'] || process.env.AT_AUTHZ_HOST || '0.0.0.0';
    const authz = createAuthzServer({ db });
    await new Promise((resolve) => authz.listen(authzPort, authzHost, resolve));

    out({
      ok: true,
      console: `http://${host}:${port}`,
      authz: `http://${authzHost}:${authzPort}/authz`,
      note: 'console is loopback only. Reach it through WireGuard or an SSH tunnel (D23).',
    });
    return undefined;
  }

  process.stderr.write(
    'usage: node core/cli.js <init|invite|users|serve> [--username --role --data --port]\n',
  );
  process.exitCode = 2;
  return undefined;
}

main().catch((err) => fail(err.code || 'E_UNKNOWN', err.message));
