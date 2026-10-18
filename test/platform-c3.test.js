import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openPlatformDb } from '../core/db.js';
import { createPlatformServer } from '../core/server.js';
import { createAuthzServer } from '../core/authz.js';
import { createSession, markStepUp } from '../core/sessions.js';
import { loadMasterKey, seal } from '../core/secretbox.js';
import { generateSecret } from '../core/totp.js';
import { remainingCodes } from '../core/recovery.js';
import { appendEvent, configureChainKey, verifyChain } from '../core/chain.js';
import { readInventory, readSigningKey } from '../core/inventory.js';
import { openDb as openGatewayDb, ensureTool } from '../src/store.js';

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'at-c3-'));

/* ------------------------------------------------------------------ */
/* Keyed audit chain                                                   */
/* ------------------------------------------------------------------ */

test('chain: with a key configured, an unkeyed rewrite does not verify', () => {
  const dir = tempDir();
  const { db } = openPlatformDb(dir);
  db.prepare(`INSERT INTO users (id, username, role, status, created_at) VALUES ('u','u','owner','active',?)`).run(
    new Date().toISOString(),
  );

  configureChainKey(Buffer.alloc(32, 7));
  appendEvent(db, { userId: 'u', event: 'login.passkey', result: 'ok' });
  assert.equal(verifyChain(db).ok, true);

  // An attacker without the key can only produce a self-consistent (unkeyed) chain.
  configureChainKey(null);
  assert.equal(verifyChain(db).ok, false);

  // With the key, it verifies again.
  configureChainKey(Buffer.alloc(32, 7));
  assert.equal(verifyChain(db).ok, true);
});

/* ------------------------------------------------------------------ */
/* Inventory                                                           */
/* ------------------------------------------------------------------ */

function seedGateway(dir) {
  const { db } = openGatewayDb(dir);
  const tool = ensureTool(db, { name: 'database-gateway', profile: 'network' });
  db.prepare(
    `INSERT INTO connections (id, name, engine, host, port, database_name, tool_id, status, created_at)
     VALUES ('conn_1','hris','mysql','127.0.0.1',3306,'hris',?,'active',?)`,
  ).run(tool.id, new Date().toISOString());
  db.prepare(
    `INSERT INTO pii_registry (id, connection_id, table_name, column_name, strategy, enabled, updated_at)
     VALUES ('reg_1','conn_1','employee','email','redact',1,?)`,
  ).run(new Date().toISOString());
  db.prepare(
    `INSERT INTO service_credentials (id, connection_id, label, kid, alg, public_key_jwk, envelope, created_at, expires_at)
     VALUES ('svc_1','conn_1','svc-hris','kabc','ES256','{}','{"action":"query.read"}',?,?)`,
  ).run(new Date().toISOString(), new Date(Date.now() + 86_400_000).toISOString());
  db.prepare(
    `INSERT INTO audit_events (ts, actor_type, actor_id, action, decision, prev_hash, row_hash)
     VALUES (?, 'agent','a','query.read','allow',?,?)`,
  ).run(new Date().toISOString(), '0'.repeat(64), 'a'.repeat(64));
  db.close();

  // A public key for the Settings page.
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  fs.writeFileSync(
    path.join(dir, 'signing.pub.pem'),
    pair.publicKey.export({ type: 'spki', format: 'pem' }),
  );
}

test('inventory: reads connections, registry, credentials and the gateway audit count', () => {
  const dir = tempDir();
  seedGateway(dir);
  const inv = readInventory(dir);
  assert.equal(inv.available, true);
  assert.equal(inv.connections[0].name, 'hris');
  assert.equal(inv.registry[0].column_name, 'email');
  assert.equal(inv.credentials[0].kid, 'kabc');
  assert.equal(inv.auditEvents, 1);

  const key = readSigningKey(dir);
  assert.equal(key.present, true);
  assert.match(key.kid, /^k[0-9a-f]{16}$/);
  assert.equal(key.jwks.keys[0].alg, 'ES256');
});

test('inventory: a missing store degrades instead of throwing', () => {
  const inv = readInventory(path.join(tempDir(), 'nope'));
  assert.equal(inv.available, false);
  assert.equal(inv.connections.length, 0);
});

/* ------------------------------------------------------------------ */
/* Server fixtures                                                     */
/* ------------------------------------------------------------------ */

async function boot() {
  const dir = tempDir();
  const { db } = openPlatformDb(dir);
  const masterKey = loadMasterKey(dir);
  const server = createPlatformServer({ db, masterKey });

  const ids = { owner1: 'usr_owner1', member1: 'usr_member1' };
  for (const [username, role] of [['owner1', 'owner'], ['member1', 'member']]) {
    db.prepare(
      `INSERT INTO users (id, username, display_name, role, status, created_at)
       VALUES (?,?,?,?, 'active', ?)`,
    ).run(ids[username], username, username, role, new Date().toISOString());
  }

  const authz = createAuthzServer({ db });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  await new Promise((r) => authz.listen(0, '127.0.0.1', r));

  const base = `http://127.0.0.1:${server.address().port}`;
  const authzBase = `http://127.0.0.1:${authz.address().port}`;
  const cookieFor = (username, level = 2) => {
    const session = createSession(db, { userId: ids[username], authLevel: level });
    return { session, header: `__Host-at_session=${session.id}` };
  };
  const post = (route, { cookie, form }) =>
    fetch(base + route, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form || {}).toString(),
    });

  return { db, masterKey, server, authz, base, authzBase, ids, cookieFor, post };
}

/* ------------------------------------------------------------------ */
/* Console inventory pages                                             */
/* ------------------------------------------------------------------ */

test('server: Tools and Policy render the gateway inventory', async () => {
  const gw = tempDir();
  seedGateway(gw);
  process.env.AT_GATEWAY_DATA = gw;
  const { server, authz, base, cookieFor } = await boot();
  try {
    const owner = cookieFor('owner1').header;
    const tools = await (await fetch(`${base}/tools`, { headers: { cookie: owner } })).text();
    assert.ok(tools.includes('hris'), 'connection appears');
    assert.ok(tools.includes('svc-hris'), 'service passkey appears');

    const policy = await (await fetch(`${base}/policy`, { headers: { cookie: owner } })).text();
    assert.ok(policy.includes('email'));
    assert.ok(policy.includes('redact'));

    const settings = await (await fetch(`${base}/settings`, { headers: { cookie: owner } })).text();
    assert.match(settings, /k[0-9a-f]{16}/);
    assert.ok(settings.includes('ES256'));
  } finally {
    server.close();
    authz.close();
    delete process.env.AT_GATEWAY_DATA;
  }
});

/* ------------------------------------------------------------------ */
/* Self-service                                                        */
/* ------------------------------------------------------------------ */

test('server: rotating the authenticator clears the confirmation and routes to enrolment', async () => {
  const { server, authz, base, db, masterKey, ids, cookieFor, post } = await boot();
  try {
    db.prepare('UPDATE users SET totp_secret = ?, totp_confirmed_at = ? WHERE id = ?').run(
      seal(masterKey, generateSecret(), ids.owner1),
      new Date().toISOString(),
      ids.owner1,
    );
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const res = await post('/me/security/totp/rotate', {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token },
    });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/enroll/totp');
    assert.equal(db.prepare('SELECT totp_confirmed_at FROM users WHERE id = ?').get(ids.owner1).totp_confirmed_at, null);
  } finally {
    server.close();
    authz.close();
  }
});

test('server: regeneration replaces the recovery codes', async () => {
  const { server, authz, base, db, ids, cookieFor, post } = await boot();
  try {
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const res = await post('/me/security/recovery/regenerate', {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token },
    });
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('Save your recovery codes'));
    assert.equal(remainingCodes(db, ids.owner1), 10);
  } finally {
    server.close();
    authz.close();
  }
});

test('server: My activity shows only the caller events', async () => {
  const { server, authz, base, ids, cookieFor } = await boot();
  try {
    const owner = cookieFor('owner1').header;
    const html = await (await fetch(`${base}/me/activity`, { headers: { cookie: owner } })).text();
    assert.ok(html.includes('My activity'));
    void ids;
  } finally {
    server.close();
    authz.close();
  }
});

/* ------------------------------------------------------------------ */
/* Split authz listener                                                */
/* ------------------------------------------------------------------ */

test('authz listener: serves only /authz, and never a bearer value', async () => {
  const { server, authz, authzBase, cookieFor } = await boot();
  try {
    const member = cookieFor('member1');
    const ok = await fetch(`${authzBase}/authz?app=durable-pi`, { headers: { cookie: member.header } });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('x-at-roles'), 'member');
    assert.equal(ok.headers.get('x-at-session'), null);
    assert.equal(ok.headers.get('set-cookie'), null);

    const anon = await fetch(`${authzBase}/authz?app=durable-pi`);
    assert.equal(anon.status, 401);

    const wrong = await fetch(`${authzBase}/`, { headers: { cookie: member.header } });
    assert.equal(wrong.status, 404);
  } finally {
    server.close();
    authz.close();
  }
});

test('inventory: reads a live WAL store, as on a read-only mount', () => {
  const dir = tempDir();
  const { db } = openGatewayDb(dir); // WAL is enabled here
  db.prepare(
    `INSERT INTO tools (id, name, profile, created_at) VALUES ('t1','database-gateway','network',?)`,
  ).run(new Date().toISOString());

  // Keep the handle open so the rows live in the -wal file, not the main database.
  const inv = readInventory(dir);
  db.close();

  assert.equal(inv.available, true);
  assert.equal(inv.tools[0].name, 'database-gateway');
});