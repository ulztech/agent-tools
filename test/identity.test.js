import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openPlatformDb } from '../core/db.js';
import { canSee, canWrite, navFor } from '../core/nav.js';
import {
  ABSOLUTE_MS,
  createSession,
  elevateSession,
  isStepUpFresh,
  loadSession,
  markStepUp,
  revokeSession,
} from '../core/sessions.js';
import { base32Decode, base32Encode, generateSecret, hotp, verifyTotp } from '../core/totp.js';
import { open as openSealed, loadMasterKey, seal } from '../core/secretbox.js';
import { createPlatformServer } from '../core/server.js';

const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // ASCII "12345678901234567890"

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'at-platform-'));
}

function dbWithUser({ username = 'ulcon', role = 'owner' } = {}) {
  const dir = tempDir();
  const { db } = openPlatformDb(dir);
  const id = `usr_${username}`;
  db.prepare(
    `INSERT INTO users (id, username, display_name, role, status, created_at)
     VALUES (?,?,?,?, 'active', ?)`,
  ).run(id, username, username, role, new Date().toISOString());
  return { db, dir, userId: id };
}

/* ------------------------------------------------------------------ */
/* Menu model                                                          */
/* ------------------------------------------------------------------ */

test('nav: owner sees all seven sections, in a fixed order', () => {
  assert.deepEqual(
    navFor('owner').map((n) => n.key),
    ['overview', 'people', 'tools', 'applications', 'policy', 'audit', 'settings'],
  );
});

test('nav: auditor loses settings but keeps the read surfaces', () => {
  assert.deepEqual(
    navFor('auditor').map((n) => n.key),
    ['overview', 'people', 'tools', 'applications', 'policy', 'audit'],
  );
});

test('nav: member sees only the launcher (overview)', () => {
  assert.deepEqual(navFor('member').map((n) => n.key), ['overview']);
});

test('nav: subtraction never reorders', () => {
  const order = navFor('owner').map((n) => n.key);
  for (const role of ['admin', 'auditor', 'member']) {
    const subset = navFor(role).map((n) => n.key);
    assert.deepEqual(subset, order.filter((k) => subset.includes(k)));
  }
});

test('nav: write roles are narrower than read roles', () => {
  assert.equal(canWrite('owner', 'people'), true);
  assert.equal(canWrite('admin', 'people'), false);
  assert.equal(canWrite('auditor', 'tools'), false);
  assert.equal(canWrite('admin', 'tools'), true);
  assert.equal(canSee('auditor', 'settings'), false);
});

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */

test('session: L1 is valid but not L2', () => {
  const { db, userId } = dbWithUser();
  const session = createSession(db, { userId, authLevel: 1 });
  assert.equal(session.auth_level, 1);
  assert.ok(loadSession(db, session.id));
});

test('session: elevation rotates the id and kills the old one', () => {
  const { db, userId } = dbWithUser();
  const l1 = createSession(db, { userId, authLevel: 1 });
  const l2 = elevateSession(db, l1.id);
  assert.notEqual(l2.id, l1.id);
  assert.equal(l2.auth_level, 2);
  assert.equal(loadSession(db, l1.id), null);
  assert.ok(loadSession(db, l2.id));
});

test('session: an idle session expires', () => {
  const { db, userId } = dbWithUser();
  const session = createSession(db, { userId });
  db.prepare('UPDATE sessions SET idle_expires_at = ? WHERE id = ?').run(
    new Date(Date.now() - 1000).toISOString(),
    session.id,
  );
  assert.equal(loadSession(db, session.id), null);
});

test('session: the absolute lifetime caps idle renewal', () => {
  const { db, userId } = dbWithUser();
  const session = createSession(db, { userId });
  const past = new Date(Date.now() - ABSOLUTE_MS - 1000).toISOString();
  db.prepare('UPDATE sessions SET absolute_expires_at = ? WHERE id = ?').run(past, session.id);
  assert.equal(loadSession(db, session.id), null);
});

test('session: revocation is immediate', () => {
  const { db, userId } = dbWithUser();
  const session = createSession(db, { userId });
  revokeSession(db, session.id);
  assert.equal(loadSession(db, session.id), null);
});

test('session: a suspended user has no valid session', () => {
  const { db, userId } = dbWithUser();
  const session = createSession(db, { userId });
  db.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").run(userId);
  assert.equal(loadSession(db, session.id), null);
});

test('session: step-up is fresh for five minutes only', () => {
  const { db, userId } = dbWithUser();
  const session = createSession(db, { userId, authLevel: 2 });
  assert.equal(isStepUpFresh(session), false);
  markStepUp(db, session.id);
  assert.equal(isStepUpFresh(loadSession(db, session.id)), true);
  const stale = { ...session, step_up_until: new Date(Date.now() - 1000).toISOString() };
  assert.equal(isStepUpFresh(stale), false);
});

/* ------------------------------------------------------------------ */
/* TOTP                                                                */
/* ------------------------------------------------------------------ */

test('totp: RFC 6238 SHA-1 vectors (six digits)', () => {
  const vectors = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ];
  for (const [seconds, expected] of vectors) {
    assert.equal(hotp(RFC_SECRET, Math.floor(seconds / 30)), expected, `T=${seconds}`);
  }
});

test('totp: a code is accepted inside the window and rejected outside it', () => {
  const now = 59_000;
  assert.equal(verifyTotp(RFC_SECRET, '287082', 0, { now }), 1);
  assert.equal(verifyTotp(RFC_SECRET, '000000', 0, { now }), null);
});

test('totp: replay within the same step is rejected', () => {
  const now = 59_000;
  const step = verifyTotp(RFC_SECRET, '287082', 0, { now });
  assert.equal(step, 1);
  assert.equal(verifyTotp(RFC_SECRET, '287082', step, { now }), null);
});

test('totp: base32 round-trips and secrets are 160-bit', () => {
  const secret = generateSecret();
  assert.equal(secret.length, 32);
  assert.equal(base32Decode(base32Encode(Buffer.from('hello'))).toString(), 'hello');
});

/* ------------------------------------------------------------------ */
/* Secret storage                                                      */
/* ------------------------------------------------------------------ */

test('secretbox: round-trip, and AAD binding prevents swapping users', () => {
  const dir = tempDir();
  const key = loadMasterKey(dir);
  const sealed = seal(key, 'JBSWY3DPEHPK3PXP', 'usr_a');
  assert.equal(openSealed(key, sealed, 'usr_a'), 'JBSWY3DPEHPK3PXP');
  assert.throws(() => openSealed(key, sealed, 'usr_b'));
});

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

async function boot() {
  const dir = tempDir();
  const { db } = openPlatformDb(dir);
  const masterKey = loadMasterKey(dir);
  const server = createPlatformServer({ db, masterKey });

  const ids = {};
  for (const [username, role] of [['owner1', 'owner'], ['admin1', 'admin'], ['auditor1', 'auditor'], ['member1', 'member']]) {
    const id = `usr_${username}`;
    db.prepare(
      `INSERT INTO users (id, username, display_name, role, status, created_at)
       VALUES (?,?,?,?, 'active', ?)`,
    ).run(id, username, username, role, new Date().toISOString());
    ids[username] = id;
  }

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const cookieFor = (userId, authLevel = 2) => {
    const s = createSession(db, { userId, authLevel });
    return { session: s, header: `__Host-at_session=${s.id}` };
  };

  return { db, server, base, ids, cookieFor };
}

test('server: unauthenticated console access redirects to login', async () => {
  const { server, base } = await boot();
  try {
    const res = await fetch(`${base}/`, { redirect: 'manual' });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/login');
  } finally {
    server.close();
  }
});

test('server: an L1 session reaches nothing but the second step', async () => {
  const { server, base, ids, cookieFor } = await boot();
  try {
    const { header } = cookieFor(ids.owner1, 1);
    for (const route of ['/', '/people', '/tools', '/settings', '/me/security']) {
      const res = await fetch(`${base}${route}`, { headers: { cookie: header }, redirect: 'manual' });
      assert.equal(res.status, 303, `${route} must not be served at L1`);
      assert.equal(res.headers.get('location'), '/login/totp');
    }
    const totp = await fetch(`${base}/login/totp`, { headers: { cookie: header } });
    assert.equal(totp.status, 200);
  } finally {
    server.close();
  }
});

test('server: an L2 session gets the console and its role sections', async () => {
  const { server, base, ids, cookieFor } = await boot();
  try {
    const { header } = cookieFor(ids.owner1, 2);
    const home = await fetch(`${base}/`, { headers: { cookie: header } });
    assert.equal(home.status, 200);
    const html = await home.text();
    assert.ok(html.includes('Overview'));
    assert.ok(html.includes('Settings'));

    assert.equal((await fetch(`${base}/settings`, { headers: { cookie: header } })).status, 200);
  } finally {
    server.close();
  }
});

test('server: roles gate sections, not just nav items', async () => {
  const { server, base, ids, cookieFor } = await boot();
  try {
    const member = cookieFor(ids.member1, 2).header;
    assert.equal((await fetch(`${base}/people`, { headers: { cookie: member } })).status, 403);
    assert.equal((await fetch(`${base}/settings`, { headers: { cookie: member } })).status, 403);

    const auditor = cookieFor(ids.auditor1, 2).header;
    assert.equal((await fetch(`${base}/people`, { headers: { cookie: auditor } })).status, 200);
    assert.equal((await fetch(`${base}/settings`, { headers: { cookie: auditor } })).status, 403);

    const admin = cookieFor(ids.admin1, 2).header;
    assert.equal((await fetch(`${base}/settings`, { headers: { cookie: admin } })).status, 200);
  } finally {
    server.close();
  }
});

test('server: the login page contains no password field', async () => {
  const { server, base } = await boot();
  try {
    const res = await fetch(`${base}/login`);
    const html = await res.text();
    assert.equal(html.includes('type="password"'), false);
    assert.ok(html.includes('/assets/login.js'));
  } finally {
    server.close();
  }
});

test('server: forward-auth grants an allowed role and refuses the others', async () => {
  const { server, base, ids, cookieFor } = await boot();
  try {
    const member = cookieFor(ids.member1, 2).header;
    const ok = await fetch(`${base}/authz?app=durable-pi`, { headers: { cookie: member } });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('x-at-roles'), 'member');
    assert.ok(ok.headers.get('x-at-user'));

    const auditor = cookieFor(ids.auditor1, 2).header;
    const denied = await fetch(`${base}/authz?app=durable-pi`, { headers: { cookie: auditor } });
    assert.equal(denied.status, 403);
  } finally {
    server.close();
  }
});

test('server: security headers are set on every console page', async () => {
  const { server, base, ids, cookieFor } = await boot();
  try {
    const { header } = cookieFor(ids.owner1, 2);
    const res = await fetch(`${base}/`, { headers: { cookie: header } });
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('cache-control'), 'no-store');
  } finally {
    server.close();
  }
});

test('server: an invalid invite is refused', async () => {
  const { server, base } = await boot();
  try {
    const res = await fetch(`${base}/enroll?token=nope`);
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});
