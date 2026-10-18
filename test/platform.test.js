import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, openPlatformDb } from '../core/db.js';
import { verifyChain } from '../core/chain.js';
import { createPlatformServer } from '../core/server.js';
import { createSession, liveSessions, loadSession, markStepUp, touchSession } from '../core/sessions.js';
import {
  consumeCode,
  generateRecoveryCodes,
  remainingCodes,
  storeCodes,
} from '../core/recovery.js';
import { MAX_FAILURES, clearFailures, isLocked, recordFailure } from '../core/throttle.js';
import { issueInvite, pendingInvites } from '../core/invites.js';
import { loadMasterKey, seal } from '../core/secretbox.js';
import { generateSecret } from '../core/totp.js';

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'at-platform2-'));

async function boot() {
  const dir = tempDir();
  const { db } = openPlatformDb(dir);
  const masterKey = loadMasterKey(dir);
  const server = createPlatformServer({ db, masterKey });

  const ids = {};
  const roles = { owner1: 'owner', owner2: 'owner', admin1: 'admin', auditor1: 'auditor', member1: 'member', member2: 'member' };
  for (const [username, role] of Object.entries(roles)) {
    const id = `usr_${username}`;
    db.prepare(
      `INSERT INTO users (id, username, display_name, role, status, created_at)
       VALUES (?,?,?,?, 'active', ?)`,
    ).run(id, username, username, role, new Date().toISOString());
    ids[username] = id;
  }

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const cookieFor = (username, authLevel = 2) => {
    const session = createSession(db, { userId: ids[username], authLevel });
    return { session, header: `__Host-at_session=${session.id}` };
  };

  const post = (route, { cookie, form, csrf, json } = {}) =>
    fetch(base + route, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        ...(cookie ? { cookie } : {}),
        'content-type': json ? 'application/json' : 'application/x-www-form-urlencoded',
        ...(csrf ? { 'x-csrf-token': csrf } : {}),
      },
      body: json ? JSON.stringify(json) : new URLSearchParams(form || {}).toString(),
    });

  const get = (route, cookie) =>
    fetch(base + route, { redirect: 'manual', headers: cookie ? { cookie } : {} });

  return { db, masterKey, server, base, ids, cookieFor, post, get };
}

/* ------------------------------------------------------------------ */
/* Recovery codes                                                      */
/* ------------------------------------------------------------------ */

test('recovery: a code verifies once and then is spent', () => {
  const { db } = openPlatformDb(tempDir());
  db.prepare(`INSERT INTO users (id, username, role, status, created_at) VALUES ('u1','u1','owner','active',?)`).run(
    new Date().toISOString(),
  );
  const codes = generateRecoveryCodes(3);
  storeCodes(db, 'u1', codes);
  assert.equal(remainingCodes(db, 'u1'), 3);
  assert.equal(consumeCode(db, 'u1', codes[0]), true);
  assert.equal(consumeCode(db, 'u1', codes[0]), false);
  assert.equal(remainingCodes(db, 'u1'), 2);
});

test('recovery: input is normalised across case, spaces and dashes', () => {
  const { db } = openPlatformDb(tempDir());
  db.prepare(`INSERT INTO users (id, username, role, status, created_at) VALUES ('u2','u2','owner','active',?)`).run(
    new Date().toISOString(),
  );
  const [code] = generateRecoveryCodes(1);
  storeCodes(db, 'u2', [code]);
  assert.equal(consumeCode(db, 'u2', code.replace('-', ' ').toLowerCase()), true);
});

/* ------------------------------------------------------------------ */
/* Throttle                                                            */
/* ------------------------------------------------------------------ */

test('throttle: locks after the budget, expires, and clears on success', () => {
  const { db } = openPlatformDb(tempDir());
  const now = 1_700_000_000_000;
  for (let i = 1; i < MAX_FAILURES; i += 1) recordFailure(db, 'k', now);
  assert.equal(isLocked(db, 'k', now), false);
  recordFailure(db, 'k', now);
  assert.equal(isLocked(db, 'k', now), true);
  assert.equal(isLocked(db, 'k', now + 61_000), false);
  clearFailures(db, 'k');
  assert.equal(isLocked(db, 'k', now), false);
});

test('throttle: the lock delay grows with repeated failures', () => {
  const { db } = openPlatformDb(tempDir());
  const now = 1_700_000_000_000;
  for (let i = 0; i < MAX_FAILURES; i += 1) recordFailure(db, 'k', now);
  const first = Date.parse(db.prepare('SELECT locked_until FROM auth_throttle WHERE key = ?').get('k').locked_until) - now;
  recordFailure(db, 'k', now);
  const second = Date.parse(db.prepare('SELECT locked_until FROM auth_throttle WHERE key = ?').get('k').locked_until) - now;
  assert.ok(second > first, `${second} should exceed ${first}`);
});

/* ------------------------------------------------------------------ */
/* CSRF + step-up                                                      */
/* ------------------------------------------------------------------ */

test('server: a state-changing form without a CSRF token is refused', async () => {
  const { server, cookieFor, post, db } = await boot();
  try {
    const { session, header } = cookieFor('owner1');
    markStepUp(db, session.id);
    const res = await post('/people/invite', { cookie: header, form: { username: 'newbie', role: 'member' } });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('server: no fresh step-up redirects to /step-up', async () => {
  const { server, cookieFor, post } = await boot();
  try {
    const { session, header } = cookieFor('owner1');
    const res = await post('/people/invite', {
      cookie: header,
      form: { _csrf: session.csrf_token, username: 'newbie', role: 'member' },
    });
    assert.equal(res.status, 303);
    assert.match(res.headers.get('location'), /^\/step-up\?next=/);
  } finally {
    server.close();
  }
});

test('server: CSRF + step-up creates an invite, shown once', async () => {
  const { server, cookieFor, post, db } = await boot();
  try {
    const { session, header } = cookieFor('owner1');
    markStepUp(db, session.id);
    const res = await post('/people/invite', {
      cookie: header,
      form: { _csrf: session.csrf_token, username: 'newbie', role: 'member' },
    });
    assert.equal(res.status, 200);
    assert.ok((await res.text()).includes('/enroll?token='));
  } finally {
    server.close();
  }
});

test('server: a member cannot reach the people surface', async () => {
  const { server, cookieFor, get, post } = await boot();
  try {
    const { session, header } = cookieFor('member1');
    assert.equal((await get('/people', header)).status, 403);
    const res = await post('/people/invite', {
      cookie: header,
      form: { _csrf: session.csrf_token, username: 'x', role: 'member' },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

/* ------------------------------------------------------------------ */
/* People administration                                               */
/* ------------------------------------------------------------------ */

test('server: an owner can change a role, and the target sessions die', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const victim = cookieFor('member1');
    const res = await post(`/people/${ids.member1}/role`, {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token, role: 'auditor' },
    });
    assert.equal(res.status, 303);
    assert.equal(db.prepare('SELECT role FROM users WHERE id = ?').get(ids.member1).role, 'auditor');
    assert.equal(loadSession(db, victim.session.id), null);
  } finally {
    server.close();
  }
});

test('server: you cannot change your own role', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const res = await post(`/people/${ids.owner1}/role`, {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token, role: 'member' },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('server: the last active owner cannot be demoted', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    db.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").run(ids.owner2);
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const res = await post(`/people/${ids.owner2}/role`, {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token, role: 'member' },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('server: suspending a user revokes their sessions', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const victim = cookieFor('member2');
    const res = await post(`/people/${ids.member2}/status`, {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token, status: 'suspended' },
    });
    assert.equal(res.status, 303);
    assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(ids.member2).status, 'suspended');
    assert.equal(loadSession(db, victim.session.id), null);
  } finally {
    server.close();
  }
});

test('server: a session can be revoked from the people page', async () => {
  const { server, cookieFor, post, db } = await boot();
  try {
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const victim = cookieFor('member2');
    const res = await post(`/people/sessions/${victim.session.id}/revoke`, {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token },
    });
    assert.equal(res.status, 303);
    assert.equal(loadSession(db, victim.session.id), null);
  } finally {
    server.close();
  }
});

test('server: a pending invite can be revoked', async () => {
  const { server, cookieFor, post, db } = await boot();
  try {
    issueInvite(db, { username: 'pending', role: 'member' });
    assert.equal(pendingInvites(db).length, 1);
    const inviteId = pendingInvites(db)[0].id;
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const res = await post(`/people/invites/${inviteId}/revoke`, {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token },
    });
    assert.equal(res.status, 303);
    assert.equal(pendingInvites(db).length, 0);
  } finally {
    server.close();
  }
});

test('server: the user detail page renders the security surface', async () => {
  const { server, cookieFor, get, ids } = await boot();
  try {
    const owner = cookieFor('owner1');
    const res = await get(`/people/${ids.member1}`, owner.header);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('Passkeys'));
    assert.ok(html.includes('recovery codes remaining'));
  } finally {
    server.close();
  }
});

/* ------------------------------------------------------------------ */
/* Recovery login and TOTP throttling                                  */
/* ------------------------------------------------------------------ */

test('server: a recovery code completes login once and elevates the session', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    const [code] = generateRecoveryCodes(1);
    storeCodes(db, ids.member1, [code]);

    const l1 = cookieFor('member1', 1);
    const res = await post('/auth/recovery', {
      cookie: l1.header,
      form: { _csrf: l1.session.csrf_token, code },
    });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/');
    assert.equal(loadSession(db, l1.session.id), null);

    const again = cookieFor('member1', 1);
    const reuse = await post('/auth/recovery', {
      cookie: again.header,
      form: { _csrf: again.session.csrf_token, code },
    });
    assert.equal(reuse.status, 401);
  } finally {
    server.close();
  }
});

test('server: TOTP failures lock the account with a 429', async () => {
  const { server, cookieFor, post, db, masterKey, ids } = await boot();
  try {
    db.prepare('UPDATE users SET totp_secret = ?, totp_confirmed_at = ? WHERE id = ?').run(
      seal(masterKey, generateSecret(), ids.member2),
      new Date().toISOString(),
      ids.member2,
    );
    const l1 = cookieFor('member2', 1);

    let last = 0;
    for (let i = 0; i < MAX_FAILURES; i += 1) {
      const res = await post('/auth/totp', {
        cookie: l1.header,
        form: { _csrf: l1.session.csrf_token, code: '000000' },
      });
      last = res.status;
      assert.equal(res.status, 401, `attempt ${i + 1}`);
    }
    const locked = await post('/auth/totp', {
      cookie: l1.header,
      form: { _csrf: l1.session.csrf_token, code: '000000' },
    });
    assert.equal(locked.status, 429);
    assert.equal(last, 401);
  } finally {
    server.close();
  }
});

test('server: recovery and TOTP surfaces are L2-gated where required', async () => {
  const { server, cookieFor, get } = await boot();
  try {
    const anon = await get('/step-up');
    assert.equal(anon.status, 303);
    const l1 = cookieFor('member1', 1);
    const step = await get('/step-up', l1.header);
    assert.equal(step.status, 303);
    assert.equal(step.headers.get('location'), '/login/totp');
  } finally {
    server.close();
  }
});

/* ------------------------------------------------------------------ */
/* Audit chain and regression fixes                                    */
/* ------------------------------------------------------------------ */

test('chain: tampering with an auth event breaks verification', () => {
  const { db } = openPlatformDb(tempDir());
  db.prepare(`INSERT INTO users (id, username, role, status, created_at) VALUES ('c1','c1','owner','active',?)`).run(
    new Date().toISOString(),
  );
  audit(db, { userId: 'c1', event: 'login.passkey', result: 'ok' });
  audit(db, { userId: 'c1', event: 'login.totp', result: 'ok' });
  assert.equal(verifyChain(db).ok, true);
  db.prepare("UPDATE auth_events SET result = 'fail' WHERE seq = 1").run();
  const broken = verifyChain(db);
  assert.equal(broken.ok, false);
  assert.equal(broken.brokenAt, 1);
});

test('server: a confirmed user cannot re-read the TOTP seed at L1', async () => {
  const { server, cookieFor, get, post, db, masterKey, ids } = await boot();
  try {
    db.prepare('UPDATE users SET totp_secret = ?, totp_confirmed_at = ? WHERE id = ?').run(
      seal(masterKey, generateSecret(), ids.member1),
      new Date().toISOString(),
      ids.member1,
    );
    const l1 = cookieFor('member1', 1);
    const page = await get('/enroll/totp', l1.header);
    assert.equal(page.status, 303);
    assert.equal(page.headers.get('location'), '/');

    const res = await post('/enroll/totp', {
      cookie: l1.header,
      form: { _csrf: l1.session.csrf_token, code: '000000' },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('server: step-up cannot redirect off-site', async () => {
  const { server, cookieFor, get } = await boot();
  try {
    const owner = cookieFor('owner1');
    const res = await get('/step-up?next=//evil.example', owner.header);
    const html = await res.text();
    assert.equal(html.includes('evil.example'), false);
    assert.ok(html.includes('data-next="/"'));
  } finally {
    server.close();
  }
});

test('server: an invalid role on invite is refused', async () => {
  const { server, cookieFor, post, db } = await boot();
  try {
    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const res = await post('/people/invite', {
      cookie: owner.header,
      form: { _csrf: owner.session.csrf_token, username: 'x', role: 'superuser' },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('sessions: expired sessions are not listed as live', () => {
  const { db } = openPlatformDb(tempDir());
  db.prepare(`INSERT INTO users (id, username, role, status, created_at) VALUES ('s1','s1','owner','active',?)`).run(
    new Date().toISOString(),
  );
  const s = createSession(db, { userId: 's1' });
  db.prepare('UPDATE sessions SET idle_expires_at = ? WHERE id = ?').run(
    new Date(Date.now() - 1000).toISOString(),
    s.id,
  );
  assert.equal(liveSessions(db).some((x) => x.id === s.id), false);
});
test('sessions: touching an L1 session keeps its 5-minute idle, not 15', () => {
  const { db } = openPlatformDb(tempDir());
  db.prepare(`INSERT INTO users (id, username, role, status, created_at) VALUES ('i1','i1','owner','active',?)`).run(
    new Date().toISOString(),
  );
  const s = createSession(db, { userId: 'i1', authLevel: 1, idleMs: 5 * 60_000 });
  touchSession(db, s.id);
  const row = db.prepare('SELECT idle_ms, idle_expires_at FROM sessions WHERE id = ?').get(s.id);
  assert.equal(row.idle_ms, 5 * 60_000);
  const remaining = Date.parse(row.idle_expires_at) - Date.now();
  assert.ok(remaining > 4 * 60_000 && remaining <= 5 * 60_000 + 1000, `remaining ${remaining}`);
});

test('server: a backslash in next= cannot become a protocol-relative redirect', async () => {
  const { server, cookieFor, get } = await boot();
  try {
    const owner = cookieFor('owner1');
    const res = await get('/step-up?next=%2F%5Cevil.example', owner.header);
    const html = await res.text();
    assert.equal(html.includes('evil.example'), false);
    assert.ok(html.includes('data-next="/"'));
  } finally {
    server.close();
  }
});
test('server: a mismatched Origin header is refused', async () => {
  const { server, base } = await boot();
  try {
    const res = await fetch(`${base}/auth/options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
      body: '{}',
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('server: a passkey can be removed, but never the last one', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    const add = (id) =>
      db.prepare(
        `INSERT INTO webauthn_creds (id, user_id, credential_id, public_key, counter, transports, created_at)
         VALUES (?,?,?,?,0,'[]',?)`,
      ).run(id, ids.member1, `cred-${id}`, 'AA', new Date().toISOString());
    add('pk1');
    add('pk2');

    const owner = cookieFor('owner1');
    markStepUp(db, owner.session.id);
    const target = cookieFor('member1');
    markStepUp(db, target.session.id);

    const first = await post('/me/security/passkeys/pk1/remove', {
      cookie: target.header,
      form: { _csrf: target.session.csrf_token },
    });
    assert.equal(first.status, 303);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM webauthn_creds WHERE user_id = ?').get(ids.member1).n, 1);

    const last = await post('/me/security/passkeys/pk2/remove', {
      cookie: target.header,
      form: { _csrf: target.session.csrf_token },
    });
    assert.equal(last.status, 403);
    void owner;
  } finally {
    server.close();
  }
});
test('server: /auth/verify fails identically for unknown and known accounts', async () => {
  const { server, base } = await boot();
  try {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: 'not-a-real-challenge', origin: 'http://localhost:8443' }),
    ).toString('base64url');
    const response = {
      id: 'AAAA',
      rawId: 'AAAA',
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON, authenticatorData: 'AAAA', signature: 'AAAA', userHandle: null },
    };
    const attempt = async (username) => {
      const res = await fetch(`${base}/auth/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, response }),
      });
      return { status: res.status, body: await res.json() };
    };

    const known = await attempt('member1');
    const unknown = await attempt('nobody-at-all');
    assert.equal(known.status, 401);
    assert.equal(unknown.status, 401);
    assert.deepEqual(known.body, unknown.body);
  } finally {
    server.close();
  }
});

test('server: removing a passkey retires the user other sessions', async () => {
  const { server, cookieFor, post, db, ids } = await boot();
  try {
    const insert = (id) =>
      db.prepare(
        `INSERT INTO webauthn_creds (id, user_id, credential_id, public_key, counter, transports, created_at)
         VALUES (?,?,?,?,0,'[]',?)`,
      ).run(id, ids.member1, `cred-${id}`, 'AA', new Date().toISOString());
    insert('pk1');
    insert('pk2');

    const current = cookieFor('member1');
    const elsewhere = cookieFor('member1');
    markStepUp(db, current.session.id);

    const res = await post('/me/security/passkeys/pk1/remove', {
      cookie: current.header,
      form: { _csrf: current.session.csrf_token },
    });
    assert.equal(res.status, 303);
    assert.equal(loadSession(db, elsewhere.session.id), null);
    assert.ok(loadSession(db, current.session.id));
  } finally {
    server.close();
  }
});