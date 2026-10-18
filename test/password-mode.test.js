import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openPlatformDb } from '../core/db.js';
import { createPlatformServer } from '../core/server.js';
import { issueInvite } from '../core/invites.js';
import { loadMasterKey, open as openSealed } from '../core/secretbox.js';
import { hashPassword, verifyPassword } from '../core/passwords.js';
import { totp } from '../core/totp.js';

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'at-pw-'));

test('passwords: policy and scrypt verification', () => {
  assert.throws(() => hashPassword('short', 'ulcon'), /at least 12/);
  assert.throws(() => hashPassword('averylongusername', 'averylongusername'), /must not be the username/);
  const hash = hashPassword('correct horse battery staple', 'ulcon');
  assert.match(hash, /^scrypt\$/);
  assert.equal(verifyPassword('correct horse battery staple', hash), true);
  assert.equal(verifyPassword('wrong password here', hash), false);
  assert.notEqual(hash, hashPassword('correct horse battery staple', 'ulcon'));
});

async function bootPasswordMode() {
  process.env.AT_AUTH_MODE = 'password';
  process.env.AT_ORIGIN = 'http://localhost:8443';
  process.env.AT_RP_ID = 'localhost';

  const dir = tempDir();
  const { db } = openPlatformDb(dir);
  const masterKey = loadMasterKey(dir);
  const server = createPlatformServer({ db, masterKey });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { db, masterKey, server, base };
}

const cookieHeader = (res, name) => {
  const all = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const hit = all.find((c) => c.startsWith(`${name}=`));
  return hit ? hit.split(';')[0] : null;
};

test('password mode: enrol with a password, confirm TOTP, and receive a remember cookie', async () => {
  const { db, masterKey, server, base } = await bootPasswordMode();
  try {
    const invite = issueInvite(db, { username: 'pwuser', role: 'owner' });

    const enrol = await fetch(`${base}/enroll/password`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: invite.token,
        password: 'correct horse battery staple',
        confirm: 'correct horse battery staple',
      }).toString(),
    });
    assert.equal(enrol.status, 303);
    assert.equal(enrol.headers.get('location'), '/enroll/totp');
    const session = cookieHeader(enrol, 'at_session');
    assert.ok(session, 'an L1 session cookie is issued');

    const user = db.prepare("SELECT * FROM users WHERE username = 'pwuser'").get();
    assert.equal(user.status, 'active');
    assert.match(user.password_hash, /^scrypt\$/);
    assert.equal(JSON.stringify(user).includes('correct horse'), false);

    const page = await fetch(`${base}/enroll/totp`, { headers: { cookie: session } });
    const html = await page.text();
    const csrf = (html.match(/name="_csrf" value="([^"]+)"/) || [])[1];
    assert.ok(csrf);
    assert.ok(html.includes('<svg'), 'QR rendered');

    const secret = openSealed(masterKey, user.totp_secret, user.id);
    const confirm = await fetch(`${base}/enroll/totp`, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: session, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: csrf, code: totp(secret) }).toString(),
    });
    assert.equal(confirm.status, 200);
    assert.ok((await confirm.text()).includes('Save your recovery codes'));

    const remember = cookieHeader(confirm, 'at_remember');
    assert.ok(remember, 'a remember cookie is issued after the second factor');
    const elevated = cookieHeader(confirm, 'at_session');
    assert.ok(elevated);
    assert.notEqual(elevated, session, 'the session id rotates on elevation');
  } finally {
    server.close();
    delete process.env.AT_AUTH_MODE;
    delete process.env.AT_ORIGIN;
    delete process.env.AT_RP_ID;
  }
});

test('password mode: the remember cookie identifies but never authenticates', async () => {
  const { db, masterKey, server, base } = await bootPasswordMode();
  try {
    const invite = issueInvite(db, { username: 'pwuser', role: 'owner' });
    const enrol = await fetch(`${base}/enroll/password`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: invite.token,
        password: 'correct horse battery staple',
        confirm: 'correct horse battery staple',
      }).toString(),
    });
    const session = cookieHeader(enrol, 'at_session');
    const user = db.prepare("SELECT * FROM users WHERE username = 'pwuser'").get();
    const secret = openSealed(masterKey, user.totp_secret, user.id);

    const page = await (await fetch(`${base}/enroll/totp`, { headers: { cookie: session } })).text();
    const csrf = (page.match(/name="_csrf" value="([^"]+)"/) || [])[1];
    const confirm = await fetch(`${base}/enroll/totp`, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: session, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: csrf, code: totp(secret) }).toString(),
    });
    const remember = cookieHeader(confirm, 'at_remember');

    // Returning browser, no session.
    const login = await fetch(`${base}/login`, { headers: { cookie: remember } });
    assert.ok((await login.text()).includes('Welcome back'));

    const resumed = await fetch(`${base}/auth/remember`, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: remember },
    });
    assert.equal(resumed.status, 303);
    assert.equal(resumed.headers.get('location'), '/login/totp');
    const l1 = cookieHeader(resumed, 'at_session');
    assert.ok(l1);

    // The remembered browser still has no console access without the code.
    const home = await fetch(`${base}/`, { headers: { cookie: l1 }, redirect: 'manual' });
    assert.equal(home.status, 303);
    assert.equal(home.headers.get('location'), '/login/totp');
  } finally {
    server.close();
    delete process.env.AT_AUTH_MODE;
    delete process.env.AT_ORIGIN;
    delete process.env.AT_RP_ID;
  }
});

test('password mode: a wrong password is refused and a correct one opens the code step', async () => {
  const { db, server, base } = await bootPasswordMode();
  try {
    const invite = issueInvite(db, { username: 'pwuser', role: 'owner' });
    await fetch(`${base}/enroll/password`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: invite.token,
        password: 'correct horse battery staple',
        confirm: 'correct horse battery staple',
      }).toString(),
    });

    const bad = await fetch(`${base}/auth/password`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'pwuser', password: 'not the password' }).toString(),
    });
    assert.equal(bad.status, 401);

    const good = await fetch(`${base}/auth/password`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'pwuser', password: 'correct horse battery staple' }).toString(),
    });
    assert.equal(good.status, 303);
    assert.equal(good.headers.get('location'), '/login/totp');
  } finally {
    server.close();
    delete process.env.AT_AUTH_MODE;
    delete process.env.AT_ORIGIN;
    delete process.env.AT_RP_ID;
  }
});

test('password mode: an open invite lets the person choose their own username', async () => {
  const { db, server, base } = await bootPasswordMode();
  try {
    const invite = issueInvite(db, { role: 'owner' });

    const page = await (await fetch(`${base}/enroll?token=${invite.token}`)).text();
    assert.ok(page.includes('id="username"'), 'the username field is offered');
    assert.ok(page.includes('Create your account'));

    const res = await fetch(`${base}/enroll/password`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: invite.token,
        username: 'newowner',
        password: 'correct horse battery staple',
        confirm: 'correct horse battery staple',
      }).toString(),
    });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/enroll/totp');
    assert.equal(db.prepare("SELECT username FROM users WHERE role = 'owner'").get().username, 'newowner');
  } finally {
    server.close();
    delete process.env.AT_AUTH_MODE;
    delete process.env.AT_ORIGIN;
    delete process.env.AT_RP_ID;
  }
});