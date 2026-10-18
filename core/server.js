import http from 'node:http';
import crypto from 'node:crypto';
import { audit, listApplications, seedDurablePi, userById } from './db.js';
import {
  SESSION_COOKIE,
  createSession,
  elevateSession,
  isStepUpFresh,
  liveSessions,
  loadSession,
  markStepUp,
  revokeAllForUser,
  revokeOtherSessions,
  rotateSession,
  revokeSession,
  touchSession,
} from './sessions.js';
import { canSee, canWrite } from './nav.js';
import {
  AuthError,
  beginAuthentication,
  beginRegistration,
  finishAuthentication,
  finishRegistration,
  rpConfig,
} from './webauthn.js';
import { generateSecret, otpauthUri, verifyTotp } from './totp.js';
import { open as openSealed, seal } from './secretbox.js';
import { consumeCode, generateRecoveryCodes, remainingCodes, storeCodes } from './recovery.js';
import { clearFailures, isLocked, recordFailure } from './throttle.js';
import { issueInvite, consumeInvite, inviteByToken, pendingInvites } from './invites.js';
import { verifyChain } from './chain.js';
import {
  applicationsPage,
  auditPage,
  enrollPage,
  enrollTotpPage,
  errorPage,
  inviteCreatedPage,
  loginPage,
  meSecurityPage,
  overviewPage,
  peoplePage,
  policyPage,
  recoveryCodesPage,
  recoveryLoginPage,
  settingsPage,
  stepUpPage,
  toolsPage,
  totpLoginPage,
  userDetailPage,
} from './views.js';
import { ENROLL_JS, LOGIN_JS, STEPUP_JS } from './assets.js';

const MAX_BODY = 1_000_000;

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers });
  res.end(body);
}
const sendHtml = (res, status, html) => send(res, status, html, { 'content-type': 'text/html; charset=utf-8' });
const sendJson = (res, status, obj) => send(res, status, JSON.stringify(obj), { 'content-type': 'application/json' });
const redirect = (res, location) => send(res, 303, '', { Location: location });

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function setSessionCookie(res, id) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new AuthError('E_BODY', 'request body too large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  if (String(req.headers['content-type'] || '').includes('application/json')) return JSON.parse(raw);
  return Object.fromEntries(new URLSearchParams(raw));
}

function sameToken(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

export function createPlatformServer({ db, masterKey }) {
  const rp = rpConfig();
  seedDurablePi(db);

  const sessionOf = (req) => {
    const cookies = parseCookies(req.headers.cookie);
    const session = loadSession(db, cookies[SESSION_COOKIE]);
    if (session) touchSession(db, session.id);
    return session;
  };

  const secretFor = (user) => (user.totp_secret ? openSealed(masterKey, user.totp_secret, user.id) : null);

  const forbid = (res, session, message) =>
    sendHtml(res, 403, errorPage({ status: 403, message, user: session }));

  const requireL2 = (session, res) => {
    if (!session) {
      redirect(res, '/login');
      return false;
    }
    if (session.auth_level < 2) {
      redirect(res, '/login/totp');
      return false;
    }
    return true;
  };

  const requireSection = (session, res, key) => {
    if (!canSee(session.role, key)) {
      forbid(res, session, 'Your role does not include this section.');
      return false;
    }
    return true;
  };

  const requireCsrf = (session, res, token) => {
    if (sameToken(token, session.csrf_token)) return true;
    forbid(res, session, 'That form expired. Reload the page and try again.');
    return false;
  };

  const requireStepUp = (session, res, next) => {
    if (isStepUpFresh(session)) return true;
    redirect(res, `/step-up?next=${encodeURIComponent(next)}`);
    return false;
  };

  const requireOwner = (session, res) => {
    if (canWrite(session.role, 'people')) return true;
    forbid(res, session, 'Only an owner can manage people.');
    return false;
  };

  const ownerCount = () =>
    db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'owner' AND status = 'active'").get().n;

  async function route(req, res) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;

    // Browsers send Origin on cross-origin POSTs. A mismatched origin is never a
    // legitimate console request.
    if (req.method === 'POST') {
      const origin = req.headers.origin;
      if (origin && origin !== rp.origin) {
        return sendHtml(res, 403, errorPage({ status: 403, message: 'Cross-origin request refused.' }));
      }
    }

    /* ---------------- public ---------------- */

    if (path === '/healthz') return sendJson(res, 200, { ok: true });

    const assets = { '/assets/login.js': LOGIN_JS, '/assets/enroll.js': ENROLL_JS, '/assets/stepup.js': STEPUP_JS };
    if (assets[path]) return send(res, 200, assets[path], { 'content-type': 'text/javascript; charset=utf-8' });

    if (path === '/login' && req.method === 'GET') {
      const session = sessionOf(req);
      if (session?.auth_level >= 2) return redirect(res, '/');
      if (session?.auth_level === 1) return redirect(res, '/login/totp');
      return sendHtml(res, 200, loginPage());
    }

    if (path === '/auth/options' && req.method === 'POST') {
      const { username } = await readBody(req);
      // Deliberately no hard lock here: an unauthenticated caller could otherwise lock the
      // only owner out. Brute force is bounded at the TOTP step, which needs the passkey.
      const { options } = await beginAuthentication(db, username);
      return sendJson(res, 200, { options });
    }

    if (path === '/auth/verify' && req.method === 'POST') {
      const { username, response } = await readBody(req);
      try {
        const { user } = await finishAuthentication(db, response);
        const session = createSession(db, {
          userId: user.id,
          authLevel: 1,
          ip: req.socket.remoteAddress,
          idleMs: 5 * 60_000,
        });
        db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), user.id);
        audit(db, { userId: user.id, event: 'login.passkey', factor: 'passkey', result: 'ok', ip: req.socket.remoteAddress });
        setSessionCookie(res, session.id);
        return sendJson(res, 200, { ok: true, next: '/login/totp' });
      } catch (err) {
        audit(db, {
          userId: null,
          event: 'login.passkey',
          factor: 'passkey',
          result: 'fail',
          detail: err.code || 'unknown',
        });
        // Uniform failure: the same status and body whether the account exists, the
        // challenge is unknown, or the assertion is bad.
        return sendJson(res, 401, { error: 'Sign-in failed' });
      }
    }

    if (path === '/authz') {
      const app = url.searchParams.get('app');
      const session = sessionOf(req);
      if (!session || session.auth_level < 2) {
        res.writeHead(401);
        return res.end();
      }
      const allowed = db
        .prepare(
          `SELECT a.id FROM applications a JOIN access_rules r ON r.application_id = a.id
            WHERE a.name = ? AND r.role = ? AND a.status = 'active'`,
        )
        .get(app, session.role);
      if (!allowed) {
        res.writeHead(403);
        return res.end();
      }
      res.writeHead(200, {
        'X-AT-User': session.user_id,
        'X-AT-Username': session.username,
        'X-AT-Roles': session.role,
        'Cache-Control': 'no-store',
        Vary: 'Cookie',
      });
      return res.end();
    }

    /* ---------------- enrolment ---------------- */

    if (path === '/enroll' && req.method === 'GET') {
      if (!inviteByToken(db, url.searchParams.get('token'))) {
        return sendHtml(res, 400, errorPage({ status: 400, message: 'This invite is invalid or has expired.' }));
      }
      return sendHtml(res, 200, enrollPage({ token: url.searchParams.get('token') }));
    }

    if (path === '/enroll/options' && req.method === 'POST') {
      const { token } = await readBody(req);
      const invite = inviteByToken(db, token);
      if (!invite) throw new AuthError('E_INVITE', 'invite is invalid or expired');
      const options = await beginRegistration(db, userById(db, invite.user_id));
      return sendJson(res, 200, { options });
    }

    if (path === '/enroll/verify' && req.method === 'POST') {
      const { token, response } = await readBody(req);
      const invite = consumeInvite(db, token);
      if (!invite) throw new AuthError('E_INVITE', 'invite is invalid, expired or already used');
      const user = userById(db, invite.user_id);
      await finishRegistration(db, user, response);

      const fresh = userById(db, user.id);
      if (!fresh.totp_secret) {
        const secret = generateSecret();
        db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(seal(masterKey, secret, user.id), user.id);
      }
      db.prepare("UPDATE users SET status = 'active' WHERE id = ?").run(user.id);
      audit(db, { userId: user.id, event: 'cred.add', factor: 'passkey', result: 'ok' });

      const session = createSession(db, {
        userId: user.id,
        authLevel: 1,
        ip: req.socket.remoteAddress,
        idleMs: 5 * 60_000,
      });
      setSessionCookie(res, session.id);
      return sendJson(res, 200, { ok: true, next: '/enroll/totp' });
    }

    if (path === '/enroll/totp' && req.method === 'GET') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const user = userById(db, session.user_id);
      // A confirmed seed is never re-rendered: possession of factor one must not disclose
      // factor two.
      if (user.totp_confirmed_at) return redirect(res, '/');
      const secret = secretFor(user);
      if (!secret) return redirect(res, '/');
      return sendHtml(
        res,
        200,
        enrollTotpPage({
          secret,
          uri: otpauthUri({ account: user.username, secret }),
          csrf: session.csrf_token,
        }),
      );
    }

    if (path === '/enroll/totp' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const user = userById(db, session.user_id);
      if (user.totp_confirmed_at) return forbid(res, session, 'This account already has an authenticator.');
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;

      const key = `enroll-totp:${user.id}`;
      if (isLocked(db, key)) {
        const secret = secretFor(user);
        return sendHtml(
          res,
          429,
          enrollTotpPage({
            secret,
            uri: otpauthUri({ account: user.username, secret }),
            csrf: session.csrf_token,
            error: 'Too many attempts. Try again later.',
          }),
        );
      }

      const secret = secretFor(user);
      const step = secret ? verifyTotp(secret, body.code, user.totp_last_step) : null;
      if (!step) {
        recordFailure(db, key);
        audit(db, { userId: user.id, event: 'totp.enrol', factor: 'totp', result: 'fail' });
        return sendHtml(
          res,
          400,
          enrollTotpPage({
            secret,
            uri: otpauthUri({ account: user.username, secret }),
            csrf: session.csrf_token,
            error: 'That code did not match. Try the next one.',
          }),
        );
      }
      clearFailures(db, key);
      db.prepare('UPDATE users SET totp_last_step = ?, totp_confirmed_at = ? WHERE id = ?').run(
        step,
        new Date().toISOString(),
        user.id,
      );
      audit(db, { userId: user.id, event: 'totp.enrol', factor: 'totp', result: 'ok' });

      const elevated = elevateSession(db, session.id);
      setSessionCookie(res, elevated.id);

      if (remainingCodes(db, user.id) === 0) {
        const codes = generateRecoveryCodes(10);
        storeCodes(db, user.id, codes);
        return sendHtml(res, 200, recoveryCodesPage({ codes, csrf: elevated.csrf_token }));
      }
      return redirect(res, '/');
    }

    if (path === '/enroll/recovery/ack' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!requireL2(session, res)) return undefined;
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      return redirect(res, '/');
    }

    /* ---------------- second factor at login ---------------- */

    if (path === '/login/totp' && req.method === 'GET') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      if (session.auth_level >= 2) return redirect(res, '/');
      return sendHtml(res, 200, totpLoginPage({ username: session.username, csrf: session.csrf_token }));
    }

    if (path === '/login/recovery' && req.method === 'GET') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      return sendHtml(res, 200, recoveryLoginPage({ csrf: session.csrf_token }));
    }

    if (path === '/auth/recovery' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      const key = `recovery:${session.user_id}`;
      if (isLocked(db, key)) {
        return sendHtml(res, 429, recoveryLoginPage({ error: 'Too many attempts. Try again later.', csrf: session.csrf_token }));
      }
      if (!consumeCode(db, session.user_id, body.code)) {
        recordFailure(db, key);
        audit(db, { userId: session.user_id, event: 'recovery.use', factor: 'recovery', result: 'fail' });
        return sendHtml(res, 401, recoveryLoginPage({ error: 'That code is not valid.', csrf: session.csrf_token }));
      }
      clearFailures(db, key);
      audit(db, { userId: session.user_id, event: 'recovery.use', factor: 'recovery', result: 'ok' });
      const elevated = elevateSession(db, session.id);
      setSessionCookie(res, elevated.id);
      return redirect(res, '/');
    }

    if (path === '/auth/totp' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      const user = userById(db, session.user_id);
      const key = `totp:${user.id}`;
      const code = body.code;
      if (isLocked(db, key)) {
        return sendHtml(
          res,
          429,
          totpLoginPage({ username: session.username, csrf: session.csrf_token, error: 'Too many attempts. Try again later.' }),
        );
      }
      const secret = secretFor(user);
      const step = secret ? verifyTotp(secret, code, user.totp_last_step) : null;
      if (!step) {
        recordFailure(db, key);
        audit(db, { userId: user.id, event: 'login.totp', factor: 'totp', result: 'fail' });
        return sendHtml(
          res,
          401,
          totpLoginPage({ username: session.username, csrf: session.csrf_token, error: 'That code did not match.' }),
        );
      }
      clearFailures(db, key);
      db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
      audit(db, { userId: user.id, event: 'login.totp', factor: 'totp', result: 'ok' });
      const elevated = elevateSession(db, session.id);
      setSessionCookie(res, elevated.id);
      return redirect(res, '/');
    }

    if (path === '/auth/logout' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      revokeSession(db, session.id);
      audit(db, { userId: session.user_id, event: 'session.revoke', result: 'ok' });
      clearSessionCookie(res);
      return redirect(res, '/login');
    }

    /* ---------------- step-up ---------------- */

    const session = sessionOf(req);

    if (path === '/step-up' && req.method === 'GET') {
      if (!requireL2(session, res)) return undefined;
      const raw = url.searchParams.get('next') || '/';
      const next = /^\/[^\\\s]*$/.test(raw) && !raw.startsWith('//') ? raw : '/';
      return sendHtml(res, 200, stepUpPage({ next, csrf: session.csrf_token }));
    }

    if (path === '/auth/stepup/options' && req.method === 'POST') {
      if (!requireL2(session, res)) return undefined;
      const { options } = await beginAuthentication(db, session.username);
      return sendJson(res, 200, { options });
    }

    if (path === '/auth/stepup/verify' && req.method === 'POST') {
      if (!requireL2(session, res)) return undefined;
      if (!sameToken(req.headers['x-csrf-token'], session.csrf_token)) {
        return sendJson(res, 403, { error: 'CSRF token missing or invalid' });
      }
      const { response } = await readBody(req);
      const { user } = await finishAuthentication(db, response);
      if (user.id !== session.user_id) return sendJson(res, 403, { error: 'Step-up used a different account' });
      const rotated = rotateSession(db, session.id);
      markStepUp(db, rotated.id);
      setSessionCookie(res, rotated.id);
      audit(db, { userId: user.id, event: 'stepup.ok', factor: 'passkey', result: 'ok' });
      return sendJson(res, 200, { ok: true });
    }

    /* ---------------- console ---------------- */

    if (!requireL2(session, res)) return undefined;

    if (path === '/') {
      const apps =
        session.role === 'member'
          ? db
              .prepare(
                `SELECT a.* FROM applications a JOIN access_rules r ON r.application_id = a.id
                  WHERE r.role = ? AND a.status = 'active' ORDER BY a.name`,
              )
              .all(session.role)
          : listApplications(db);
      const counts = {
        users: db.prepare('SELECT COUNT(*) AS n FROM users').get().n,
        apps: db.prepare('SELECT COUNT(*) AS n FROM applications').get().n,
        sessions: liveSessions(db).length,
        events: db.prepare('SELECT COUNT(*) AS n FROM auth_events').get().n,
      };
      return sendHtml(res, 200, overviewPage({ user: session, apps, counts, chain: verifyChain(db) }));
    }

    /* ---- people: collection actions ---- */

    if (path === '/people/invite' && req.method === 'POST') {
      if (!requireSection(session, res, 'people')) return undefined;
      if (!requireOwner(session, res)) return undefined;
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      if (!requireStepUp(session, res, '/people')) return undefined;
      const role = body.role || 'member';
      if (!['owner', 'admin', 'auditor', 'member'].includes(role)) {
        return forbid(res, session, 'That role is not valid.');
      }
      const invite = issueInvite(db, {
        username: body.username,
        role,
        createdBy: session.user_id,
        ttlMinutes: 15,
      });
      return sendHtml(
        res,
        200,
        inviteCreatedPage({
          user: session,
          invite: { path: invite.path, username: invite.username, role: invite.role, expiresInMinutes: invite.expiresInMinutes },
        }),
      );
    }

    const sessionRevoke = path.match(/^\/people\/sessions\/([^/]+)\/revoke$/);
    if (sessionRevoke && req.method === 'POST') {
      if (!requireSection(session, res, 'people')) return undefined;
      if (!requireOwner(session, res)) return undefined;
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      if (!requireStepUp(session, res, '/people')) return undefined;
      revokeSession(db, sessionRevoke[1]);
      audit(db, { userId: session.user_id, event: 'session.revoke', result: 'ok', detail: 'target=session' });
      return redirect(res, '/people');
    }

    const inviteRevoke = path.match(/^\/people\/invites\/([^/]+)\/revoke$/);
    if (inviteRevoke && req.method === 'POST') {
      if (!requireSection(session, res, 'people')) return undefined;
      if (!requireOwner(session, res)) return undefined;
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      if (!requireStepUp(session, res, '/people')) return undefined;
      db.prepare('UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL').run(
        new Date().toISOString(),
        inviteRevoke[1],
      );
      audit(db, { userId: session.user_id, event: 'user.invite', result: 'revoked', detail: inviteRevoke[1] });
      return redirect(res, '/people');
    }

    /* ---- people: one user ---- */

    const roleChange = path.match(/^\/people\/([^/]+)\/role$/);
    if (roleChange && req.method === 'POST') {
      if (!requireSection(session, res, 'people')) return undefined;
      if (!requireOwner(session, res)) return undefined;
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      if (!requireStepUp(session, res, `/people/${roleChange[1]}`)) return undefined;
      const target = userById(db, roleChange[1]);
      const role = body.role;
      if (!target || !['owner', 'admin', 'auditor', 'member'].includes(role)) {
        return forbid(res, session, 'That role is not valid.');
      }
      if (target.id === session.user_id) return forbid(res, session, 'You cannot change your own role.');
      if (target.role === 'owner' && role !== 'owner' && ownerCount() <= 1) {
        return forbid(res, session, 'At least one owner must remain.');
      }
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id);
      revokeAllForUser(db, target.id);
      audit(db, { userId: session.user_id, event: 'user.role', result: 'ok', detail: `${target.username}:${role}` });
      return redirect(res, `/people/${target.id}`);
    }

    const statusChange = path.match(/^\/people\/([^/]+)\/status$/);
    if (statusChange && req.method === 'POST') {
      if (!requireSection(session, res, 'people')) return undefined;
      if (!requireOwner(session, res)) return undefined;
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      if (!requireStepUp(session, res, `/people/${statusChange[1]}`)) return undefined;
      const target = userById(db, statusChange[1]);
      const status = body.status === 'suspended' ? 'suspended' : 'active';
      if (!target) return forbid(res, session, 'That user does not exist.');
      if (target.id === session.user_id) return forbid(res, session, 'You cannot suspend your own account.');
      if (target.role === 'owner' && status === 'suspended' && ownerCount() <= 1) {
        return forbid(res, session, 'At least one owner must remain active.');
      }
      db.prepare('UPDATE users SET status = ?, disabled_at = ? WHERE id = ?').run(
        status,
        status === 'suspended' ? new Date().toISOString() : null,
        target.id,
      );
      if (status === 'suspended') revokeAllForUser(db, target.id);
      audit(db, { userId: session.user_id, event: 'user.status', result: 'ok', detail: `${target.username}:${status}` });
      return redirect(res, `/people/${target.id}`);
    }

    const userMatch = path.match(/^\/people\/([^/]+)$/);
    if (userMatch && req.method === 'GET') {
      if (!requireSection(session, res, 'people')) return undefined;
      const target = userById(db, userMatch[1]);
      if (!target) return sendHtml(res, 404, errorPage({ status: 404, message: 'No such user.', user: session }));
      return sendHtml(
        res,
        200,
        userDetailPage({
          user: session,
          target,
          creds: db.prepare('SELECT * FROM webauthn_creds WHERE user_id = ? ORDER BY created_at').all(target.id),
          sessions: db
            .prepare('SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC')
            .all(target.id),
          events: db
            .prepare('SELECT * FROM auth_events WHERE user_id = ? ORDER BY seq DESC LIMIT 20')
            .all(target.id),
          recoveryRemaining: remainingCodes(db, target.id),
        }),
      );
    }

    /* ---- sections ---- */

    if (path === '/people') {
      if (!requireSection(session, res, 'people')) return undefined;
      return sendHtml(
        res,
        200,
        peoplePage({
          user: session,
          users: db
            .prepare(
              `SELECT u.*, (SELECT COUNT(*) FROM webauthn_creds c WHERE c.user_id = u.id) AS passkeys
                 FROM users u ORDER BY u.username`,
            )
            .all(),
          sessions: liveSessions(db),
          invites: pendingInvites(db),
        }),
      );
    }

    const sections = {
      '/tools': { key: 'tools', render: () => toolsPage({ user: session }) },
      '/applications': {
        key: 'applications',
        render: () => applicationsPage({ user: session, apps: listApplications(db) }),
      },
      '/policy': { key: 'policy', render: () => policyPage({ user: session }) },
      '/audit': {
        key: 'audit',
        render: () =>
          auditPage({
            user: session,
            events: db.prepare('SELECT * FROM auth_events ORDER BY seq DESC LIMIT 100').all(),
          }),
      },
      '/settings': { key: 'settings', render: () => settingsPage({ user: session, rp }) },
    };

    if (sections[path]) {
      const section = sections[path];
      if (!requireSection(session, res, section.key)) return undefined;
      return sendHtml(res, 200, section.render());
    }

    const passkeyRemove = path.match(/^\/me\/security\/passkeys\/([^/]+)\/remove$/);
    if (passkeyRemove && req.method === 'POST') {
      const body = await readBody(req);
      if (!requireCsrf(session, res, body._csrf)) return undefined;
      if (!requireStepUp(session, res, '/me/security')) return undefined;
      const owned = db.prepare('SELECT * FROM webauthn_creds WHERE user_id = ?').all(session.user_id);
      if (owned.length <= 1) return forbid(res, session, 'You cannot remove your only passkey.');
      const info = db
        .prepare('DELETE FROM webauthn_creds WHERE id = ? AND user_id = ?')
        .run(passkeyRemove[1], session.user_id);
      audit(db, {
        userId: session.user_id,
        event: 'cred.remove',
        factor: 'passkey',
        result: Number(info.changes) === 1 ? 'ok' : 'missing',
      });
      // A retired device must not keep a live session elsewhere.
      if (Number(info.changes) === 1) revokeOtherSessions(db, session.user_id, session.id);
      return redirect(res, '/me/security');
    }

    if (path === '/me/security') {
      const user = userById(db, session.user_id);
      return sendHtml(
        res,
        200,
        meSecurityPage({
          user: session,
          creds: db.prepare('SELECT * FROM webauthn_creds WHERE user_id = ? ORDER BY created_at').all(user.id),
          totpConfirmed: Boolean(user.totp_confirmed_at),
          recoveryRemaining: remainingCodes(db, user.id),
        }),
      );
    }

    return sendHtml(res, 404, errorPage({ status: 404, message: 'That page does not exist.', user: session }));
  }

  return http.createServer((req, res) => {
    route(req, res).catch((err) => {
      if (res.headersSent) return;
      const status = err instanceof AuthError ? 401 : 400;
      const wantsJson =
        String(req.headers.accept || '').includes('application/json') ||
        String(req.headers['content-type'] || '').includes('application/json');
      if (wantsJson) return sendJson(res, status, { error: err.code || err.message });
      return sendHtml(res, status, errorPage({ status, message: err.message }));
    });
  });
}
