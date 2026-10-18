import http from 'node:http';
import crypto from 'node:crypto';
import { audit, findUser, listApplications, seedDurablePi, userById } from './db.js';
import {
  SESSION_COOKIE,
  createSession,
  elevateSession,
  liveSessions,
  loadSession,
  revokeSession,
  touchSession,
} from './sessions.js';
import { canSee } from './nav.js';
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
import {
  applicationsPage,
  auditPage,
  enrollPage,
  enrollTotpPage,
  errorPage,
  loginPage,
  meSecurityPage,
  overviewPage,
  peoplePage,
  policyPage,
  settingsPage,
  toolsPage,
  totpLoginPage,
} from './views.js';
import { LOGIN_JS, ENROLL_JS } from './assets.js';

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

function sendHtml(res, status, html) {
  send(res, status, html, { 'content-type': 'text/html; charset=utf-8' });
}

function sendJson(res, status, obj) {
  send(res, status, JSON.stringify(obj), { 'content-type': 'application/json' });
}

function redirect(res, location) {
  send(res, 303, '', { Location: location });
}

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
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
  );
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

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

export function createPlatformServer({ db, masterKey }) {
  const rp = rpConfig();
  seedDurablePi(db);

  const sessionOf = (req) => {
    const cookies = parseCookies(req.headers.cookie);
    const session = loadSession(db, cookies[SESSION_COOKIE]);
    if (session) touchSession(db, session.id);
    return session;
  };

  const inviteFor = (token) => {
    const row = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(sha256(token));
    if (!row || row.used_at) return null;
    if (Date.parse(row.expires_at) < Date.now()) return null;
    return row;
  };

  const secretFor = (user) => (user.totp_secret ? openSealed(masterKey, user.totp_secret, user.id) : null);

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
      sendHtml(res, 403, errorPage({ status: 403, message: 'Your role does not include this section.', user: session }));
      return false;
    }
    return true;
  };

  async function route(req, res) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;

    /* ---------------- public ---------------- */

    if (path === '/healthz') return sendJson(res, 200, { ok: true });

    if (path === '/assets/login.js') {
      return send(res, 200, LOGIN_JS, { 'content-type': 'text/javascript; charset=utf-8' });
    }
    if (path === '/assets/enroll.js') {
      return send(res, 200, ENROLL_JS, { 'content-type': 'text/javascript; charset=utf-8' });
    }

    if (path === '/login' && req.method === 'GET') {
      const session = sessionOf(req);
      if (session?.auth_level >= 2) return redirect(res, '/');
      if (session?.auth_level === 1) return redirect(res, '/login/totp');
      return sendHtml(res, 200, loginPage());
    }

    if (path === '/auth/options' && req.method === 'POST') {
      const { username } = await readBody(req);
      const { options } = await beginAuthentication(db, username);
      return sendJson(res, 200, { options });
    }

    if (path === '/auth/verify' && req.method === 'POST') {
      const { username, response } = await readBody(req);
      try {
        const { user } = await finishAuthentication(db, response);
        const session = createSession(db, { userId: user.id, authLevel: 1, ip: req.socket.remoteAddress });
        db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), user.id);
        audit(db, { userId: user.id, event: 'login.passkey', factor: 'passkey', result: 'ok', ip: req.socket.remoteAddress });
        setSessionCookie(res, session.id);
        return sendJson(res, 200, { ok: true, next: '/login/totp' });
      } catch (err) {
        audit(db, { userId: null, event: 'login.passkey', factor: 'passkey', result: 'fail', detail: err.code || err.message });
        throw err;
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
        'X-AT-Session': session.id,
      });
      return res.end();
    }

    /* ---------------- enrolment ---------------- */

    if (path === '/enroll' && req.method === 'GET') {
      const invite = inviteFor(url.searchParams.get('token'));
      if (!invite) return sendHtml(res, 400, errorPage({ status: 400, message: 'This invite is invalid or has expired.' }));
      return sendHtml(res, 200, enrollPage({ token: url.searchParams.get('token') }));
    }

    if (path === '/enroll/options' && req.method === 'POST') {
      const { token } = await readBody(req);
      const invite = inviteFor(token);
      if (!invite) throw new AuthError('E_INVITE', 'invite is invalid or expired');
      const user = userById(db, invite.user_id);
      const options = await beginRegistration(db, user);
      return sendJson(res, 200, { options });
    }

    if (path === '/enroll/verify' && req.method === 'POST') {
      const { token, response } = await readBody(req);
      const invite = inviteFor(token);
      if (!invite) throw new AuthError('E_INVITE', 'invite is invalid or expired');
      const user = userById(db, invite.user_id);
      await finishRegistration(db, user, response);

      db.prepare('UPDATE invites SET used_at = ? WHERE id = ?').run(new Date().toISOString(), invite.id);
      let secret = secretFor(user);
      if (!secret) {
        secret = generateSecret();
        db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(seal(masterKey, secret, user.id), user.id);
      }
      db.prepare("UPDATE users SET status = 'active' WHERE id = ?").run(user.id);
      audit(db, { userId: user.id, event: 'cred.add', factor: 'passkey', result: 'ok' });

      const session = createSession(db, { userId: user.id, authLevel: 1, ip: req.socket.remoteAddress });
      setSessionCookie(res, session.id);
      return sendJson(res, 200, { ok: true, next: '/enroll/totp' });
    }

    if (path === '/enroll/totp' && req.method === 'GET') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const user = userById(db, session.user_id);
      const secret = secretFor(user);
      if (!secret) return redirect(res, '/');
      return sendHtml(res, 200, enrollTotpPage({ secret, uri: otpauthUri({ account: user.username, secret }) }));
    }

    if (path === '/enroll/totp' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const user = userById(db, session.user_id);
      const secret = secretFor(user);
      const { code } = await readBody(req);
      const step = secret ? verifyTotp(secret, code, user.totp_last_step) : null;
      if (!step) {
        audit(db, { userId: user.id, event: 'totp.enrol', factor: 'totp', result: 'fail' });
        return sendHtml(res, 400, enrollTotpPage({ secret, uri: otpauthUri({ account: user.username, secret }), error: 'That code did not match. Try the next one.' }));
      }
      db.prepare('UPDATE users SET totp_last_step = ?, totp_confirmed_at = ? WHERE id = ?').run(step, new Date().toISOString(), user.id);
      audit(db, { userId: user.id, event: 'totp.enrol', factor: 'totp', result: 'ok' });
      const elevated = elevateSession(db, session.id);
      setSessionCookie(res, elevated.id);
      return redirect(res, '/');
    }

    /* ---------------- login second factor ---------------- */

    if (path === '/login/totp' && req.method === 'GET') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      if (session.auth_level >= 2) return redirect(res, '/');
      return sendHtml(res, 200, totpLoginPage({ username: session.username }));
    }

    if (path === '/auth/totp' && req.method === 'POST') {
      const session = sessionOf(req);
      if (!session) return redirect(res, '/login');
      const user = userById(db, session.user_id);
      const secret = secretFor(user);
      const { code } = await readBody(req);
      const step = secret ? verifyTotp(secret, code, user.totp_last_step) : null;
      if (!step) {
        audit(db, { userId: user.id, event: 'login.totp', factor: 'totp', result: 'fail' });
        return sendHtml(res, 401, totpLoginPage({ username: session.username, error: 'That code did not match.' }));
      }
      db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
      audit(db, { userId: user.id, event: 'login.totp', factor: 'totp', result: 'ok' });
      const elevated = elevateSession(db, session.id);
      setSessionCookie(res, elevated.id);
      return redirect(res, '/');
    }

    if (path === '/auth/logout' && req.method === 'POST') {
      const session = sessionOf(req);
      if (session) {
        revokeSession(db, session.id);
        audit(db, { userId: session.user_id, event: 'session.revoke', result: 'ok' });
      }
      clearSessionCookie(res);
      return redirect(res, '/login');
    }

    /* ---------------- console ---------------- */

    const session = sessionOf(req);
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
      return sendHtml(res, 200, overviewPage({ user: session, apps, counts }));
    }

    const sections = {
      '/people': { key: 'people', render: () =>
        peoplePage({
          user: session,
          users: db.prepare('SELECT * FROM users ORDER BY username').all(),
          sessions: liveSessions(db),
        }) },
      '/tools': { key: 'tools', render: () => toolsPage({ user: session }) },
      '/applications': { key: 'applications', render: () => applicationsPage({ user: session, apps: listApplications(db) }) },
      '/policy': { key: 'policy', render: () => policyPage({ user: session }) },
      '/audit': { key: 'audit', render: () =>
        auditPage({
          user: session,
          events: db.prepare('SELECT * FROM auth_events ORDER BY seq DESC LIMIT 100').all(),
        }) },
      '/settings': { key: 'settings', render: () => settingsPage({ user: session, rp }) },
    };

    if (sections[path]) {
      const section = sections[path];
      if (!requireSection(session, res, section.key)) return undefined;
      return sendHtml(res, 200, section.render());
    }

    if (path === '/me/security') {
      const user = userById(db, session.user_id);
      const creds = db.prepare('SELECT * FROM webauthn_creds WHERE user_id = ? ORDER BY created_at').all(user.id);
      return sendHtml(res, 200, meSecurityPage({ user: session, creds, totpConfirmed: Boolean(user.totp_confirmed_at) }));
    }

    return sendHtml(res, 404, errorPage({ status: 404, message: 'That page does not exist.', user: session }));
  }

  return http.createServer((req, res) => {
    route(req, res).catch((err) => {
      if (res.headersSent) return;
      const status = err instanceof AuthError ? 401 : 400;
      const wantsJson = String(req.headers.accept || '').includes('application/json') ||
        String(req.headers['content-type'] || '').includes('application/json');
      if (wantsJson) return sendJson(res, status, { error: err.code || err.message });
      return sendHtml(res, status, errorPage({ status, message: err.message }));
    });
  });
}

export { findUser };
