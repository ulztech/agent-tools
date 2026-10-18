import http from 'node:http';
import { SESSION_COOKIE, loadSession, touchSession } from './sessions.js';

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

/**
 * The forward-auth decision. Deliberately tiny and mountable on its own listener: the
 * console stays loopback-only, while a proxy on the application network can reach this
 * one endpoint and nothing else.
 *
 * Never returns a bearer secret. The upstream gets an opaque user id, the username and
 * the role; the session cookie stays between the browser and the console.
 */
export function authzDecision(db, req) {
  const cookies = parseCookies(req.headers.cookie);
  const session = loadSession(db, cookies[SESSION_COOKIE]);
  if (!session || session.auth_level < 2) return { status: 401, headers: {} };
  touchSession(db, session.id);

  const url = new URL(req.url, 'http://localhost');
  const app = url.searchParams.get('app');
  const allowed = db
    .prepare(
      `SELECT a.id FROM applications a JOIN access_rules r ON r.application_id = a.id
        WHERE a.name = ? AND r.role = ? AND a.status = 'active'`,
    )
    .get(app, session.role);
  if (!allowed) return { status: 403, headers: {} };

  return {
    status: 200,
    headers: {
      'X-AT-User': session.user_id,
      'X-AT-Username': session.username,
      'X-AT-Roles': session.role,
      'Cache-Control': 'no-store',
      Vary: 'Cookie',
    },
  };
}

/** Standalone listener for the application network: /authz only, 404 for everything else. */
export function createAuthzServer({ db }) {
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/authz') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end();
    }
    const decision = authzDecision(db, req);
    res.writeHead(decision.status, {
      ...decision.headers,
      'content-type': 'text/plain',
      'Cache-Control': 'no-store',
      Vary: 'Cookie',
    });
    return res.end();
  });
}
