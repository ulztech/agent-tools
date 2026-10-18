import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

/** Where the gateway keeps its SQLite store and signing key. */
export function gatewayDataDir() {
  return process.env.AT_GATEWAY_DATA || path.resolve('.data');
}

/**
 * Read-only view of the gateway estate. The platform opens the gateway database as a
 * second reader; it never writes to it. Missing or half-initialised stores degrade to
 * `available: false` rather than throwing.
 */
export function readInventory(dir = gatewayDataDir()) {
  const empty = {
    available: false,
    dir,
    connections: [],
    tools: [],
    credentials: [],
    registry: [],
    auditEvents: 0,
  };
  const file = path.join(dir, 'gateway.sqlite');
  if (!fs.existsSync(file)) return { ...empty, reason: 'gateway store not found' };

  // Always read from a snapshot. The store is normally a WAL database on a read-only
  // mount, where SQLite cannot create the -shm it needs: the open succeeds and the first
  // query fails. A copy removes that whole class of failure.
  const size = fs.statSync(file).size;
  if (size > 256 * 1024 * 1024) {
    return { ...empty, reason: 'gateway store is too large to snapshot for console display' };
  }

  const snapshot = path.join(
    os.tmpdir(),
    `at-inventory-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`,
  );
  try {
    fs.copyFileSync(file, snapshot);
    for (const suffix of ['-wal', '-shm']) {
      if (fs.existsSync(`${file}${suffix}`)) fs.copyFileSync(`${file}${suffix}`, `${snapshot}${suffix}`);
    }
  } catch (err) {
    try {
      fs.unlinkSync(snapshot);
    } catch {
      /* best effort */
    }
    return { ...empty, reason: `could not snapshot the gateway store: ${err.message}` };
  }

  let db;
  try {
    db = new DatabaseSync(snapshot);
    db.exec('PRAGMA busy_timeout = 500;');
    return {
      available: true,
      dir,
      connections: db
        .prepare('SELECT id, name, engine, host, port, database_name, status FROM connections ORDER BY name')
        .all(),
      tools: db.prepare('SELECT id, name, profile FROM tools ORDER BY name').all(),
      credentials: db
        .prepare(
          `SELECT s.id, c.name AS connection, s.label, s.kid, s.envelope, s.expires_at,
                  s.revoked_at, s.last_minted_at, s.minted_today
             FROM service_credentials s JOIN connections c ON c.id = s.connection_id
            ORDER BY s.created_at DESC`,
        )
        .all(),
      registry: db
        .prepare(
          `SELECT c.name AS connection, r.table_name, r.column_name, r.strategy, r.enabled
             FROM pii_registry r JOIN connections c ON c.id = r.connection_id
            ORDER BY c.name, r.table_name, r.column_name`,
        )
        .all(),
      auditEvents: db.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n,
    };
  } catch (err) {
    return { ...empty, reason: err.message };
  } finally {
    if (db) db.close();
    if (snapshot) {
      for (const suffix of ['', '-wal', '-shm']) {
        try {
          fs.unlinkSync(`${snapshot}${suffix}`);
        } catch {
          /* best effort */
        }
      }
    }
  }
}

/** Public half of the capability signing key, for the Settings page. */
export function readSigningKey(dir = gatewayDataDir()) {
  const pub = path.join(dir, 'signing.pub.pem');
  if (!fs.existsSync(pub)) return { present: false };
  try {
    const key = crypto.createPublicKey(fs.readFileSync(pub, 'utf8'));
    const der = key.export({ type: 'spki', format: 'der' });
    const kid = `k${crypto.createHash('sha256').update(der).digest('hex').slice(0, 16)}`;
    const jwk = key.export({ format: 'jwk' });
    return { present: true, kid, alg: 'ES256', jwks: { keys: [{ ...jwk, kid, alg: 'ES256', use: 'sig' }] } };
  } catch (err) {
    return { present: false, reason: err.message };
  }
}

/** 150 ms TCP probe, so a dead app shows as unreachable instead of stalling the page. */
export async function probeUpstream(url) {
  let target;
  try {
    target = new URL(url);
  } catch {
    return 'invalid';
  }
  const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(150);
    socket.once('connect', () => done('up'));
    socket.once('timeout', () => done('unreachable'));
    socket.once('error', () => done('unreachable'));
    socket.connect(port, target.hostname);
  });
}
