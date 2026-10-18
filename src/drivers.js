import { GatewayError } from './util.js';

/** In-memory driver used by tests and by `--dry-run`. */
export function stubDriver({ fields, rows = [], onQuery }) {
  return {
    async query({ sql, params, maxRows }) {
      if (onQuery) onQuery({ sql, params, maxRows });
      const sliced = typeof maxRows === 'number' ? rows.slice(0, maxRows) : rows.slice();
      return { fields: (fields || []).slice(), rows: sliced.map((r) => ({ ...r })) };
    },
    async close() {},
  };
}

/**
 * MySQL adapter. `mysql2` is an optional dependency so the core (and the whole test
 * suite) runs with zero installed packages.
 */
export async function createMysqlDriver(secret, { connectTimeoutMs = 5000, queryTimeoutMs = 15000 } = {}) {
  let mysql;
  try {
    const mod = await import('mysql2/promise');
    mysql = mod.default ?? mod;
  } catch {
    throw new GatewayError('E_DRIVER_MISSING', 'mysql2 is not installed — run npm install to enable MySQL connections');
  }
  const pool = mysql.createPool({
    host: secret.host,
    port: secret.port,
    user: secret.user,
    password: secret.password,
    database: secret.database,
    connectionLimit: 2,
    waitForConnections: true,
    connectTimeout: connectTimeoutMs,
    multipleStatements: false,
    dateStrings: true,
    supportBigNumbers: true,
  });
  return {
    async query({ sql, params, maxRows }) {
      const [rows, fields] = await pool.query({
        sql,
        values: params,
        timeout: queryTimeoutMs,
        rowsAsArray: false,
      });
      const list = Array.isArray(rows) ? rows : [];
      return {
        fields: (fields || []).map((f) => f.name),
        rows: typeof maxRows === 'number' ? list.slice(0, maxRows) : list,
      };
    },
    async close() {
      await pool.end();
    },
  };
}
