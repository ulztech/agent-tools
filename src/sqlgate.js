import { GatewayError } from './util.js';

const MAX_SQL_LENGTH = 20_000;
const MAX_NESTED_LINEAGE = 6;

const ALLOWED_FIRST = new Set(['select', 'with', 'explain', 'describe', 'desc', 'show']);
const SHOW_ALLOW = new Set(['tables', 'columns', 'index', 'indexes', 'create', 'full']);

const DENY_WORDS = new Set([
  'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate',
  'rename', 'grant', 'revoke', 'call', 'do', 'handler', 'lock', 'unlock',
  'prepare', 'execute', 'deallocate', 'set', 'into', 'outfile', 'dumpfile',
  'load_file', 'sleep', 'benchmark', 'get_lock', 'release_lock',
  'information_schema', 'performance_schema', 'mysql', 'sys',
]);

const PROJECTION_KEYWORDS = new Set([
  'select', 'distinct', 'all', 'as', 'from', 'where', 'group', 'by', 'order',
  'having', 'limit', 'offset', 'case', 'when', 'then', 'else', 'end', 'and',
  'or', 'not', 'null', 'is', 'in', 'like', 'between', 'cast', 'convert',
  'interval', 'asc', 'desc', 'separator', 'using', 'on', 'join', 'left',
  'right', 'inner', 'outer', 'cross', 'natural', 'union', 'except', 'intersect',
]);

function isWordStart(ch) {
  return /[A-Za-z_$]/.test(ch);
}

function isWordChar(ch) {
  return /[A-Za-z0-9_$]/.test(ch);
}

function isDigit(ch) {
  return /[0-9]/.test(ch);
}

/**
 * Tokenize SQL. Comments are rejected outright rather than stripped: a comment is the
 * classic obfuscation vector (`sel/**\/ect`, `UNION--x`), and a read-only query never
 * needs one.
 */
export function tokenize(sql) {
  if (typeof sql !== 'string') throw new GatewayError('E_SQL_TYPE', 'sql must be a string');
  if (sql.length > MAX_SQL_LENGTH) throw new GatewayError('E_SQL_TOO_LONG', 'sql exceeds the length limit');
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(sql)) {
    throw new GatewayError('E_SQL_CONTROL_CHARS', 'sql contains control characters');
  }

  const tokens = [];
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i];

    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }

    if ((ch === '-' && sql[i + 1] === '-') || (ch === '/' && sql[i + 1] === '*') || ch === '#') {
      throw new GatewayError('E_SQL_COMMENT', 'sql comments are not allowed');
    }

    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      const start = i;
      i += 1;
      let closed = false;
      while (i < sql.length) {
        const c = sql[i];
        if (c === '\\' && quote !== '`') {
          i += 2;
          continue;
        }
        if (c === quote) {
          if (sql[i + 1] === quote) {
            i += 2;
            continue;
          }
          i += 1;
          closed = true;
          break;
        }
        i += 1;
      }
      if (!closed) throw new GatewayError('E_SQL_UNTERMINATED', 'unterminated string literal');
      tokens.push({
        type: quote === '`' ? 'ident' : 'string',
        value: sql.slice(start + 1, i - 1),
        start,
        end: i,
      });
      continue;
    }

    if (ch === '@') {
      const start = i;
      i += 1;
      if (sql[i] === '@') i += 1;
      while (i < sql.length && (isWordChar(sql[i]) || sql[i] === '.')) i += 1;
      tokens.push({ type: 'var', value: sql.slice(start, i), start, end: i });
      continue;
    }

    if (isDigit(ch) || (ch === '.' && isDigit(sql[i + 1]))) {
      const start = i;
      while (i < sql.length && /[0-9.eE]/.test(sql[i])) i += 1;
      tokens.push({ type: 'number', value: sql.slice(start, i), start, end: i });
      continue;
    }

    if (isWordStart(ch)) {
      const start = i;
      while (i < sql.length && isWordChar(sql[i])) i += 1;
      tokens.push({ type: 'word', value: sql.slice(start, i), start, end: i });
      continue;
    }

    if ('(),.;*+-/%<>=!|&^~:'.includes(ch)) {
      tokens.push({ type: 'punct', value: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }

    throw new GatewayError('E_SQL_CHAR', `unexpected character in sql: ${JSON.stringify(ch)}`);
  }

  return tokens;
}

function depthWalk(tokens, fn) {
  let depth = 0;
  for (let idx = 0; idx < tokens.length; idx += 1) {
    const t = tokens[idx];
    if (t.type === 'punct' && t.value === '(') {
      fn(t, idx, depth);
      depth += 1;
      continue;
    }
    if (t.type === 'punct' && t.value === ')') {
      depth -= 1;
      if (depth < 0) throw new GatewayError('E_SQL_PARENS', 'unbalanced parentheses');
      fn(t, idx, depth);
      continue;
    }
    fn(t, idx, depth);
  }
  if (depth !== 0) throw new GatewayError('E_SQL_PARENS', 'unbalanced parentheses');
}

/**
 * Read-only gate. Refusing a write is not "blocking a result" — there is no result to
 * block when the statement is not a read.
 *
 * Deny words are matched on BOTH bare words and backticked identifiers: MySQL parses
 * `` `load_file`('/etc/passwd') `` and `` `mysql`.`user` `` exactly like the unquoted
 * form, so skipping identifiers would leave the gate open.
 */
export function assertReadOnly(sql) {
  const tokens = tokenize(sql);
  if (tokens.length === 0) throw new GatewayError('E_SQL_EMPTY', 'sql is empty');

  let statements = 0;
  depthWalk(tokens, (t, idx) => {
    if (t.type === 'punct' && t.value === ';') {
      const rest = tokens.slice(idx + 1);
      if (rest.length > 0) throw new GatewayError('E_SQL_MULTI', 'multiple statements are not allowed');
      statements += 1;
    }
  });
  if (statements > 1) throw new GatewayError('E_SQL_MULTI', 'multiple statements are not allowed');

  const first = tokens.find((t) => t.type === 'word');
  if (!first) throw new GatewayError('E_SQL_EMPTY', 'sql has no statement keyword');
  const head = first.value.toLowerCase();
  if (!ALLOWED_FIRST.has(head)) {
    throw new GatewayError('E_SQL_NOT_READ_ONLY', `only read-only statements are allowed, got: ${head}`);
  }

  for (const t of tokens) {
    if (t.type === 'var') throw new GatewayError('E_SQL_VAR', 'user variables are not allowed');
  }

  // SHOW is allow-listed to schema introspection only (SHOW PROCESSLIST / VARIABLES leak),
  // and is exempt from the deny words so `SHOW CREATE TABLE` stays usable.
  if (head === 'show') {
    const after = tokens.slice(tokens.indexOf(first) + 1).filter((t) => t.type === 'word' || t.type === 'ident');
    const ok = after.slice(0, 3).some((t) => SHOW_ALLOW.has(t.value.toLowerCase()));
    if (!ok) throw new GatewayError('E_SQL_NOT_READ_ONLY', 'only schema-introspection SHOW statements are allowed');
    return tokens;
  }

  for (const t of tokens) {
    if (t.type !== 'word' && t.type !== 'ident') continue;
    const w = t.value.toLowerCase();
    if (DENY_WORDS.has(w)) throw new GatewayError('E_SQL_NOT_READ_ONLY', `disallowed keyword: ${w}`);
  }

  return tokens;
}

/* ------------------------------------------------------------------ */
/* Projection / lineage                                                */
/* ------------------------------------------------------------------ */

function depthsOf(tokens) {
  const depths = [];
  let d = 0;
  for (const t of tokens) {
    if (t.type === 'punct' && t.value === ')') d -= 1;
    depths.push(d);
    if (t.type === 'punct' && t.value === '(') d += 1;
  }
  return depths;
}

function parseItems(tokens, depths, selectIdx) {
  const d = depths[selectIdx];
  let end = tokens.length;
  for (let i = selectIdx + 1; i < tokens.length; i += 1) {
    if (depths[i] < d) {
      end = i;
      break;
    }
    if (depths[i] === d && tokens[i].type === 'word' && tokens[i].value.toLowerCase() === 'from') {
      end = i;
      break;
    }
  }
  const list = tokens.slice(selectIdx + 1, end);
  const listDepths = depths.slice(selectIdx + 1, end);

  const items = [];
  let current = [];
  for (let i = 0; i < list.length; i += 1) {
    const t = list[i];
    if (listDepths[i] === d && t.type === 'punct' && t.value === ',') {
      if (current.length) items.push(describeItem(current));
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length) items.push(describeItem(current));
  return items;
}

function describeItem(tokens) {
  if (tokens.length === 1 && tokens[0].type === 'punct' && tokens[0].value === '*') {
    return { out: '*', sources: [], star: true };
  }
  if (
    tokens.length === 3 &&
    (tokens[0].type === 'word' || tokens[0].type === 'ident') &&
    tokens[1].type === 'punct' &&
    tokens[1].value === '.' &&
    tokens[2].type === 'punct' &&
    tokens[2].value === '*'
  ) {
    return { out: '*', sources: [], star: true };
  }

  let alias = null;
  let expr = tokens;
  const asIdx = tokens.findIndex((t) => t.type === 'word' && t.value.toLowerCase() === 'as');
  if (asIdx !== -1 && asIdx + 1 < tokens.length) {
    const aliasTok = tokens[asIdx + 1];
    if (aliasTok.type === 'word' || aliasTok.type === 'ident') {
      alias = aliasTok.value;
      expr = tokens.slice(0, asIdx);
    }
  } else if (tokens.length > 1) {
    const last = tokens[tokens.length - 1];
    const prev = tokens[tokens.length - 2];
    const aliasLike =
      (last.type === 'word' || last.type === 'ident') &&
      !(prev.type === 'punct' && prev.value === '.') &&
      !(prev.type === 'punct' && prev.value === '*');
    if (aliasLike && !(last.type === 'word' && PROJECTION_KEYWORDS.has(last.value.toLowerCase()))) {
      alias = last.value;
      expr = tokens.slice(0, -1);
    }
  }

  const sources = [];
  for (const t of expr) {
    if (t.type === 'ident') sources.push(t.value);
    else if (t.type === 'word') {
      const w = t.value.toLowerCase();
      if (!PROJECTION_KEYWORDS.has(w)) sources.push(t.value);
    }
  }

  const lastIdent = [...expr].reverse().find((t) => t.type === 'word' || t.type === 'ident');
  const out = alias || (lastIdent ? lastIdent.value : null);
  return { out, sources, star: false };
}

/**
 * Full projection analysis.
 *
 * Lineage is resolved through derived tables, CTEs and UNION branches. Without that,
 * `select x from (select first_name as x from employee) t` would launder a masked column
 * through one pair of parentheses — a registry column reaching the agent unmasked.
 *
 * `byOutput` and `byPosition` therefore contain the *transitively expanded* source set.
 */
export function analyzeProjection(sql) {
  const tokens = tokenize(sql);
  const depths = depthsOf(tokens);

  const selects = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i].type === 'word' && tokens[i].value.toLowerCase() === 'select') {
      selects.push({ idx: i, depth: depths[i], items: parseItems(tokens, depths, i) });
    }
  }

  // Any select nested one or more levels deep contributes an output -> sources mapping.
  const derived = new Map();
  for (const s of selects) {
    if (s.depth === 0) continue;
    for (const item of s.items) {
      if (!item.out || item.star) continue;
      derived.set(String(item.out).toLowerCase(), item.sources || []);
    }
  }

  const expand = (names) => {
    const out = new Set();
    const queue = [...(names || [])];
    let hops = 0;
    while (queue.length && hops < MAX_NESTED_LINEAGE) {
      const next = [];
      for (const raw of queue) {
        const n = String(raw).toLowerCase();
        if (out.has(n)) continue;
        out.add(n);
        const inner = derived.get(n);
        if (inner) next.push(...inner);
      }
      queue.length = 0;
      queue.push(...next);
      hops += 1;
    }
    return out;
  };

  const top = selects.filter((s) => s.depth === 0);
  const branches = top.map((s) => s.items);
  const star = top.some((s) => s.items.some((i) => i.star));

  const maxLen = branches.reduce((m, b) => Math.max(m, b.length), 0);
  const byPosition = [];
  for (let i = 0; i < maxLen; i += 1) {
    const set = new Set();
    for (const branch of branches) {
      const item = branch[i];
      if (!item || item.star) continue;
      for (const name of expand(item.sources)) set.add(name);
    }
    byPosition.push(set);
  }

  const byOutput = new Map();
  for (const branch of branches) {
    for (const item of branch) {
      if (!item.out || item.star) continue;
      const key = String(item.out).toLowerCase();
      const set = byOutput.get(key) || new Set();
      for (const name of expand([...(item.sources || []), key])) set.add(name);
      byOutput.set(key, set);
    }
  }

  return { tokens, star, branches, byOutput, byPosition, derived };
}

/** Backwards-compatible view: the first top-level select list. */
export function projectionOf(sql) {
  const analysis = analyzeProjection(sql);
  return { items: analysis.branches[0] || [], star: analysis.star };
}
