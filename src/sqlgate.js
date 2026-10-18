import { GatewayError } from './util.js';

const MAX_SQL_LENGTH = 20_000;

const ALLOWED_FIRST = new Set(['select', 'with', 'explain', 'describe', 'desc', 'show']);

const DENY_WORDS = new Set([
  'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate',
  'rename', 'grant', 'revoke', 'call', 'do', 'handler', 'lock', 'unlock',
  'prepare', 'execute', 'deallocate', 'set', 'into', 'outfile', 'dumpfile',
  'load_file', 'sleep', 'benchmark', 'get_lock', 'release_lock',
  'information_schema', 'performance_schema', 'mysql',
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
 */
export function assertReadOnly(sql) {
  const tokens = tokenize(sql);
  if (tokens.length === 0) throw new GatewayError('E_SQL_EMPTY', 'sql is empty');

  let statements = 0;
  depthWalk(tokens, (t, idx) => {
    if (t.type === 'punct' && t.value === ';') {
      const rest = tokens.slice(idx + 1);
      if (rest.length > 0) statements += 1;
      if (rest.length === 0) statements += 1;
      if (rest.length > 0) throw new GatewayError('E_SQL_MULTI', 'multiple statements are not allowed');
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
    if (t.type !== 'word') continue;
    const w = t.value.toLowerCase();
    if (DENY_WORDS.has(w)) {
      throw new GatewayError('E_SQL_NOT_READ_ONLY', `disallowed keyword: ${w}`);
    }
  }

  return tokens;
}

/**
 * Extract the select list and, for each output column, the source columns it reads.
 * This is what lets an aliased or wrapped PII column still be masked:
 *   SELECT CONCAT(first_name,' ',last_name) AS full  ->  full <- [first_name, last_name]
 */
export function projectionOf(sql) {
  const tokens = tokenize(sql);
  let depth = 0;
  let selectIdx = -1;
  let fromIdx = -1;
  for (let idx = 0; idx < tokens.length; idx += 1) {
    const t = tokens[idx];
    if (t.type === 'punct' && t.value === '(') depth += 1;
    else if (t.type === 'punct' && t.value === ')') depth -= 1;
    else if (depth === 0 && t.type === 'word') {
      const w = t.value.toLowerCase();
      if (w === 'select' && selectIdx === -1) selectIdx = idx;
      else if (w === 'from' && selectIdx !== -1) {
        fromIdx = idx;
        break;
      }
    }
  }
  if (selectIdx === -1) return { items: [], star: false };
  const end = fromIdx === -1 ? tokens.length : fromIdx;
  const list = tokens.slice(selectIdx + 1, end);

  const items = [];
  let current = [];
  let d = 0;
  const flush = () => {
    if (current.length === 0) return;
    items.push(describeItem(current));
    current = [];
  };
  for (const t of list) {
    if (t.type === 'punct' && t.value === '(') d += 1;
    if (t.type === 'punct' && t.value === ')') d -= 1;
    if (d === 0 && t.type === 'punct' && t.value === ',') {
      flush();
      continue;
    }
    current.push(t);
  }
  flush();

  const star = items.some((it) => it.star);
  return { items: items.filter((it) => !it.star), star };
}

function describeItem(tokens) {
  if (tokens.length === 1 && tokens[0].type === 'punct' && tokens[0].value === '*') {
    return { out: '*', sources: [], star: true };
  }
  // table.* shorthand
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
