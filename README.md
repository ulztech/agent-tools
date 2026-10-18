# Agent-tools

Agent-facing gateways behind **one** control plane: single login, one credential vault,
one policy engine, one hash-chained audit trail, one admin console.

**Feature 1 — Database Gateway.** The only path AI agents use to reach SQL databases.
Agents send a read-only query; the gateway checks a short-lived capability, runs the
query, masks every column listed in that table's masking inventory, writes an audit
record, and returns the rows. **No result is blocked.**

```text
agent ──query──► gateway ──► read-only gate ──► database
                    │                              │
                    │◄──────────── rows ───────────┘
                    ▼
           mask from registry inventory (always)
                    ▼
           audit (hash-chained, values never stored)
                    ▼
           masked rows ──► agent        never blocked
```

## What this protects

- **Credentials leave client configs.** Connections (host, port, user, password,
  database) are stored as one encrypted secret inside the gateway. MCP client configs
  carry a connection *name*, never a password.
- **Agents hold an asymmetric passkey, not a bearer token.** Creating a connection issues
  an ES256 service passkey bound to it. The private key stays on the agent host; the
  gateway stores only the public key and a reads-only envelope. A mint request is
  **signed**, never transmitted with the key.
- **Masked columns are masked on egress.** Every returned column is resolved against
  the connection's masking registry. When the source of a column cannot be resolved
  from the query, it is matched **by column name** — because this gateway never blocks
  a result to stay safe.
- **Every access is audited.** Hash-chained records holding query *shape* and hash,
  never values or raw parameters.
- **No agent can reach the settings.** There is no tool, resource or endpoint that
  exposes connections, the registry, users, or vault contents.
- **Unknowable shapes fail safe.** When the gateway cannot prove which output column maps
  to a registry column — a `*` mixed with other items, a join across a base table and a
  derived table, a union of stars, a nested derived chain — it **redacts every column**
  rather than guess. That is over-masking, never a leak.

## What this does **not** protect

Stated plainly, because a masking tool that oversells itself is worse than none:

> Tool results automatically mask PII-mapped columns per policy and log every access.
> This is defence-in-depth, not a guarantee: unmapped columns, and anything inferable
> from aggregates, counts, timing, or schema, are not protected. Use it as one control
> among several over personal data — never as the only one.

In particular, deliberately out of scope for v1:

| Not done | Why |
|---|---|
| Blocking or denying a result | Product decision — the gateway always returns a row set for an authorised read |
| Denying aggregates over masked columns | `COUNT(*) WHERE name='X'` and `AVG(salary)` remain a re-identification path |
| Masking unmapped columns | The registry is the control; the detector only writes an audit flag |
| Masked database views (I12) | Not implemented in this slice. App-layer masking is the only enforcement today; a gateway bypass would reach raw columns |
| Audit tail truncation | The hash chain detects modification of any existing record; deleting the newest rows can only be caught by the external WORM anchor planned for a later phase |
| `write` / `export` | No write scope and no export channel in v1 |
| PostgreSQL / SQL Server | MySQL/MariaDB only in v1 |

## Quick start

```bash
npm run build      # syntax gate over every module
npm test           # unit + capability + audit + gate + masking + adversarial suite
npm run verify     # build && test
```

**Verification is local.** There is no hosted CI — `npm run verify` is the gate. Run it
before every commit; it is the same command the pipeline's tester gate runs.

### CLI

```bash
node src/cli.js init
node src/cli.js connection add --name hris --engine mysql --host 127.0.0.1 --port 3306 \
  --user hruser --password '***' --database hris-regression
#   -> prints svc_id, kid and the key file path; the private key is written 0600
node src/cli.js registry set --connection hris --table employee --column email --strategy mask
node src/cli.js svc enroll --connection hris --label agent-2 --ttl 90d
node src/cli.js svc list
node src/cli.js svc revoke --id svc_...
node src/cli.js cap mint --svc svc_... --key-file .data/keys/hris.pem --ttl 900
node src/cli.js query --cap atkcap_... --sql "select id, email from employee limit 5"
node src/cli.js audit verify
node src/cli.js jwks
```

## Platform console (C1)

The identity core and the admin console live in `core/`.

```bash
npm run platform:init -- --username ulcon --display-name "Ulcon"
# prints a one-time /enroll?token=... URL — open it once

npm run platform
# listening on http://127.0.0.1:8443 (loopback only)
npm run platform:users
```

**Menu:** Overview · People · Tools · Applications · Policy · Audit · Settings —
role-filtered, subtraction only. A `member` sees the application launcher and their own
security, nothing else.

**Sign-in is passkey → TOTP.** An L1 session (passkey only) reaches nothing but the
second step; the session id rotates on elevation, so a cookie captured before the code is
useless afterwards. TOTP is any standard app — add the setup key shown at enrolment.

Not in this slice: QR rendering (the setup key is manual), TOTP rotation, and the
gateway inventory inside Tools/Policy — the gateway still owns it until C3.

Every auth event is hash-chained (`prev_hash` → `row_hash`) and the Overview reports the
verification result. The chain is **unkeyed**: it catches edits, deletions in the middle
and reordering, but someone who can write to the database can recompute the whole chain.
Keyed signing plus an external anchor land in C3.

## Deployment (C3)

`deploy/` holds the two-zone topology from the auth plan.

| Network | Purpose | Reachable from agents |
|---|---|---|
| `cp-net` | idp, sessions, console | **no** — `internal: true`, no gateway |
| `authz-net` | a single endpoint, `/authz` | **no** |
| `app-net` | durable-pi | only through Caddy |
| `edge-net` | the application proxy | — |

```bash
cd deploy
cp .env.example .env          # fill in AT_MASTER_KEY
docker compose --profile apps up -d --build
docker compose port platform  # 127.0.0.1:8443 — loopback only
```

The forward-auth decision runs on its **own listener** (`:8444`), so a proxy on the
application network can call `/authz` and nothing else. Caddy strips inbound `X-AT-*`
headers before adding its own, and durable-pi publishes no port.

Run the five isolation checks in `deploy/RUNBOOK.md` **before** enrolling anyone.

## Layout

```
src/
  util.js       ids, canonical json, errors
  store.js      SQLite schema, audit hash-chain
  crypto.js     master key, per-tool DEK, ES256 capability mint/verify
  sqlgate.js    tokenizer, read-only gate, projection/lineage extraction
  masking.js    registry, strategies, PII detector (audit-only)
  query.js      the data path: capability -> gate -> driver -> mask -> audit
  drivers.js    stub (tests) and MySQL adapter
  cli.js        gateway admin CLI
core/
  db.js         platform schema (users, passkeys, sessions, invites, apps)
  webauthn.js   registration + assertion, RP ID pinned, UV required
  totp.js       RFC 6238, ±1 step, replay-blocked
  sessions.js   L1/L2, idle + absolute expiry, id rotation on elevation
  nav.js        the seven-section menu and role filtering
  server.js     login, enrolment, console routes, forward-auth
  views.js      server-rendered pages
  cli.js        init / invite / users / serve
test/           gateway, capability, masking, adversarial, identity
```

## Status

Phase A + B of the platform plan, plus A2 (service passkeys) and C1+C2 of the identity
layer: passkey registration and assertion, TOTP, recovery codes, step-up, invites,
session management, role-based console, forward-auth for applications, and a
hash-chained auth log, gateway inventory in the console, and the C3 deployment topology.
Later: MCP transport over HTTP, signing-key rotation with JWKS overlap, and an external
anchor for the audit chain.

## License

MIT.
