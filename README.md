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
- **Masked columns are masked on egress.** Every returned column is resolved against
  the connection's masking registry. When the source of a column cannot be resolved
  from the query, it is matched **by column name** — because this gateway never blocks
  a result to stay safe.
- **Every access is audited.** Hash-chained records holding query *shape* and hash,
  never values or raw parameters.
- **No agent can reach the settings.** There is no tool, resource or endpoint that
  exposes connections, the registry, users, or vault contents.

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

Local state lives in `.data/` and is git-ignored. The master key and the signing key
are generated on first use; production installs must supply the master key from the
host keystore (see `docs/RUNBOOK` in the platform plan).

### CLI

```bash
node src/cli.js init
node src/cli.js connection add --name hris --engine mysql --host 127.0.0.1 --port 3306 \
  --user hruser --password '***' --database hris-regression
node src/cli.js registry set --connection hris --table employee --column email --strategy mask
node src/cli.js registry list --connection hris
node src/cli.js key mint --connection hris --label agent-1 --ttl 30d
node src/cli.js cap mint --key dbg_... --ttl 900
node src/cli.js query --cap atkcap_... --sql "select id, email from employee limit 5"
node src/cli.js audit verify
node src/cli.js jwks
```

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
  cli.js        admin CLI
test/           unit, capability, audit, gate, masking, adversarial
```

## Status

Phase A + B of the platform plan (`2026-10-18-agent-tools-platform.md`): data path,
capability issuance, masking engine, audit chain, CLI. The admin console, WebAuthn
passkeys, the MCP endpoint and the platform control plane are later phases.

## License

MIT.
