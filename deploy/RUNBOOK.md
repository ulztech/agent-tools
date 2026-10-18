# Agent-tools — deployment runbook (C3)

One host, two trust zones. This is the **weaker** of the two isolation options: the host,
not a network segment, is the last boundary (AR-14). The precondition is absolute:
**no agent runtime, MCP client or LLM tooling runs on this host.**

## 1. Prerequisites

- Debian 12 / Ubuntu 24.04, full-disk encryption, no desktop.
- Docker 28+ with the Compose plugin.
- WireGuard for admin access.
- A TPM, or a sealed offline copy of the master key. The key **must not** live beside
  the database volume.

## 2. Master key

```bash
# Preferred: bind the key to the TPM.
systemd-creds encrypt --name=at-master-key /dev/stdin /etc/agent-tools/master.cred
# then expose it to the unit with LoadCredentialEncrypted=at-master-key:/etc/agent-tools/master.cred
```

For a non-TPM host, generate once and store it offline:

```bash
openssl rand -base64 32 > /root/at-master-key
chmod 600 /root/at-master-key
```

Put it in `deploy/.env` as `AT_MASTER_KEY=...` (the file is git-ignored). Without it the
platform refuses to start under `NODE_ENV=production`.

## 3. Start

```bash
cd deploy
docker compose --profile apps up -d --build
docker compose ps
```

Expected:

| Service | Ports | Networks |
|---|---|---|
| `platform` | **none** | `cp-net`, `authz-net` |
| `caddy` | `127.0.0.1:8443` · `:443` | `cp-net`, `authz-net`, `app-net`, `edge-net` |
| `durable-pi` | none | `app-net` |

## 4. Verify isolation (do this before enrolling anyone)

```bash
# 1. The control plane publishes nothing at all. Caddy does, on loopback.
docker compose port platform 8443       # -> empty
docker compose port caddy 8443          # -> 127.0.0.1:8443
ss -ltnp | grep 8443                    # -> 127.0.0.1 only

# 2. cp-net has no gateway.
docker network inspect agent-tools_cp-net -f '{{.Internal}}'   # -> true

# 3. From the edge network, the control plane is unreachable (DNS + routing).
docker run --rm --network agent-tools_edge-net curlimages/curl -m3 -sS http://platform:8443/healthz || echo BLOCKED
#    and the authz listener is reachable only from authz-net:
docker run --rm --network agent-tools_authz-net curlimages/curl -m3 -sS http://platform:8444/authz || echo '401 expected'

# 4. The nftables deny is loaded.
sudo nft list chain inet agenttools forward

# 5. Agent reachability: from the agent host, not from here.
nmap -Pn -p 8443,8444 <cph-ip>          # -> filtered/filtered
```

If any of 1–5 fails, **stop**. Do not enrol users onto a control plane that is reachable.

## 5. First owner

```bash
docker compose exec platform node --experimental-sqlite core/cli.js init --username ulcon
# prints a one-time /enroll?token=... path, valid 15 minutes
```

Open it through the tunnel at `https://console.agent-tools.internal:8443/enroll?token=...`.
Create a passkey, add the authenticator, save the recovery codes.

## 6. WireGuard

The console origin must match `AT_ORIGIN` exactly, or WebAuthn fails:

```
[Interface]
Address = 10.88.0.2/24

[Peer]
PublicKey = <cph>
AllowedIPs = 10.88.0.0/24, 10.89.0.0/24
Endpoint = <cph-public>:51820
```

Resolve `console.agent-tools.internal` only on the VPN (split-DNS or `/etc/hosts`), and
import Caddy's internal CA once per admin device.

## 7. durable-pi

It is registered automatically as an application with `member`, `admin`, `owner`. It has
no published port; Caddy is the only path in, and strips inbound `X-AT-*` before adding
its own. Signing a human in does **not** authorize the agents inside it — those still need
service passkeys against the gateway.

## 7b. Console freshness

The console reads a snapshot of gateway.sqlite and cannot see rows still sitting in the
gateway's -wal file. Normally the lag is seconds. Before relying on the inventory during
an incident, checkpoint:

``bash
node --experimental-sqlite src/cli.js checkpoint --data <gateway data dir>
``

## 8. Drills (record the result in the audit log)

| Drill | Command | Pass |
|---|---|---|
| **Rotation** | create a second signing key on the gateway, publish both in JWKS, retire the old one after the capability TTL | no tool call fails during the overlap |
| **Restore** | restore the platform volume into a scratch container | `verifyChain` returns `ok:true`; log in with a passkey |
| **Tamper** | edit one `auth_events` row in a copy | Overview reports the broken sequence |
| **Break-glass** | lose the authenticator on a test account | host CLI issues a one-time enrol token; second owner countersigns within 24 h |

## 9. Known deviations from the plan

- **Console transport:** published to `127.0.0.1`, not a unix socket. The property that
  matters (unreachable off-host) is identical; Docker cannot share a socket across
  containers without a bind mount.
- **Audit anchor:** the chain is HMAC-keyed from the master key, so forgery needs the key.
  Tail truncation is still undetectable without an external anchor — that is Phase E.
- **Signing key custody:** the gateway's key file on the `AT_GATEWAY_DATA` volume. TPM
  custody and rotation land with the platform owning the vault.
