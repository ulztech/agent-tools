import { canWrite, navFor } from './nav.js';

export function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const CSS = `
:root{--bg:#f7f7f5;--panel:#fff;--ink:#18181b;--muted:#6b7280;--line:#e5e7eb;--accent:#1f6feb;--warn:#b42318}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
header .brand{font-weight:650;letter-spacing:-.01em}
header .who{color:var(--muted);font-size:12.5px}
.shell{display:grid;grid-template-columns:210px 1fr;min-height:calc(100vh - 49px)}
nav{padding:14px 10px;border-right:1px solid var(--line);background:var(--panel)}
nav a{display:block;padding:8px 12px;border-radius:7px;color:var(--ink);text-decoration:none;font-weight:500}
nav a:hover{background:#f1f2f4}
nav a.active{background:#eaf1fe;color:var(--accent)}
main{padding:26px 32px;max-width:1100px}
h1{font-size:20px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:15px;margin:26px 0 8px}
p.lede{color:var(--muted);margin:0 0 18px}
table{border-collapse:collapse;width:100%;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:13px}
th{background:#fafafa;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat b{display:block;font-size:22px;letter-spacing:-.02em}
.stat span{color:var(--muted);font-size:12px}
code{background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:12.5px}
input,button{font:inherit}
input[type=text],input[type=password]{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:7px;background:#fff}
button{padding:9px 14px;border-radius:7px;border:1px solid var(--accent);background:var(--accent);color:#fff;font-weight:600;cursor:pointer}
button.ghost{background:#fff;color:var(--ink);border-color:var(--line)}
.err{color:var(--warn);font-size:13px;min-height:18px}
.muted{color:var(--muted)}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;background:#eef2f7;color:#334155;font-size:11.5px;font-weight:600}
.center{max-width:420px;margin:9vh auto}
`;

function shell({ title, user, active, body, csrf = '' }) {
  const items = user ? navFor(user.role) : [];
  const nav = items
    .map(
      (item) =>
        `<a href="${item.href}"${item.key === active ? ' class="active"' : ''}>${esc(item.label)}</a>`,
    )
    .join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="${esc(csrf)}">
<title>${esc(title)} · Agent-tools</title><style>${CSS}</style></head><body>
<header><span class="brand">Agent-tools</span>
<span class="who">${user ? `${esc(user.username)} · <span class="tag">${esc(user.role)}</span>` : 'not signed in'}${
    user
      ? `<a href="/me/security" style="margin-left:12px;font-size:12.5px">My security</a><form method="post" action="/auth/logout" style="display:inline;margin-left:12px"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="ghost" type="submit" style="padding:3px 9px">Sign out</button></form>`
      : ''
  }</span>
</header>
<div class="shell">${user ? `<nav>${nav}</nav>` : ''}<main>${body}</main></div>
</body></html>`;
}

function bare({ title, body, csrf = '' }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="${esc(csrf)}">
<title>${esc(title)} · Agent-tools</title><style>${CSS}</style></head>
<body><div class="center">${body}</div></body></html>`;
}

function table(headers, rows) {
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join('');
  const body = rows.length
    ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
    : `<tr><td colspan="${headers.length}" class="muted">Nothing here yet.</td></tr>`;
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

/* ------------------------------------------------------------------ */

export function loginPage({ error = '' } = {}) {
  return bare({
    title: 'Sign in',
    body: `<div class="card">
<h1>Sign in</h1>
<p class="lede">Passkey, then a code from your authenticator app.</p>
<form id="login-form">
<label for="username" class="muted">Username</label>
<input id="username" name="username" type="text" autocomplete="username webauthn" required autofocus>
<p class="err" id="err">${esc(error)}</p>
<button type="submit">Continue with a passkey</button>
</form>
<p class="muted" style="font-size:12px;margin-top:14px">No password exists on this system.</p>
</div>
<script src="/assets/login.js"></script>`,
  });
}

export function totpLoginPage({ error = '', username, csrf = '' }) {
  return bare({
    title: 'Authenticator code',
    body: `<div class="card">
<h1>Authenticator code</h1>
<p class="lede">Signed in as <strong>${esc(username)}</strong>. Enter the 6-digit code from your authenticator app.</p>
<form method="post" action="/auth/totp">
<input type="hidden" name="_csrf" value="${esc(csrf)}">
<label for="code" class="muted">Code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
<p class="err">${esc(error)}</p>
<button type="submit">Verify</button>
</form>
<p style="margin-top:14px"><a href="/login/recovery">Use a recovery code instead</a></p>
</div>`,
  });
}

export function enrollPage({ token, error = '' }) {
  return bare({
    title: 'Enrol',
    body: `<div class="card">
<h1>Set up your passkey</h1>
<p class="lede">Your invite is valid for one enrolment. You will create a passkey, then connect an authenticator app.</p>
<p class="err" id="err">${esc(error)}</p>
<button id="start">Create passkey</button>
<input type="hidden" id="token" value="${esc(token)}">
</div>
<script src="/assets/enroll.js"></script>`,
  });
}

export function enrollTotpPage({ secret, uri, error = '', csrf = '' }) {
  return bare({
    title: 'Connect authenticator',
    body: `<div class="card">
<h1>Connect your authenticator</h1>
<p class="lede">Add this account to Google Authenticator, Authy, Microsoft Authenticator, 1Password or any TOTP app.</p>
<p><strong>Setup key</strong><br><code>${esc(secret)}</code></p>
<p class="muted" style="font-size:12px;word-break:break-all">${esc(uri)}</p>
<form method="post" action="/enroll/totp">
<input type="hidden" name="_csrf" value="${esc(csrf)}">
<label for="code" class="muted">Enter the 6-digit code to confirm</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
<p class="err">${esc(error)}</p>
<button type="submit">Confirm and finish</button>
</form>
</div>`,
  });
}

export function overviewPage({ user, apps, counts, chain = { ok: true, checked: 0 } }) {
  const launcher =
    user.role === 'member'
      ? `<h2>Your applications</h2>${table(
          ['Application', 'Status'],
          apps.map((a) => [`<strong>${esc(a.name)}</strong>`, '<span class="tag">available</span>']),
        )}`
      : `<div class="grid">
<div class="stat"><b>${counts.users}</b><span>people</span></div>
<div class="stat"><b>${counts.apps}</b><span>applications</span></div>
<div class="stat"><b>${counts.sessions}</b><span>live sessions</span></div>
<div class="stat"><b>${counts.events}</b><span>auth events</span></div>
</div>`;

  return shell({
    title: 'Overview',
    user,
    active: 'overview',
    body: `<h1>Overview</h1>
<p class="lede">${user.role === 'member' ? 'Launch an application, or review your own security.' : 'What needs attention, and what is in the estate.'}</p>
${launcher}
<h2>Needs attention</h2>
<div class="card"><p style="margin:0">${
      chain.ok
        ? `<span class="tag">verified</span> Audit chain intact across ${chain.checked} events.`
        : `<span class="tag" style="background:#fee4e2;color:#b42318">broken</span> Audit chain failed at event ${chain.brokenAt}.`
    }</p></div>`,
  });
}

export function peoplePage({ user, users, sessions, invites = [] }) {
  const owner = canWrite(user.role, 'people');
  const csrf = esc(user.csrf_token);
  const inviteForm = owner
    ? `<h2>Invite someone</h2>
<div class="card">
<form method="post" action="/people/invite">
<input type="hidden" name="_csrf" value="${csrf}">
<label class="muted">Username</label>
<input type="text" name="username" required>
<label class="muted">Role</label>
<select name="role">
<option value="member">member</option>
<option value="auditor">auditor</option>
<option value="admin">admin</option>
<option value="owner">owner</option>
</select>
<p></p>
<button type="submit">Create invite</button>
</form>
</div>`
    : '';

  return shell({
    title: 'People',
    user,
    active: 'people',
    csrf: user.csrf_token,
    body: `<h1>People</h1><p class="lede">Who can sign in, and as what.</p>
${table(
  ['User', 'Role', 'Status', 'Passkeys', 'Last login'],
  users.map((u) => [
    `<a href="/people/${esc(u.id)}"><strong>${esc(u.username)}</strong></a>`,
    `<span class="tag">${esc(u.role)}</span>`,
    esc(u.status),
    String(u.passkeys ?? 0),
    esc(u.last_login_at || '—'),
  ]),
)}
${inviteForm}
<h2>Pending invitations</h2>
${table(
  ['User', 'Role', 'Expires', ''],
  invites.map((i) => [
    esc(i.username),
    `<span class="tag">${esc(i.role)}</span>`,
    esc(i.expires_at),
    owner
      ? `<form method="post" action="/people/invites/${esc(i.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${csrf}"><button class="ghost" type="submit">Revoke</button></form>`
      : '',
  ]),
)}
<h2>Live sessions</h2>
${table(
  ['User', 'Level', 'Last seen', ''],
  sessions.map((s) => [
    esc(s.username),
    s.auth_level === 2 ? 'L2 (passkey + TOTP)' : 'L1 (passkey only)',
    esc(s.last_seen_at),
    owner
      ? `<form method="post" action="/people/sessions/${esc(s.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${csrf}"><button class="ghost" type="submit">Revoke</button></form>`
      : '',
  ]),
)}`,
  });
}

export function inviteCreatedPage({ user, invite }) {
  return shell({
    title: 'Invite created',
    user,
    active: 'people',
    csrf: user.csrf_token,
    body: `<h1>Invite created</h1>
<p class="lede">Send this link out of band. It is shown once and expires in ${esc(invite.expiresInMinutes)} minutes.</p>
<div class="card"><p><code>${esc(invite.path)}</code></p>
<p class="muted" style="margin:0">For <strong>${esc(invite.username)}</strong> as <span class="tag">${esc(invite.role)}</span></p></div>
<p><a href="/people">Back to People</a></p>`,
  });
}

export function userDetailPage({ user, target, creds, sessions, events, recoveryRemaining }) {
  const owner = canWrite(user.role, 'people') && target.id !== user.id;
  const csrf = esc(user.csrf_token);
  const roleOptions = ['member', 'auditor', 'admin', 'owner']
    .map((r) => `<option value="${r}"${r === target.role ? ' selected' : ''}>${r}</option>`)
    .join('');

  return shell({
    title: target.username,
    user,
    active: 'people',
    csrf: user.csrf_token,
    body: `<h1>${esc(target.username)}</h1>
<p class="lede">${esc(target.display_name || target.username)} · <span class="tag">${esc(target.role)}</span> · ${esc(target.status)}</p>

${
  owner
    ? `<div class="card"><h2 style="margin-top:0">Role</h2>
<form method="post" action="/people/${esc(target.id)}/role">
<input type="hidden" name="_csrf" value="${csrf}">
<select name="role">${roleOptions}</select>
<button type="submit">Update role</button>
</form>
<form method="post" action="/people/${esc(target.id)}/status" style="margin-top:10px">
<input type="hidden" name="_csrf" value="${csrf}">
<input type="hidden" name="status" value="${target.status === 'active' ? 'suspended' : 'active'}">
<button class="ghost" type="submit">${target.status === 'active' ? 'Suspend account' : 'Reactivate account'}</button>
</form></div>`
    : ''
}

<h2>Passkeys</h2>
${table(
  ['Passkey', 'Created', 'Last used'],
  creds.map((c) => [`<code>${esc(c.nickname || c.id)}</code>`, esc(c.created_at), esc(c.last_used_at || '—')]),
)}
<h2>Second factor</h2>
<div class="card"><p style="margin:0">${
      target.totp_confirmed_at ? '<span class="tag">TOTP enrolled</span>' : '<span class="tag">not enrolled</span>'
    } · ${recoveryRemaining} recovery codes remaining</p></div>

<h2>Sessions</h2>
${table(
  ['Level', 'Last seen', ''],
  sessions.map((s) => [
    s.auth_level === 2 ? 'L2' : 'L1',
    esc(s.last_seen_at),
    owner
      ? `<form method="post" action="/people/sessions/${esc(s.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${csrf}"><button class="ghost" type="submit">Revoke</button></form>`
      : '',
  ]),
)}

<h2>Recent events</h2>
${table(
  ['When', 'Event', 'Result'],
  events.map((e) => [esc(e.ts), `<code>${esc(e.event)}</code>`, esc(e.result)]),
)}`,
  });
}

export function toolsPage({ user, inventory }) {
  const banner = inventory.available
    ? `<p class="muted">Read-only view of <code>${esc(inventory.dir)}</code> · ${inventory.auditEvents} gateway audit events</p>`
    : `<div class="card"><p style="margin:0">Gateway store not readable: ${esc(inventory.reason)}. Set <code>AT_GATEWAY_DATA</code> to the gateway data directory.</p></div>`;

  return shell({
    title: 'Tools',
    user,
    active: 'tools',
    body: `<h1>Tools</h1><p class="lede">What an agent can reach.</p>
${banner}
<h2>Tools</h2>
${table(
  ['Tool', 'Profile'],
  inventory.tools.map((t) => [`<strong>${esc(t.name)}</strong>`, `<span class="tag">${esc(t.profile)}</span>`]),
)}
<h2>Connections</h2>
${table(
  ['Name', 'Engine', 'Host', 'Database', 'Status'],
  inventory.connections.map((c) => [
    `<strong>${esc(c.name)}</strong>`,
    esc(c.engine),
    `<code>${esc(c.host)}:${esc(c.port)}</code>`,
    esc(c.database_name),
    `<span class="tag">${esc(c.status)}</span>`,
  ]),
)}
<h2>Service passkeys</h2>
${table(
  ['Connection', 'Label', 'kid', 'Envelope', 'Expires', 'Minted today'],
  inventory.credentials.map((s) => [
    esc(s.connection),
    esc(s.label),
    `<code>${esc(s.kid)}</code>`,
    `<code>${esc(s.envelope)}</code>`,
    esc(s.expires_at),
    s.revoked_at ? '<span class="tag">revoked</span>' : String(s.minted_today),
  ]),
)}`,
  });
}

export function applicationsPage({ user, apps, health = {} }) {
  return shell({
    title: 'Applications',
    user,
    active: 'applications',
    body: `<h1>Applications</h1><p class="lede">What a person can sign into. Access is role → application, never a per-app user list.</p>
${table(
  ['Application', 'Upstream', 'Auth mode', 'Allowed roles', 'Status', 'Health'],
  apps.map((a) => [
    `<strong>${esc(a.name)}</strong>`,
    `<code>${esc(a.upstream_url)}</code>`,
    esc(a.auth_mode),
    esc(JSON.parse(a.allowed_roles).join(', ')),
    `<span class="tag">${esc(a.status)}</span>`,
    `<span class="tag">${esc(health[a.name] || 'unknown')}</span>`,
  ]),
)}
<h2>Signing users in</h2>
<div class="card"><p class="muted" style="margin:0">forward-auth: the proxy calls <code>/authz</code>, receives <code>X-AT-User</code> and <code>X-AT-Roles</code>, and strips any inbound copy. durable-pi stays reachable only through the proxy.</p></div>`,
  });
}

export function policyPage({ user, inventory }) {
  return shell({
    title: 'Policy',
    user,
    active: 'policy',
    body: `<h1>Policy</h1><p class="lede">What gets masked, and who may use what.</p>
<div class="card"><p style="margin:0">Read-only here. The registry is edited on the gateway until the platform owns the store.</p></div>
<h2>Masking registry</h2>
${table(
  ['Connection', 'Table', 'Column', 'Strategy', 'State'],
  inventory.registry.map((r) => [
    esc(r.connection),
    esc(r.table_name),
    `<code>${esc(r.column_name)}</code>`,
    `<span class="tag">${esc(r.strategy)}</span>`,
    r.enabled ? 'enforced' : 'disabled',
  ]),
)}
<h2>Access rules</h2>
${table(
  ['Rule', 'State'],
  [
    ['Capability envelopes', 'reads-only · ≤900 s · daily quota'],
    ['Role → application', 'editable under Applications'],
    ['Trifecta', 'private-read blocks external-send'],
  ],
)}`,
  });
}

export function auditPage({ user, events }) {
  return shell({
    title: 'Audit',
    user,
    active: 'audit',
    body: `<h1>Audit</h1><p class="lede">Authentication events. Query and domain audit arrive with the gateway inventory in C3.</p>
${table(
  ['When', 'User', 'Event', 'Factor', 'Result'],
  events.map((e) => [
    esc(e.ts),
    esc(e.user_id || '—'),
    `<code>${esc(e.event)}</code>`,
    esc(e.factor || '—'),
    esc(e.result),
  ]),
)}`,
  });
}

export function settingsPage({ user, rp, signing, inventory }) {
  return shell({
    title: 'Settings',
    user,
    active: 'settings',
    body: `<h1>Settings</h1><p class="lede">Keys, system, backups and drills.</p>
<h2>WebAuthn relying party</h2>
${table(
  ['Setting', 'Value'],
  [
    ['RP ID', `<code>${esc(rp.rpID)}</code>`],
    ['Origin', `<code>${esc(rp.origin)}</code>`],
    ['User verification', 'required'],
    ['Algorithm', 'ES256 (pinned by the library)'],
  ],
)}
<h2>Capability signing key</h2>
${
      signing.present
        ? `${table(
            ['Setting', 'Value'],
            [
              ['kid', `<code>${esc(signing.kid)}</code>`],
              ['alg', esc(signing.alg)],
              ['custody', 'gateway host keystore'],
            ],
          )}
<pre style="background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:11.5px">${esc(JSON.stringify(signing.jwks, null, 2))}</pre>`
        : `<div class="card"><p style="margin:0">No signing key found in the gateway store${signing.reason ? `: ${esc(signing.reason)}` : ''}.</p></div>`
    }
<h2>Gateway store</h2>
<div class="card"><p style="margin:0">${
      inventory.available
        ? `<span class="tag">connected</span> <code>${esc(inventory.dir)}</code> · ${inventory.connections.length} connections · ${inventory.registry.length} registry rules`
        : `<span class="tag">not found</span> ${esc(inventory.reason)}`
    }</p></div>
<h2>Backups and drills</h2>
<div class="card"><p class="muted" style="margin:0">Rotation, restore and break-glass drills are run from the runbook; results are recorded in the audit log.</p></div>`,
  });
}

export function meSecurityPage({ user, creds, totpConfirmed, recoveryRemaining = 0 }) {
  return shell({
    title: 'My security',
    user,
    active: 'me',
    body: `<h1>My security</h1><p class="lede">Your passkeys and second factor.</p>
<h2>Passkeys</h2>
${table(
  ['Passkey', 'Created', 'Last used', ''],
  creds.map((c) => [
    `<code>${esc(c.nickname || c.id)}</code>`,
    esc(c.created_at),
    esc(c.last_used_at || '—'),
    creds.length > 1
      ? `<form method="post" action="/me/security/passkeys/${esc(c.id)}/remove" style="margin:0"><input type="hidden" name="_csrf" value="${esc(user.csrf_token)}"><button class="ghost" type="submit">Remove</button></form>`
      : '',
  ]),
)}
<h2>Authenticator app</h2>
<div class="card"><p style="margin:0">${
      totpConfirmed
        ? '<span class="tag">enrolled</span> A 6-digit code is required at every sign-in.'
        : '<span class="tag">not enrolled</span>'
    }</p>
<form method="post" action="/me/security/totp/rotate" style="margin-top:10px">
<input type="hidden" name="_csrf" value="${esc(user.csrf_token)}">
<button class="ghost" type="submit">Set up a new authenticator</button>
</form></div>

<h2>Recovery codes</h2>
<div class="card"><p style="margin:0"><strong>${recoveryRemaining}</strong> unused. A code replaces the authenticator factor once — never the passkey.</p>
<form method="post" action="/me/security/recovery/regenerate" style="margin-top:10px">
<input type="hidden" name="_csrf" value="${esc(user.csrf_token)}">
<button class="ghost" type="submit">Regenerate codes</button>
</form></div>`,
  });
}

export function meActivityPage({ user, events }) {
  return shell({
    title: 'My activity',
    user,
    active: 'me',
    body: `<h1>My activity</h1><p class="lede">Your own authentication events.</p>
${table(
  ['When', 'Event', 'Factor', 'Result'],
  events.map((e) => [
    esc(e.ts),
    `<code>${esc(e.event)}</code>`,
    esc(e.factor || '—'),
    esc(e.result),
  ]),
)}`,
  });
}

export function stepUpPage({ next, csrf }) {
  return bare({
    title: 'Confirm',
    csrf,
    body: `<div class="card">
<h1>Confirm it's you</h1>
<p class="lede">This action needs a fresh passkey check. It is valid for five minutes.</p>
<p class="err" id="err"></p>
<button id="stepup" data-csrf="${esc(csrf)}" data-next="${esc(next)}">Use passkey</button>
</div>
<script src="/assets/stepup.js"></script>`,
  });
}

export function recoveryCodesPage({ codes, csrf }) {
  return bare({
    title: 'Recovery codes',
    csrf,
    body: `<div class="card">
<h1>Save your recovery codes</h1>
<p class="lede">Each code can replace your authenticator once. They are shown once and never again.</p>
<p>${codes.map((c) => `<code>${esc(c)}</code>`).join('<br>')}</p>
<form method="post" action="/enroll/recovery/ack">
<input type="hidden" name="_csrf" value="${esc(csrf)}">
<button type="submit">I have saved them</button>
</form>
</div>`,
  });
}

export function recoveryLoginPage({ error = '', csrf = '' }) {
  return bare({
    title: 'Recovery code',
    csrf,
    body: `<div class="card">
<h1>Use a recovery code</h1>
<p class="lede">This replaces your authenticator code once.</p>
<form method="post" action="/auth/recovery">
<input type="hidden" name="_csrf" value="${esc(csrf)}">
<input type="text" name="code" placeholder="ABCDE-FGHIJ" required autofocus>
<p class="err">${esc(error)}</p>
<button type="submit">Continue</button>
</form>
</div>`,
  });
}

export function errorPage({ status, message, user = null }) {
  return shell({
    title: String(status),
    user,
    active: null,
    body: `<h1>${status}</h1><p class="lede">${esc(message)}</p><p><a href="/">Back to the console</a></p>`,
  });
}
