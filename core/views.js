import { canWrite, navFor } from './nav.js';

let CURRENT_MODE = 'passkey+totp';

/** Set once by the server so every auth screen renders the right copy and steps. */
export function setAuthMode(mode) {
  CURRENT_MODE = mode;
}

export function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const CSS = `
:root{
  --ink:#0f172a;--slate:#475569;--muted:#64748b;--faint:#94a3b8;
  --line:#e2e8f0;--line-soft:#eef2f7;--surface:#fff;--canvas:#f6f8fb;
  --accent:#1d4ed8;--accent-ink:#1e40af;--accent-soft:#eff4ff;
  --ok:#0f766e;--danger:#b91c1c;--danger-soft:#fef2f2;
  --radius:10px;--shadow:0 1px 2px rgba(15,23,42,.05),0 8px 24px rgba(15,23,42,.06);
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--canvas);color:var(--ink);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{margin:0;letter-spacing:-.02em}
code{font:500 12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--line-soft);
  border:1px solid var(--line);border-radius:5px;padding:1px 5px}
pre{font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

/* ---------- auth ---------- */
.auth{min-height:100vh;display:grid;grid-template-columns:minmax(0,400px) 1fr}
.auth-aside{background:linear-gradient(165deg,#0b1220 0%,#111c33 55%,#16233d 100%);
  color:#cbd5e1;padding:44px 40px;display:flex;flex-direction:column;justify-content:space-between;gap:32px}
.brandmark{display:flex;align-items:center;gap:10px;color:#fff;font-weight:650;letter-spacing:-.01em;font-size:15px}
.brandmark .glyph{width:30px;height:30px;border-radius:8px;background:#fff;color:#0b1220;display:grid;
  place-items:center;font-weight:800;font-size:12px;letter-spacing:0}
.auth-aside h2{color:#fff;font-size:21px;line-height:1.3;margin:0 0 10px}
.auth-aside .lede{color:#94a3b8;margin:0 0 24px;font-size:13.5px}
.assurances{list-style:none;padding:0;margin:0;display:grid;gap:14px}
.assurances li{display:grid;grid-template-columns:16px 1fr;gap:10px;font-size:12.5px;color:#94a3b8;line-height:1.45}
.assurances .dot{width:6px;height:6px;border-radius:50%;background:#3b82f6;margin-top:7px}
.assurances b{color:#e2e8f0;font-weight:600}
.aside-foot{font-size:11.5px;color:#64748b;letter-spacing:.03em;text-transform:uppercase}
.auth-main{display:flex;align-items:center;justify-content:center;padding:48px 24px}
.auth-card{width:100%;max-width:404px}
.auth-title{font-size:23px;margin:0 0 6px}
.auth-sub{color:var(--muted);margin:0 0 24px;font-size:13.5px}
.steps{display:flex;gap:8px;margin:0 0 28px}
.step{flex:1;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint);
  border-top:2px solid var(--line);padding-top:8px;font-weight:600}
.step.on{color:var(--accent-ink);border-top-color:var(--accent)}
.step.done{color:var(--ok);border-top-color:var(--ok)}
.label{display:block;font-size:12.5px;font-weight:600;color:var(--slate);margin:0 0 6px}
.input{width:100%;height:44px;padding:0 12px;border:1px solid var(--line);border-radius:8px;
  background:#fff;color:var(--ink);font:inherit;transition:border-color .15s,box-shadow .15s}
.input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(29,78,216,.12)}
.input.code{letter-spacing:.42em;font-size:20px;font-weight:600;text-align:center;font-variant-numeric:tabular-nums}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;height:44px;
  border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#fff;font:inherit;
  font-weight:600;cursor:pointer;transition:background .15s,border-color .15s}
.btn:hover{background:var(--accent-ink);border-color:var(--accent-ink)}
.btn:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(29,78,216,.25)}
.btn[disabled]{opacity:.55;cursor:progress}
.btn.secondary{background:#fff;color:var(--ink);border-color:var(--line)}
.btn.secondary:hover{background:#f8fafc;border-color:#cbd5e1}
.btn.small{width:auto;height:34px;padding:0 12px;font-size:12.5px}
.hint{color:var(--muted);font-size:12.5px;margin:14px 0 0}
.hint a{font-weight:600}
.alert{border-left:3px solid var(--danger);background:var(--danger-soft);color:#7f1d1d;
  padding:10px 12px;border-radius:6px;font-size:13px;margin:0 0 14px}
.alert[hidden]{display:none}
.field{margin:0 0 16px}
.choice{display:grid;gap:8px;margin:0 0 18px}
.choice label{display:grid;grid-template-columns:18px 1fr;gap:10px;align-items:start;
  border:1px solid var(--line);border-radius:8px;padding:11px 12px;cursor:pointer;background:#fff;transition:border-color .15s,background .15s}
.choice label:hover{border-color:#cbd5e1;background:#fcfdff}
.choice label:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}
.choice input{margin:3px 0 0}
.choice b{display:block;font-size:13px}
.choice span{color:var(--muted);font-size:12px}
.setup-key{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;margin:0 0 18px}
.qr{display:grid;place-items:center;background:#fff;border:1px solid var(--line);border-radius:12px;padding:12px;margin:0 0 18px}
.qr svg{width:196px;height:196px;display:block}
.setup-key code{background:#f8fafc;border:1px solid var(--line);border-radius:8px;padding:11px 12px;
  font-size:14px;letter-spacing:.08em;text-align:center;overflow-wrap:anywhere}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0 18px}
.codes code{background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:9px 8px;
  text-align:center;font-size:13px;letter-spacing:.06em;background-image:none}
.check{display:grid;grid-template-columns:18px 1fr;gap:9px;align-items:start;font-size:12.5px;
  color:var(--slate);margin:0 0 16px}
.overlay{position:fixed;inset:0;background:rgba(15,23,42,.55);display:none;align-items:center;
  justify-content:center;z-index:50;backdrop-filter:blur(2px)}
.overlay.on{display:flex}
.overlay .box{background:#fff;border-radius:12px;padding:26px 28px;max-width:340px;text-align:center;
  box-shadow:0 24px 60px rgba(15,23,42,.28)}
.spinner{width:26px;height:26px;border:3px solid #dbe3ef;border-top-color:var(--accent);
  border-radius:50%;margin:0 auto 14px;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.overlay b{display:block;margin:0 0 4px}
.overlay p{margin:0;color:var(--muted);font-size:12.5px}

/* ---------- console ---------- */
header{display:flex;align-items:center;justify-content:space-between;height:56px;padding:0 22px;
  background:var(--surface);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}
header .brand{display:flex;align-items:center;gap:9px;font-weight:650;letter-spacing:-.01em;font-size:14px}
header .glyph{width:26px;height:26px;border-radius:7px;background:linear-gradient(160deg,#0b1220,#1e293b);
  color:#fff;display:grid;place-items:center;font-size:10.5px;font-weight:800}
header .who{display:flex;align-items:center;gap:14px;color:var(--muted);font-size:12.5px}
header .who a{color:var(--slate);font-weight:500}
header form{margin:0}
.shell{display:grid;grid-template-columns:216px 1fr;min-height:calc(100vh - 56px)}
nav{padding:18px 12px;border-right:1px solid var(--line);background:var(--surface)}
nav .navlabel{font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--faint);
  font-weight:700;padding:0 12px;margin:0 0 10px}
nav a{display:block;padding:9px 12px;border-radius:7px;color:var(--slate);text-decoration:none;
  font-weight:500;font-size:13.5px;border-left:2px solid transparent}
nav a:hover{background:#f8fafc;color:var(--ink);text-decoration:none}
nav a.active{background:var(--accent-soft);color:var(--accent-ink);border-left-color:var(--accent);font-weight:600}
main{padding:32px 40px 56px;max-width:1120px;width:100%}
h1{font-size:22px;margin:0 0 4px}
p.lede{color:var(--muted);margin:0 0 22px;font-size:13.5px}
h2{font-size:14px;margin:30px 0 10px;letter-spacing:-.01em}
table{border-collapse:separate;border-spacing:0;width:100%;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line-soft);font-size:13px;vertical-align:middle}
th{background:#fbfcfe;color:var(--muted);font-weight:600;font-size:11.5px;letter-spacing:.03em;text-transform:uppercase}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:#fcfdff}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  padding:18px 20px;margin:0 0 14px;box-shadow:var(--shadow)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:16px 18px}
.stat b{display:block;font-size:24px;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:12px}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;background:var(--line-soft);color:#334155;
  font-size:11px;font-weight:600;letter-spacing:.01em}
.tag.ok{background:#ecfdf5;color:#065f46}
.tag.warn{background:#fef2f2;color:#991b1b}
.muted{color:var(--muted)}
.stack{display:grid;gap:14px}
.kv{display:grid;grid-template-columns:160px 1fr;gap:8px 14px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0}

@media (max-width:900px){
  .auth{grid-template-columns:1fr}
  .auth-aside{display:none}
  .auth-main{padding:32px 20px}
  .shell{grid-template-columns:1fr}
  nav{display:flex;overflow-x:auto;border-right:0;border-bottom:1px solid var(--line);padding:10px 12px;gap:4px}
  nav .navlabel{display:none}
  nav a{white-space:nowrap;border-left:0;border-bottom:2px solid transparent;border-radius:6px}
  nav a.active{border-left:0;border-bottom-color:var(--accent)}
  main{padding:24px 18px 48px}
}
`;

function stepper(step, items = ['Passkey', 'Authenticator', 'Recovery codes']) {
  if (!step) return '';
  return `<div class="steps">${items
    .map((label, index) => {
      const n = index + 1;
      const cls = n === step ? 'on' : n < step ? 'done' : '';
      return `<div class="step ${cls}">${n}. ${label}</div>`;
    })
    .join('')}</div>`;
}

function overlay(text = 'Waiting for your device') {
  return `<div class="overlay" id="wait"><div class="box"><div class="spinner"></div>
<b>${esc(text)}</b><p>Complete the prompt from your device.</p></div></div>`;
}

function authShell({ title, step = 0, body, csrf = '', lede = 'Secure access to your agent estate.', mode = CURRENT_MODE }) {
  const labels =
    mode === 'password+totp'
      ? ['Password', 'Authenticator', 'Recovery codes']
      : mode === 'totp'
        ? ['Account', 'Authenticator', 'Recovery codes']
        : ['Passkey', 'Authenticator', 'Recovery codes'];
  const blurb =
    mode === 'password+totp'
      ? 'Password first, authenticator second. Every sign-in is audited.'
      : mode === 'totp'
        ? 'One-time code from your authenticator app. Every sign-in is audited.'
        : 'Passkey first, authenticator second. No password exists on this system.';
  const firstAssurance =
    mode === 'password+totp'
      ? '<b>Hashed at rest</b><br>Your password is stored only as a salted scrypt hash.'
      : mode === 'totp'
        ? '<b>Rotating code</b><br>A fresh 6-digit code every 30 seconds.'
        : '<b>Phishing-resistant</b><br>Your passkey is bound to this origin and never leaves your device.';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="${esc(csrf)}">
<title>${esc(title)} · Agent-tools</title><style>${CSS}</style></head><body>
<div class="auth">
  <aside class="auth-aside">
    <div class="brandmark"><span class="glyph">AT</span> Agent-tools</div>
    <div>
      <h2>${esc(lede)}</h2>
      <p class="lede">${blurb}</p>
      <ul class="assurances">
        <li><span class="dot"></span><div>${firstAssurance}</div></li>
        <li><span class="dot"></span><div><b>Two independent factors</b><br>A passkey on your device, a code from your authenticator app.</div></li>
        <li><span class="dot"></span><div><b>Every action is audited</b><br>Sign-ins, step-ups and changes are written to a hash-chained log.</div></li>
      </ul>
    </div>
    <div class="aside-foot">Control plane · internal deployment</div>
  </aside>
  <main class="auth-main">
    <div class="auth-card">
      ${stepper(step, labels)}
      ${body}
    </div>
  </main>
</div>
</body></html>`;
}

function consoleShell({ title, user, active, body, csrf = '' }) {
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
<header>
  <span class="brand"><span class="glyph">AT</span> Agent-tools</span>
  <span class="who">
    ${user ? `${esc(user.username)} · <span class="tag">${esc(user.role)}</span>` : 'not signed in'}
    ${user ? `<a href="/me/security">My security</a>` : ''}
    ${
      user
        ? `<form method="post" action="/auth/logout"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn secondary small" type="submit">Sign out</button></form>`
        : ''
    }
  </span>
</header>
<div class="shell">${user ? `<nav><p class="navlabel">Control plane</p>${nav}</nav>` : ''}<main>${body}</main></div>
</body></html>`;
}

function table(headers, rows) {
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join('');
  const body = rows.length
    ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
    : `<tr><td colspan="${headers.length}" class="muted">Nothing here yet.</td></tr>`;
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

/* ------------------------------------------------------------------ */
/* Authentication screens                                             */
/* ------------------------------------------------------------------ */

export function loginPasswordPage({ error = '', remembered = null }) {
  if (remembered) {
    return authShell({
      title: 'Welcome back',
      step: 1,
      lede: 'Sign in to the control plane.',
      body: `<h1 class="auth-title">Welcome back</h1>
<p class="auth-sub">This browser is remembered as <strong>${esc(remembered)}</strong>. You still need your authenticator code.</p>
<form method="post" action="/auth/remember">
  <button class="btn" type="submit">Continue as ${esc(remembered)}</button>
</form>
<p class="hint"><a href="/login?switch=1">Use another account</a></p>`,
    });
  }
  return authShell({
    title: 'Sign in',
    step: 1,
    lede: 'Sign in to the control plane.',
    body: `<h1 class="auth-title">Sign in</h1>
<p class="auth-sub">Account and password, then the code from your authenticator app.</p>
<form method="post" action="/auth/password">
  <div class="field">
    <label class="label" for="username">Username</label>
    <input class="input" id="username" name="username" type="text" autocomplete="username" required autofocus>
  </div>
  <div class="field">
    <label class="label" for="password">Password</label>
    <input class="input" id="password" name="password" type="password" autocomplete="current-password" required>
  </div>
  <p class="alert" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit">Sign in</button>
</form>
<p class="hint">After this, the authenticator code is requested. This browser can be remembered for 30 days — the code is required every time.</p>`,
  });
}

export function enrollPasswordPage({ token, username, error = '' }) {
  const choosable = !username;
  return authShell({
    title: 'Create account',
    step: 1,
    mode: 'password+totp',
    lede: 'Set up your account.',
    body: `<h1 class="auth-title">Create your account</h1>
<p class="auth-sub">${
      choosable
        ? 'Choose your login name and a password. The password is stored only as a salted scrypt hash.'
        : `Set a password for <strong>${esc(username)}</strong>. It is stored only as a salted scrypt hash.`
    }</p>
<form method="post" action="/enroll/password">
  <input type="hidden" name="token" value="${esc(token)}">
  ${
    choosable
      ? `<div class="field">
    <label class="label" for="username">Username</label>
    <input class="input" id="username" name="username" type="text" autocomplete="username"
      pattern="[a-z0-9][a-z0-9._-]*" maxlength="64" required autofocus>
    <p class="hint" style="margin-top:6px">Lowercase letters, digits, dot, underscore or hyphen.</p>
  </div>`
      : ''
  }
  <div class="field">
    <label class="label" for="password">Password</label>
    <input class="input" id="password" name="password" type="password" autocomplete="new-password" minlength="12" required ${choosable ? '' : 'autofocus'}>
    <p class="hint" style="margin-top:6px">At least 12 characters. Length beats complexity.</p>
  </div>
  <div class="field">
    <label class="label" for="confirm">Confirm password</label>
    <input class="input" id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="12" required>
  </div>
  <p class="alert" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit">Continue</button>
</form>
<p class="hint">Next: scan a QR code with Google Authenticator, then confirm one code.</p>`,
  });
}

export function loginPage({ error = '', mode = 'passkey+totp', remembered = null } = {}) {
  if (mode === 'password+totp') return loginPasswordPage({ error, remembered });
  const totp = mode === 'totp';
  return authShell({
    title: 'Sign in',
    step: 1,
    lede: 'Sign in to the control plane.',
    body: `<h1 class="auth-title">Sign in</h1>
<p class="auth-sub">${
      totp
        ? 'Enter your username, then the 6-digit code from your authenticator app.'
        : 'Use the passkey registered for your account.'
    }</p>
<form id="login-form" novalidate>
  <input type="hidden" id="mode" value="${esc(mode)}">
  <div class="field">
    <label class="label" for="username">Username</label>
    <input class="input" id="username" name="username" type="text" autocomplete="username webauthn" required autofocus>
  </div>
  <p class="alert" id="err" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit" id="submit">${totp ? 'Continue' : 'Continue with passkey'}</button>
</form>
<p class="hint">${
      totp
        ? 'Your authenticator app supplies a new code every 30 seconds.'
        : 'You will be prompted by your device, then asked for a 6-digit code.'
    }</p>
${overlay(totp ? 'Checking your account' : 'Waiting for your passkey')}
<script src="/assets/login.js"></script>`,
  });
}

export function totpLoginPage({ error = '', username, csrf = '' }) {
  return authShell({
    title: 'Authenticator code',
    step: 2,
    csrf,
    lede: 'One more step.',
    body: `<h1 class="auth-title">Authenticator code</h1>
<p class="auth-sub">Signed in as <strong>${esc(username)}</strong>. Enter the 6-digit code from your authenticator app.</p>
<form method="post" action="/auth/totp">
  <input type="hidden" name="_csrf" value="${esc(csrf)}">
  <div class="field">
    <label class="label" for="code">Verification code</label>
    <input class="input code" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code"
      pattern="[0-9]{6}" maxlength="6" placeholder="000000" required autofocus>
  </div>
  <p class="alert" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit">Verify and continue</button>
</form>
<p class="hint"><a href="/login/recovery">Use a recovery code instead</a></p>`,
  });
}

export function enrollPage({ token, error = '', mode = 'passkey+totp' }) {
  const totp = mode === 'totp';
  return authShell({
    title: totp ? 'Create account' : 'Create passkey',
    step: 1,
    lede: 'Set up your account.',
    body: `<h1 class="auth-title">${totp ? 'Create your account' : 'Create your passkey'}</h1>
<p class="auth-sub">${
      totp
        ? 'Your account is protected by a 6-digit code from an authenticator app such as Google Authenticator.'
        : 'A passkey replaces your password. It stays on your device and is unlocked with your fingerprint, face or PIN.'
    }</p>
${
      totp
        ? ''
        : `<div class="choice">
  <label><input type="radio" name="device" value="platform" checked>
    <div><b>This device</b><span>Windows Hello, Touch ID or Android biometrics</span></div></label>
  <label><input type="radio" name="device" value="cross-platform">
    <div><b>Phone or security key</b><span>Scan a QR code with your phone, or insert a USB key</span></div></label>
</div>`
    }
<p class="alert" id="err" ${error ? '' : 'hidden'}>${esc(error)}</p>
<button id="start" class="btn">${totp ? 'Set up authenticator app' : 'Continue'}</button>
<input type="hidden" id="token" value="${esc(token)}">
<input type="hidden" id="mode" value="${esc(mode)}">
<p class="hint">${
      totp
        ? 'You will scan a QR code with your phone, then enter one code to finish.'
        : 'Next you will connect an authenticator app for the second factor.'
    }</p>
${overlay(totp ? 'Preparing your authenticator' : 'Waiting for your device')}
<script src="/assets/enroll.js"></script>`,
  });
}

export function enrollTotpPage({ secret, uri, qr = '', error = '', csrf = '' }) {
  return authShell({
    title: 'Connect authenticator',
    step: 2,
    csrf,
    lede: 'Add the second factor.',
    body: `<h1 class="auth-title">Connect your authenticator</h1>
<p class="auth-sub">Scan this code with Google Authenticator, Microsoft Authenticator, Authy, 1Password or any TOTP app.</p>
${qr ? `<div class="qr">${qr}</div>` : ''}
<label class="label">Or enter the setup key</label>
<div class="setup-key">
  <code id="secret">${esc(secret)}</code>
  <button class="btn secondary small" type="button" id="copy" data-secret="${esc(secret)}">Copy</button>
</div>
<p class="hint" style="margin:-8px 0 18px">Prefer a link? <code style="word-break:break-all">${esc(uri)}</code></p>
<form method="post" action="/enroll/totp">
  <input type="hidden" name="_csrf" value="${esc(csrf)}">
  <div class="field">
    <label class="label" for="code">Enter the 6-digit code to confirm</label>
    <input class="input code" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code"
      pattern="[0-9]{6}" maxlength="6" placeholder="000000" required autofocus>
  </div>
  <p class="alert" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit">Confirm and continue</button>
</form>
<script src="/assets/copy.js"></script>`,
  });
}

export function recoveryCodesPage({ codes, csrf }) {
  return authShell({
    title: 'Recovery codes',
    step: 3,
    csrf,
    lede: 'Keep a way back in.',
    body: `<h1 class="auth-title">Save your recovery codes</h1>
<p class="auth-sub">Each code replaces your authenticator once. They are shown once and never again.</p>
<div class="codes" id="codes">${codes.map((c) => `<code>${esc(c)}</code>`).join('')}</div>
<div style="display:flex;gap:8px;margin:0 0 18px">
  <button class="btn secondary small" type="button" id="copy-codes" style="width:100%">Copy all</button>
  <button class="btn secondary small" type="button" id="download-codes" style="width:100%">Download</button>
</div>
<form method="post" action="/enroll/recovery/ack">
  <input type="hidden" name="_csrf" value="${esc(csrf)}">
  <label class="check"><input type="checkbox" id="saved" required>
    <span>I have saved these codes somewhere safe. I understand they will not be shown again.</span></label>
  <button class="btn" type="submit" id="ack">Finish setup</button>
</form>
<script src="/assets/recovery.js"></script>`,
  });
}

export function recoveryLoginPage({ error = '', csrf = '' }) {
  return authShell({
    title: 'Recovery code',
    step: 2,
    csrf,
    lede: 'Recover access.',
    body: `<h1 class="auth-title">Use a recovery code</h1>
<p class="auth-sub">This replaces your authenticator code once, and does not bypass your passkey.</p>
<form method="post" action="/auth/recovery">
  <input type="hidden" name="_csrf" value="${esc(csrf)}">
  <div class="field">
    <label class="label" for="code">Recovery code</label>
    <input class="input code" id="code" name="code" type="text" autocomplete="off" placeholder="ABCDE-FGHIJ" required autofocus>
  </div>
  <p class="alert" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit">Continue</button>
</form>
<p class="hint"><a href="/login/totp">Back to the authenticator code</a></p>`,
  });
}

export function stepUpPage({ next, csrf, mode = 'passkey+totp', error = '' }) {
  const totp = mode !== 'passkey+totp';
  return authShell({
    title: 'Confirm',
    lede: 'Confirm a sensitive action.',
    body: `<h1 class="auth-title">Confirm it's you</h1>
<p class="auth-sub">This action needs a fresh ${
      totp ? 'code from your authenticator' : 'passkey check'
    }. It stays valid for five minutes.</p>
${
      totp
        ? `<form method="post" action="/auth/stepup/totp">
  <input type="hidden" name="_csrf" value="${esc(csrf)}">
  <input type="hidden" name="next" value="${esc(next)}">
  <div class="field">
    <label class="label" for="code">Verification code</label>
    <input class="input code" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code"
      pattern="[0-9]{6}" maxlength="6" placeholder="000000" required autofocus>
  </div>
  <p class="alert" id="err" ${error ? '' : 'hidden'}>${esc(error)}</p>
  <button class="btn" type="submit">Confirm</button>
</form>`
        : `<p class="alert" id="err" hidden></p>
<button class="btn" id="stepup" data-csrf="${esc(csrf)}" data-next="${esc(next)}">Use passkey</button>
<p class="hint">You are confirming an administrative change to the estate.</p>
${overlay('Waiting for your passkey')}
<script src="/assets/stepup.js"></script>`
    }`,
  });
}

/* ------------------------------------------------------------------ */
/* Console                                                             */
/* ------------------------------------------------------------------ */

export function overviewPage({ user, apps, counts, chain = { ok: true, checked: 0 } }) {
  const launcher =
    user.role === 'member'
      ? `<h2>Your applications</h2>${table(
          ['Application', 'Status'],
          apps.map((a) => [`<strong>${esc(a.name)}</strong>`, '<span class="tag ok">available</span>']),
        )}`
      : `<div class="grid">
<div class="stat"><b>${counts.users}</b><span>People</span></div>
<div class="stat"><b>${counts.apps}</b><span>Applications</span></div>
<div class="stat"><b>${counts.sessions}</b><span>Live sessions</span></div>
<div class="stat"><b>${counts.events}</b><span>Auth events</span></div>
</div>`;

  return consoleShell({
    title: 'Overview',
    user,
    active: 'overview',
    csrf: user.csrf_token,
    body: `<h1>Overview</h1>
<p class="lede">${user.role === 'member' ? 'Launch an application, or review your own security.' : 'What needs attention, and what is in the estate.'}</p>
${launcher}
<h2>Needs attention</h2>
<div class="card"><p style="margin:0">${
      chain.ok
        ? `<span class="tag ok">verified</span> Audit chain intact across ${chain.checked} events.`
        : `<span class="tag warn">broken</span> Audit chain failed at event ${chain.brokenAt}.`
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
<div class="field"><label class="label">Username</label><input class="input" type="text" name="username" required></div>
<div class="field"><label class="label">Role</label>
<select class="input" name="role">
<option value="member">member</option><option value="auditor">auditor</option>
<option value="admin">admin</option><option value="owner">owner</option>
</select></div>
<button class="btn" type="submit">Create invite</button>
</form>
</div>`
    : '';

  return consoleShell({
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
      ? `<form method="post" action="/people/invites/${esc(i.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${csrf}"><button class="btn secondary small" type="submit">Revoke</button></form>`
      : '',
  ]),
)}
<h2>Live sessions</h2>
${table(
  ['User', 'Level', 'Last seen', ''],
  sessions.map((s) => [
    esc(s.username),
    s.auth_level === 2 ? '<span class="tag ok">L2</span>' : '<span class="tag">L1</span>',
    esc(s.last_seen_at),
    owner
      ? `<form method="post" action="/people/sessions/${esc(s.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${csrf}"><button class="btn secondary small" type="submit">Revoke</button></form>`
      : '',
  ]),
)}`,
  });
}

export function inviteCreatedPage({ user, invite }) {
  return consoleShell({
    title: 'Invite created',
    user,
    active: 'people',
    csrf: user.csrf_token,
    body: `<h1>Invite created</h1>
<p class="lede">Send this link out of band. It is shown once and expires in ${esc(invite.expiresInMinutes)} minutes.</p>
<div class="card"><p style="margin:0 0 8px"><code>${esc(invite.path)}</code></p>
<p class="muted" style="margin:0">For <strong>${esc(invite.username || 'a new user')}</strong> as <span class="tag">${esc(invite.role)}</span>${
      invite.username ? '' : ' · username chosen at enrolment'
    }</p></div>
<p><a href="/people">Back to People</a></p>`,
  });
}

export function userDetailPage({ user, target, creds, sessions, events, recoveryRemaining }) {
  const owner = canWrite(user.role, 'people') && target.id !== user.id;
  const csrf = esc(user.csrf_token);
  const roleOptions = ['member', 'auditor', 'admin', 'owner']
    .map((r) => `<option value="${r}"${r === target.role ? ' selected' : ''}>${r}</option>`)
    .join('');

  return consoleShell({
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
<select class="input" name="role" style="margin-bottom:10px">${roleOptions}</select>
<button class="btn" type="submit">Update role</button>
</form>
<form method="post" action="/people/${esc(target.id)}/status" style="margin-top:10px">
<input type="hidden" name="_csrf" value="${csrf}">
<input type="hidden" name="status" value="${target.status === 'active' ? 'suspended' : 'active'}">
<button class="btn secondary" type="submit">${target.status === 'active' ? 'Suspend account' : 'Reactivate account'}</button>
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
      target.totp_confirmed_at ? '<span class="tag ok">TOTP enrolled</span>' : '<span class="tag warn">not enrolled</span>'
    } · ${recoveryRemaining} recovery codes remaining</p></div>

<h2>Sessions</h2>
${table(
  ['Level', 'Last seen', ''],
  sessions.map((s) => [
    s.auth_level === 2 ? '<span class="tag ok">L2</span>' : '<span class="tag">L1</span>',
    esc(s.last_seen_at),
    owner
      ? `<form method="post" action="/people/sessions/${esc(s.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${csrf}"><button class="btn secondary small" type="submit">Revoke</button></form>`
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
    ? `<p class="muted" style="margin:-6px 0 18px">Read-only view of <code>${esc(inventory.dir)}</code> · ${inventory.auditEvents} gateway audit events</p>`
    : `<div class="card"><p style="margin:0"><span class="tag warn">not readable</span> ${esc(inventory.reason)}. Set <code>AT_GATEWAY_DATA</code> to the gateway data directory.</p></div>`;

  return consoleShell({
    title: 'Tools',
    user,
    active: 'tools',
    csrf: user.csrf_token,
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
    `<span class="tag ok">${esc(c.status)}</span>`,
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
    s.revoked_at ? '<span class="tag warn">revoked</span>' : esc(s.minted_today),
  ]),
)}`,
  });
}

export function applicationsPage({ user, apps, health = {} }) {
  return consoleShell({
    title: 'Applications',
    user,
    active: 'applications',
    csrf: user.csrf_token,
    body: `<h1>Applications</h1><p class="lede">What a person can sign into. Access is role → application, never a per-app user list.</p>
${table(
  ['Application', 'Upstream', 'Auth mode', 'Allowed roles', 'Status', 'Health'],
  apps.map((a) => [
    `<strong>${esc(a.name)}</strong>`,
    `<code>${esc(a.upstream_url)}</code>`,
    esc(a.auth_mode),
    esc(JSON.parse(a.allowed_roles).join(', ')),
    `<span class="tag ok">${esc(a.status)}</span>`,
    `<span class="tag ${health[a.name] === 'up' ? 'ok' : 'warn'}">${esc(health[a.name] || 'unknown')}</span>`,
  ]),
)}
<h2>Signing users in</h2>
<div class="card"><p class="muted" style="margin:0">forward-auth: the proxy calls <code>/authz</code>, receives <code>X-AT-User</code> and <code>X-AT-Roles</code>, and strips any inbound copy. durable-pi stays reachable only through the proxy.</p></div>`,
  });
}

export function policyPage({ user, inventory }) {
  return consoleShell({
    title: 'Policy',
    user,
    active: 'policy',
    csrf: user.csrf_token,
    body: `<h1>Policy</h1><p class="lede">What gets masked, and who may use what.</p>
<div class="card"><p style="margin:0" class="muted">Read-only here. The registry is edited on the gateway until the platform owns the store.</p></div>
<h2>Masking registry</h2>
${table(
  ['Connection', 'Table', 'Column', 'Strategy', 'State'],
  inventory.registry.map((r) => [
    esc(r.connection),
    esc(r.table_name),
    `<code>${esc(r.column_name)}</code>`,
    `<span class="tag">${esc(r.strategy)}</span>`,
    r.enabled ? '<span class="tag ok">enforced</span>' : 'disabled',
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
  return consoleShell({
    title: 'Audit',
    user,
    active: 'audit',
    csrf: user.csrf_token,
    body: `<h1>Audit</h1><p class="lede">Authentication events. Query and domain audit arrive with the gateway inventory.</p>
${table(
  ['When', 'User', 'Event', 'Factor', 'Result'],
  events.map((e) => [
    esc(e.ts),
    esc(e.user_id || '—'),
    `<code>${esc(e.event)}</code>`,
    esc(e.factor || '—'),
    e.result === 'ok' ? '<span class="tag ok">ok</span>' : `<span class="tag warn">${esc(e.result)}</span>`,
  ]),
)}`,
  });
}

export function settingsPage({ user, rp, signing, inventory }) {
  return consoleShell({
    title: 'Settings',
    user,
    active: 'settings',
    csrf: user.csrf_token,
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
<pre style="background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto">${esc(JSON.stringify(signing.jwks, null, 2))}</pre>`
        : `<div class="card"><p style="margin:0">No signing key found in the gateway store${signing.reason ? `: ${esc(signing.reason)}` : ''}.</p></div>`
    }
<h2>Gateway store</h2>
<div class="card"><p style="margin:0">${
      inventory.available
        ? `<span class="tag ok">connected</span> <code>${esc(inventory.dir)}</code> · ${inventory.connections.length} connections · ${inventory.registry.length} registry rules`
        : `<span class="tag warn">not found</span> ${esc(inventory.reason)}`
    }</p></div>
<h2>Backups and drills</h2>
<div class="card"><p class="muted" style="margin:0">Rotation, restore and break-glass drills are run from the runbook; results are recorded in the audit log.</p></div>`,
  });
}

export function meSecurityPage({ user, creds, totpConfirmed, recoveryRemaining = 0, remembered = [] }) {
  return consoleShell({
    title: 'My security',
    user,
    active: 'me',
    csrf: user.csrf_token,
    body: `<h1>My security</h1><p class="lede">Your passkeys and second factor. <a href="/me/activity">View your activity</a></p>
<h2>Passkeys</h2>
${table(
  ['Passkey', 'Created', 'Last used', ''],
  creds.map((c) => [
    `<code>${esc(c.nickname || c.id)}</code>`,
    esc(c.created_at),
    esc(c.last_used_at || '—'),
    creds.length > 1
      ? `<form method="post" action="/me/security/passkeys/${esc(c.id)}/remove" style="margin:0"><input type="hidden" name="_csrf" value="${esc(user.csrf_token)}"><button class="btn secondary small" type="submit">Remove</button></form>`
      : '',
  ]),
)}
<h2>Remembered browsers</h2>
${table(
  ['Remembered', 'Last used', 'Expires', ''],
  remembered.map((r) => [
    esc(r.created_at),
    esc(r.last_used_at || '—'),
    esc(r.expires_at),
    `<form method="post" action="/me/security/remembered/${esc(r.id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${esc(user.csrf_token)}"><button class="btn secondary small" type="submit">Revoke</button></form>`,
  ]),
)}

<h2>Authenticator app</h2>
<div class="card"><p style="margin:0 0 12px">${
      totpConfirmed ? '<span class="tag ok">enrolled</span> A 6-digit code is required at every sign-in.' : '<span class="tag warn">not enrolled</span>'
    }</p>
<form method="post" action="/me/security/totp/rotate">
<input type="hidden" name="_csrf" value="${esc(user.csrf_token)}">
<button class="btn secondary" type="submit">Set up a new authenticator</button>
</form></div>

<h2>Recovery codes</h2>
<div class="card"><p style="margin:0 0 12px"><strong>${recoveryRemaining}</strong> unused. A code replaces the authenticator factor once — never the passkey.</p>
<form method="post" action="/me/security/recovery/regenerate">
<input type="hidden" name="_csrf" value="${esc(user.csrf_token)}">
<button class="btn secondary" type="submit">Regenerate codes</button>
</form></div>`,
  });
}

export function meActivityPage({ user, events }) {
  return consoleShell({
    title: 'My activity',
    user,
    active: 'me',
    csrf: user.csrf_token,
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

export function errorPage({ status, message, user = null }) {
  const body = `<h1>${status}</h1><p class="lede">${esc(message)}</p><p><a href="${user ? '/' : '/login'}">${user ? 'Back to the console' : 'Back to sign in'}</a></p>`;
  return user
    ? consoleShell({ title: String(status), user, active: null, csrf: user.csrf_token, body })
    : authShell({ title: String(status), body });
}
