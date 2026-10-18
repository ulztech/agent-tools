const B64 = `
const b64 = {
  toBuf: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
  fromBuf: (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''),
};
async function post(url, body, headers) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...(headers || {}) }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
`;

const UI = `
function showWait(on) {
  const el = document.getElementById('wait');
  if (el) el.classList.toggle('on', on);
}
function fail(message) {
  const el = document.getElementById('err');
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
}
function clearFail() {
  const el = document.getElementById('err');
  if (el) { el.hidden = true; el.textContent = ''; }
}
function supportsPasskeys() {
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}
`;

export const LOGIN_JS = `${B64}${UI}
const form = document.getElementById('login-form');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = document.getElementById('submit');
  clearFail();

  const username = document.getElementById('username').value.trim();
  if (!username) { fail('Enter your username.'); return; }

  const mode = (document.getElementById('mode') || {}).value || 'passkey+totp';
  button.disabled = true;
  showWait(true);

  try {
    if (mode === 'totp') {
      await post('/auth/start', { username });
      location.href = '/login/totp';
      return;
    }

    if (!supportsPasskeys()) {
      showWait(false);
      button.disabled = false;
      fail('This browser does not support passkeys. Use a current Chrome, Edge, Safari or Firefox.');
      return;
    }

    const { options } = await post('/auth/options', { username });
    options.challenge = b64.toBuf(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map((c) => ({ ...c, id: b64.toBuf(c.id) }));
    const cred = await navigator.credentials.get({ publicKey: options });
    const response = {
      id: cred.id,
      rawId: b64.fromBuf(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: b64.fromBuf(cred.response.clientDataJSON),
        authenticatorData: b64.fromBuf(cred.response.authenticatorData),
        signature: b64.fromBuf(cred.response.signature),
        userHandle: cred.response.userHandle ? b64.fromBuf(cred.response.userHandle) : null,
      },
    };
    await post('/auth/verify', { username, response });
    location.href = '/login/totp';
  } catch (e) {
    showWait(false);
    button.disabled = false;
    fail(e && e.name === 'NotAllowedError' ? 'The passkey prompt was cancelled or timed out.' : (e.message || 'Sign-in failed.'));
  }
});
`;

export const ENROLL_JS = `${B64}${UI}
document.getElementById('start').addEventListener('click', async () => {
  const button = document.getElementById('start');
  const token = document.getElementById('token').value;
  const mode = (document.getElementById('mode') || {}).value || 'passkey+totp';
  clearFail();
  button.disabled = true;
  showWait(true);

  try {
    if (mode === 'totp') {
      const next = await post('/enroll/start-totp', { token });
      location.href = next.next || '/enroll/totp';
      return;
    }

    if (!supportsPasskeys()) {
      showWait(false);
      button.disabled = false;
      fail('This browser does not support passkeys. Use a current Chrome, Edge, Safari or Firefox.');
      return;
    }

    const { options } = await post('/enroll/options', { token });
    const device = document.querySelector('input[name="device"]:checked');
    const attachment = device && device.value === 'cross-platform' ? 'cross-platform' : 'platform';
    options.challenge = b64.toBuf(options.challenge);
    options.user.id = b64.toBuf(options.user.id);
    options.excludeCredentials = (options.excludeCredentials || []).map((c) => ({ ...c, id: b64.toBuf(c.id) }));
    options.authenticatorSelection = {
      ...(options.authenticatorSelection || {}),
      authenticatorAttachment: attachment,
      userVerification: 'required',
    };

    const cred = await navigator.credentials.create({ publicKey: options });
    const transports = cred.response.getTransports ? cred.response.getTransports() : [];
    const response = {
      id: cred.id,
      rawId: b64.fromBuf(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: b64.fromBuf(cred.response.clientDataJSON),
        attestationObject: b64.fromBuf(cred.response.attestationObject),
        transports,
      },
    };
    await post('/enroll/verify', { token, response });
    location.href = '/enroll/totp';
  } catch (e) {
    showWait(false);
    button.disabled = false;
    fail(e && e.name === 'NotAllowedError' ? 'The passkey prompt was cancelled or timed out.' : (e.message || 'Enrolment failed.'));
  }
});
`;

export const STEPUP_JS = `${B64}${UI}
const button = document.getElementById('stepup');
button.addEventListener('click', async () => {
  clearFail();
  button.disabled = true;
  showWait(true);
  try {
    const { options } = await post('/auth/stepup/options', {});
    options.challenge = b64.toBuf(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map((c) => ({ ...c, id: b64.toBuf(c.id) }));
    const cred = await navigator.credentials.get({ publicKey: options });
    const response = {
      id: cred.id,
      rawId: b64.fromBuf(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: b64.fromBuf(cred.response.clientDataJSON),
        authenticatorData: b64.fromBuf(cred.response.authenticatorData),
        signature: b64.fromBuf(cred.response.signature),
        userHandle: cred.response.userHandle ? b64.fromBuf(cred.response.userHandle) : null,
      },
    };
    await post('/auth/stepup/verify', { response }, { 'x-csrf-token': button.dataset.csrf });
    location.href = button.dataset.next || '/';
  } catch (e) {
    showWait(false);
    button.disabled = false;
    fail(e && e.name === 'NotAllowedError' ? 'The passkey prompt was cancelled.' : (e.message || 'Step-up failed.'));
  }
});
`;

export const COPY_JS = `
const button = document.getElementById('copy');
if (button) {
  button.addEventListener('click', async () => {
    const secret = button.dataset.secret || '';
    try {
      await navigator.clipboard.writeText(secret);
    } catch {
      const range = document.createRange();
      range.selectNodeContents(document.getElementById('secret'));
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      return;
    }
    const original = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = original; }, 1500);
  });
}
`;

export const RECOVERY_JS = `
const codes = Array.from(document.querySelectorAll('#codes code')).map((el) => el.textContent.trim());
const asText = () => 'Agent-tools recovery codes\\nEach code works once.\\n\\n' + codes.join('\\n') + '\\n';

const copyAll = document.getElementById('copy-codes');
if (copyAll) {
  copyAll.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(asText());
      copyAll.textContent = 'Copied';
      setTimeout(() => { copyAll.textContent = 'Copy all'; }, 1500);
    } catch {
      copyAll.textContent = 'Select the codes and copy';
    }
  });
}

const download = document.getElementById('download-codes');
if (download) {
  download.addEventListener('click', () => {
    const blob = new Blob([asText()], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'agent-tools-recovery-codes.txt';
    link.click();
    URL.revokeObjectURL(link.href);
  });
}

const saved = document.getElementById('saved');
const ack = document.getElementById('ack');
if (saved && ack) {
  ack.disabled = !saved.checked;
  saved.addEventListener('change', () => { ack.disabled = !saved.checked; });
}
`;
