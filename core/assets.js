const B64 = `
const b64 = {
  toBuf: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
  fromBuf: (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''),
};
async function post(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
`;

export const LOGIN_JS = `${B64}
const form = document.getElementById('login-form');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const err = document.getElementById('err');
  err.textContent = '';
  const username = document.getElementById('username').value.trim();
  try {
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
    err.textContent = e.message || 'Sign-in failed';
  }
});
`;

export const STEPUP_JS = `${B64}
const button = document.getElementById('stepup');
button.addEventListener('click', async () => {
  const err = document.getElementById('err');
  err.textContent = '';
  button.disabled = true;
  try {
    const optsRes = await fetch('/auth/stepup/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const { options } = await optsRes.json();
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
    const verify = await fetch('/auth/stepup/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-csrf-token': button.dataset.csrf },
      body: JSON.stringify({ response }),
    });
    if (!verify.ok) throw new Error((await verify.json()).error || 'Step-up failed');
    location.href = button.dataset.next || '/';
  } catch (e) {
    err.textContent = e.message || 'Step-up failed';
    button.disabled = false;
  }
});
`;

export const ENROLL_JS = `${B64}
document.getElementById('start').addEventListener('click', async () => {
  const err = document.getElementById('err');
  const token = document.getElementById('token').value;
  err.textContent = '';
  try {
    const { options } = await post('/enroll/options', { token });
    options.challenge = b64.toBuf(options.challenge);
    options.user.id = b64.toBuf(options.user.id);
    options.excludeCredentials = (options.excludeCredentials || []).map((c) => ({ ...c, id: b64.toBuf(c.id) }));
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
    err.textContent = e.message || 'Enrolment failed';
  }
});
`;
