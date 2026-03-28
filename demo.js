import { sha256 } from 'https://esm.sh/@noble/hashes@1.7.1/sha256';
import { bytesToHex, hexToBytes, concatBytes } from 'https://esm.sh/@noble/hashes@1.7.1/utils';
import * as secp from 'https://esm.sh/@noble/secp256k1@2.2.3';
import QRCode from 'https://esm.sh/qrcode@1.5.4';

const $ = id => document.getElementById(id);

const state = {
  nonce: null,
  k1: null,
  signature: null,
  linkingPubKey: null,
  sessionToken: null,
  privKey: null,
  pubKey: null,
};

function setBadge(n, status) {
  $(`badge-${n}`).textContent = status;
  $(`badge-${n}`).className = `step-badge ${status}`;
  $(`step-${n}`).className = `step ${status}`;
}

function show(id) { $(id).hidden = false; }
function disable(id, text) { $(id).disabled = true; if (text) $(id).textContent = text; }

async function api(serviceUrl, method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(serviceUrl + path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// Step 1 — Nonce

$('btn-gen-nonce').addEventListener('click', () => {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  state.nonce = bytesToHex(buf);

  $('nonce-value').textContent = state.nonce;
  show('nonce-result');
  disable('btn-gen-nonce', 'Generated');
  setBadge(1, 'done');
  setBadge(2, 'active');
  $('btn-auth').disabled = false;
});

// Step 2 — LNURL-auth

$('btn-auth').addEventListener('click', async () => {
  const url = $('service-url').value.trim();
  let dealId = $('deal-id').value.trim();
  const role = $('role').value;

  if (!url) return alert('Service URL required');

  disable('btn-auth', 'Creating deal...');
  show('auth-qr');

  try {
    if (!dealId) {
      const deal = await api(url, 'POST', '/api/deals', { title: 'SplitSig Demo', amount: 50000, role });
      dealId = deal.id;
      $('deal-id').value = dealId;
    }

    $('btn-auth').textContent = 'Requesting challenge...';
    const challenge = await api(url, 'GET', `/api/auth/challenge?deal=${dealId}&role=${role}`);
    state.k1 = challenge.k1;
    $('k1-value').textContent = state.k1;

    const canvas = document.createElement('canvas');
    await QRCode.toCanvas(canvas, challenge.qr_content, { width: 240, margin: 2 });
    $('qr-container').replaceChildren(canvas);
    $('auth-status-text').textContent = 'Scan with your Lightning wallet...';
    $('btn-auth').textContent = 'Waiting for wallet...';

    startPolling(url);
  } catch (e) {
    $('auth-status-text').textContent = e.message;
    $('btn-auth').disabled = false;
    $('btn-auth').textContent = 'Retry';
  }
});

function startPolling(serviceUrl) {
  const endpoint = `${serviceUrl}/api/auth/status/${state.k1}`;
  const timer = setInterval(async () => {
    try {
      const res = await fetch(endpoint);
      if (!res.ok) return;
      const data = await res.json();
      if (!data.verified || !data.signature) return;

      clearInterval(timer);
      state.signature = data.signature;
      state.linkingPubKey = data.linking_pubkey;
      state.sessionToken = data.session_token;

      $('sig-value').textContent = state.signature;
      $('linking-pubkey-value').textContent = state.linkingPubKey;
      show('sig-result');
      $('auth-status-text').textContent = 'Wallet verified.';
      $('btn-auth').textContent = 'Done';
      setBadge(2, 'done');
      setBadge(3, 'active');
      $('btn-derive').disabled = false;
    } catch {}
  }, 2000);

  setTimeout(() => clearInterval(timer), 600_000);
}

// Step 3 — Derive key

$('btn-derive').addEventListener('click', () => {
  const privBytes = sha256(concatBytes(hexToBytes(state.signature), hexToBytes(state.nonce)));
  const pubBytes = secp.getPublicKey(privBytes, true);

  state.privKey = bytesToHex(privBytes);
  state.pubKey = bytesToHex(pubBytes.slice(1));

  const sigShort = state.signature.slice(0, 16) + '...' + state.signature.slice(-8);
  const nonceShort = state.nonce.slice(0, 16) + '...';
  $('derive-input').textContent = `SHA256( ${sigShort} + ${nonceShort} )`;
  $('privkey-value').textContent = state.privKey;
  $('pubkey-value').textContent = state.pubKey;
  show('derive-result');
  disable('btn-derive', 'Derived');
  setBadge(3, 'done');
  setBadge(4, 'active');
  $('btn-register').disabled = false;
});

// Step 4 — Register pubkey

$('btn-register').addEventListener('click', async () => {
  const url = $('service-url').value.trim();
  const dealId = $('deal-id').value.trim();

  disable('btn-register', 'Sending...');

  try {
    const res = await fetch(`${url}/api/deals/${dealId}/register-pubkey`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.sessionToken}`,
      },
      body: JSON.stringify({ escrow_pubkey: state.pubKey }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    show('register-result');
    $('btn-register').textContent = 'Registered';
    setBadge(4, 'done');
    setBadge(5, 'active');
    $('btn-kit').disabled = false;
  } catch (e) {
    $('register-result').innerHTML = `<p class="error-text">${e.message}</p>`;
    show('register-result');
    $('btn-register').disabled = false;
    $('btn-register').textContent = 'Retry';
  }
});

// Step 5 — Recovery kit

$('btn-kit').addEventListener('click', () => {
  const url = $('service-url').value.trim();
  let domain;
  try { domain = new URL(url).hostname; } catch { domain = url; }

  const kit = {
    role: $('role').value,
    deal_id: $('deal-id').value.trim(),
    nonce: state.nonce,
    linking_pubkey: state.linkingPubKey,
    auth_domain: domain,
  };

  $('kit-json').textContent = JSON.stringify(kit, null, 2);
  show('kit-result');
  disable('btn-kit', 'Generated');
  setBadge(5, 'done');
  show('step-summary');
});
