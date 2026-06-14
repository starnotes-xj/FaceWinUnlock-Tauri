// FaceWinUnlock Passkey Bridge — Background Service Worker
//
// Forwards WebAuthn assertion requests from content scripts
// to the local SYSTEM FIDO2 signer via HTTP.
//
// The signer's port is read from the passkey_port file
// (written by Unlock EXE when it starts the HTTP server).

'use strict';

// Default port (will be updated from file via native messaging or polling)
let signerPort = 0;
let signerToken = '';

// ── Initialize connection to signer ──────────────────────────────────
async function initSignerConnection() {
  try {
    // Try to read port from local file via fetch to localhost
    // The signer writes its port to a known location
    // For now, try common ports
    const ports = [19527, 19528, 19529, 19530, 19531];
    for (const port of ports) {
      try {
        const resp = await fetch(`http://127.0.0.1:${port}/ping`, {
          method: 'GET',
          signal: AbortSignal.timeout(500)
        });
        if (resp.ok) {
          signerPort = port;
          console.log('[FaceWinUnlock] Signer found on port', port);
          return true;
        }
      } catch (e) {
        // Try next port
      }
    }
    console.warn('[FaceWinUnlock] No signer found on any known port');
    return false;
  } catch (e) {
    console.error('[FaceWinUnlock] Error connecting to signer:', e);
    return false;
  }
}

// Try to connect on startup
initSignerConnection();

// Retry periodically
setInterval(initSignerConnection, 30000);

// ── Message handler ─────────────────────────────────────────────────
chrome.runtime.onMessageExternal.addListener(
  function (request, sender, sendResponse) {
    if (request.type !== 'WEBAUTHN_GET') {
      sendResponse({ error: 'Unknown request type' });
      return true;
    }

    handleWebAuthnGet(request.options)
      .then(sendResponse)
      .catch(err => sendResponse({ error: err.message }));

    return true; // Keep channel open for async response
  }
);

async function handleWebAuthnGet(options) {
  if (!signerPort) {
    await initSignerConnection();
    if (!signerPort) {
      throw new Error('Passkey signer not available. Please ensure FaceWinUnlock is running.');
    }
  }

  // 先尝试无 PIN 签名（已捕获密钥优先）
  let resp = await fetch(`http://127.0.0.1:${signerPort}/assertion`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${signerToken}`
    },
    body: JSON.stringify({ ...options, pin: '' })
  });

  // 如果无 PIN 失败，提示用户输入 PIN 重试
  if (!resp.ok) {
    const errBody = await resp.json().catch(() => ({}));
    // 只有密钥未找到时才弹 PIN 框
    if (errBody.error && errBody.error.includes('PIN')) {
      const pin = await promptForPin(options.rpId, options.origin);
      if (!pin) {
        throw new Error('User cancelled PIN entry');
      }
      resp = await fetch(`http://127.0.0.1:${signerPort}/assertion`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${signerToken}`
        },
        body: JSON.stringify({ ...options, pin })
      });
    }
  }

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: 'HTTP ' + resp.status }));
    throw new Error(err.error || 'Signer returned error');
  }

  return await resp.json();
}

// ── PIN prompt ──────────────────────────────────────────────────────
function promptForPin(rpId, origin) {
  return new Promise((resolve) => {
    // Use a simple prompt for PIN input
    // In production, this should use a proper UI
    const domain = new URL(origin).hostname;
    const message = `${domain} requests passkey authentication\n\nEnter your Windows Hello PIN:`;
    const pin = prompt(message, '');
    resolve(pin);
  });
}
