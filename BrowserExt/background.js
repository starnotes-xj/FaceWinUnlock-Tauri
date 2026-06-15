'use strict';

const SIGNER_PORT = 19531; // fixed port (http.rs binds this)
let signerOk = false;

async function checkSigner() {
  try {
    const resp = await fetch(`http://127.0.0.1:${SIGNER_PORT}/ping`);
    signerOk = resp.ok;
    if (signerOk) {
      console.log('[FaceWinUnlock] Signer OK on port', SIGNER_PORT);
    }
  } catch (e) {
    signerOk = false;
  }
}

// 启动时检查一次，之后每30秒复查
checkSigner();
setInterval(checkSigner, 30000);

// 内部消息监听（content_script 同扩展内通信）
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.type === 'WEBAUTHN_GET_PIN') {
    handleWebAuthnGetWithPin(request.options, request.pin)
      .then(sendResponse)
      .catch(err => sendResponse({ error: err.message || String(err) }));
    return true;
  }
  if (request.type !== 'WEBAUTHN_GET') {
    sendResponse({ error: 'Unknown request type' });
    return true;
  }

  handleWebAuthnGet(request.options)
    .then(sendResponse)
    .catch(err => sendResponse({ error: err.message || String(err) }));

  return true; // 异步响应
});

async function handleWebAuthnGet(options) {
  if (!signerOk) {
    await checkSigner();
    if (!signerOk) {
      throw new Error('Passkey signer not available. Please ensure FaceWinUnlock is running.');
    }
  }

  // 先尝试无 PIN 签名（key_store 缓存或数据库存储 PIN 自动解密）
  let resp = await fetch(`http://127.0.0.1:${SIGNER_PORT}/assertion`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...options, pin: '' })
  });

  // 如果无 PIN 失败且需要 PIN，返回错误让 content_script 弹框
  if (!resp.ok) {
    const errBody = await resp.json().catch(() => ({}));
    if (errBody.error && errBody.error.includes('PIN')) {
      throw new Error('PIN_REQUIRED');
    }
    throw new Error(errBody.error || 'Signer returned error');
  }

  return await resp.json();
}

async function handleWebAuthnGetWithPin(options, pin) {
  const resp = await fetch(`http://127.0.0.1:${SIGNER_PORT}/assertion`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...options, pin: pin })
  });

  if (!resp.ok) {
    const errBody = await resp.json().catch(() => ({}));
    throw new Error(errBody.error || 'Signer returned error');
  }

  return await resp.json();
}
