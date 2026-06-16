// FaceWinUnlock Passkey Bridge - MAIN-world WebAuthn hook.
//
// Chrome isolates ordinary content scripts from page JavaScript. This file is
// explicitly loaded in the MAIN world so websites call this override. Requests
// are forwarded to webauthn-bridge.js through window.postMessage.

(function () {
  'use strict';

  if (!navigator.credentials || navigator.credentials.get.__faceWinUnlockHook) {
    return;
  }

  const REQUEST_SOURCE = 'facewinunlock-passkey-page';
  const RESPONSE_SOURCE = 'facewinunlock-passkey-extension';
  const pending = new Map();
  let requestSequence = 0;

  const _originalGet = navigator.credentials.get.bind(navigator.credentials);

  function toBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  function fromBase64url(str) {
    const base64 = str
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function sendToExtension(type, options, pin) {
    return new Promise((resolve, reject) => {
      const requestId = `${Date.now()}-${++requestSequence}`;
      const timeout = setTimeout(() => {
        pending.delete(requestId);
        reject(new Error('FaceWinUnlock extension bridge timed out'));
      }, Math.max(options.timeout || 60000, 5000) + 5000);

      pending.set(requestId, { resolve, reject, timeout });
      window.postMessage({
        source: REQUEST_SOURCE,
        requestId,
        type,
        options,
        pin,
      }, '*');
    });
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window || event.data?.source !== RESPONSE_SOURCE) {
      return;
    }

    if (event.data.ready) {
      document.documentElement.setAttribute(
        'data-facewinunlock-passkey-bridge',
        'ready'
      );
      return;
    }

    const waiter = pending.get(event.data.requestId);
    if (!waiter) {
      return;
    }

    pending.delete(event.data.requestId);
    clearTimeout(waiter.timeout);
    waiter.resolve(event.data.response);
  });

  async function faceWinUnlockGet(options) {
    if (!options || !options.publicKey) {
      return _originalGet(options);
    }

    const pkOptions = options.publicKey;
    if (!pkOptions.allowCredentials || pkOptions.allowCredentials.length === 0) {
      return _originalGet(options);
    }

    // Convert challenge and allowCredentials to JSON-serializable form
    const serialized = {
      rpId: pkOptions.rpId,
      challenge: toBase64url(pkOptions.challenge),
      origin: window.location.origin,
      timeout: pkOptions.timeout || 60000,
      allowCredentials: (pkOptions.allowCredentials || []).map(c => ({
        id: toBase64url(c.id),
        type: c.type || 'public-key',
        transports: c.transports || []
      }))
    };

    let response;
    try {
      response = await sendToExtension('WEBAUTHN_GET', serialized);
    } catch (error) {
      console.warn('[FaceWinUnlock] Bridge unavailable, falling back to native:', error);
      return _originalGet(options);
    }

    if (response?.error === 'NATIVE_FALLBACK') {
      return _originalGet(options);
    }

    if (response?.error === 'PIN_REQUIRED') {
      const pin = prompt(
        `${location.hostname} 需要 passkey 认证\n\n请输入 Windows Hello PIN:`,
        ''
      );
      if (pin) {
        response = await sendToExtension('WEBAUTHN_GET_PIN', serialized, pin);
      }
    }

    if (!response || response.error) {
      const error = new Error(response?.error || 'Passkey assertion failed');
      error.name = 'NotAllowedError';
      throw error;
    }

    return buildAssertion(response);
  }

  function buildAssertion(response) {
    const assertion = {
      id: response.id,
      rawId: fromBase64url(response.rawId),
      response: {
        authenticatorData: fromBase64url(response.authenticatorData),
        clientDataJSON: fromBase64url(response.clientDataJSON),
        signature: fromBase64url(response.signature),
        userHandle: response.userHandle ? fromBase64url(response.userHandle) : null
      },
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults() {
        return {};
      },
      toJSON() {
        return {
          id: this.id,
          rawId: toBase64url(this.rawId),
          response: {
            authenticatorData: toBase64url(this.response.authenticatorData),
            clientDataJSON: toBase64url(this.response.clientDataJSON),
            signature: toBase64url(this.response.signature),
            userHandle: this.response.userHandle
              ? toBase64url(this.response.userHandle)
              : null
          },
          type: this.type,
          authenticatorAttachment: this.authenticatorAttachment,
          clientExtensionResults: this.getClientExtensionResults()
        };
      }
    };
    return assertion;
  }

  Object.defineProperty(faceWinUnlockGet, '__faceWinUnlockHook', {
    value: true,
  });
  navigator.credentials.get = faceWinUnlockGet;
  document.documentElement.setAttribute(
    'data-facewinunlock-passkey-hook',
    'ready'
  );
})();
