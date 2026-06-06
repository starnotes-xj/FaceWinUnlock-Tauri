// FaceWinUnlock Passkey Bridge — Content Script
//
// Injected at document_start to override navigator.credentials.get
// before any page scripts can access it.
//
// Reference: Shwmae ShwmaeExt/webauthn-inject.js

(function () {
  'use strict';

  // Only override if the passkey bridge extension is present
  if (typeof chrome === 'undefined' || !chrome.runtime) {
    return;
  }

  const EXTENSION_ID = 'facewinunlock-passkey-bridge';
  const SIGNER_PORT_FILE = ''; // Will be read via extension native messaging

  // Save original for cleanup
  const _originalGet = navigator.credentials.get.bind(navigator.credentials);

  // ── Base64url helpers ────────────────────────────────────────────────
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

  // ── Override navigator.credentials.get ───────────────────────────────
  navigator.credentials.get = function (options) {
    // Only intercept public-key (WebAuthn) requests
    if (!options || !options.publicKey) {
      return _originalGet(options);
    }

    const pkOptions = options.publicKey;

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

    // Forward to background script for PIN dialog and signing
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        EXTENSION_ID,
        { type: 'WEBAUTHN_GET', options: serialized },
        function (response) {
          if (chrome.runtime.lastError) {
            console.warn('[FaceWinUnlock] Bridge unavailable, falling back to native:',
              chrome.runtime.lastError.message);
            // Fall back to original WebAuthn
            return resolve(_originalGet(options));
          }

          if (!response || response.error) {
            const err = new Error(response?.error || 'Passkey assertion failed');
            err.name = 'NotAllowedError';
            return reject(err);
          }

          // Construct the standard WebAuthn response object
          const assertion = {
            id: response.id,
            rawId: fromBase64url(response.rawId),
            response: {
              authenticatorData: fromBase64url(response.authenticatorData),
              clientDataJSON: fromBase64url(response.clientDataJSON),
              signature: fromBase64url(response.signature),
              userHandle: response.userHandle
                ? fromBase64url(response.userHandle)
                : null
            },
            type: 'public-key',
            authenticatorAttachment: 'platform'
          };

          resolve(assertion);
        }
      );
    });
  };
})();
