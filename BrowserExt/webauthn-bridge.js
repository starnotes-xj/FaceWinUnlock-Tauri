// FaceWinUnlock Passkey Bridge - isolated-world transport.
//
// The WebAuthn hook must run in the page's MAIN world, where extension APIs are
// unavailable. This script forwards requests between that hook and the
// extension service worker.

(function () {
  'use strict';

  const REQUEST_SOURCE = 'facewinunlock-passkey-page';
  const RESPONSE_SOURCE = 'facewinunlock-passkey-extension';

  window.addEventListener('message', (event) => {
    if (event.source !== window || event.data?.source !== REQUEST_SOURCE) {
      return;
    }

    const { requestId, type, options, pin } = event.data;
    if (!requestId || (type !== 'WEBAUTHN_GET' && type !== 'WEBAUTHN_GET_PIN')) {
      return;
    }

    chrome.runtime.sendMessage({ type, options, pin }, (response) => {
      const error = chrome.runtime.lastError?.message;
      window.postMessage({
        source: RESPONSE_SOURCE,
        requestId,
        response: error ? { error } : response,
      }, '*');
    });
  });

  document.documentElement.setAttribute(
    'data-facewinunlock-passkey-bridge',
    'ready'
  );
  window.postMessage({ source: RESPONSE_SOURCE, ready: true }, '*');
})();
