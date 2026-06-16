'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const repoRoot = path.resolve(__dirname, '..');
const extensionDir = process.env.FACEWINUNLOCK_EXTENSION_DIR
  || path.join(repoRoot, 'BrowserExt');
const installDir = process.env.FACEWINUNLOCK_INSTALL_DIR || 'D:\\facewinunlock-tauri';
const mappingPath = path.join(installDir, 'passkey_keys.json');
const testCredentialLabel = 'facewinunlock-local-e2e';
const testCredentialId = base64url(Buffer.from(testCredentialLabel));
const testRpId = 'localhost';
const port = Number(process.env.FACEWINUNLOCK_E2E_PORT || 19532);

function base64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function fromBase64url(value) {
  return Buffer.from(value, 'base64url');
}

function loadMapping() {
  const entries = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
  const source = entries.find((entry) => {
    if (!entry.key_file || !fs.existsSync(entry.key_file)) {
      return false;
    }
    return fs.statSync(entry.key_file).size === 32;
  });
  if (!source) {
    throw new Error(`No usable 32-byte passkey key in ${mappingPath}`);
  }
  return { entries, source };
}

function publicKeyFromRawPrivateKey(privateKey) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(privateKey);
  const point = ecdh.getPublicKey(undefined, 'uncompressed');
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x, y },
    format: 'jwk',
  });
}

function html() {
  return `<!doctype html>
<meta charset="utf-8">
<title>FaceWinUnlock passkey E2E</title>
<button id="run">Run passkey assertion</button>
<pre id="result">ready</pre>
<script>
const credentialLabel = ${JSON.stringify(testCredentialLabel)};
const result = document.querySelector('#result');
const toBase64url = buffer => {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
};
document.querySelector('#run').onclick = async () => {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion = await navigator.credentials.get({ publicKey: {
      challenge,
      rpId: location.hostname,
      timeout: 15000,
      userVerification: 'required',
      allowCredentials: [{
        type: 'public-key',
        id: new TextEncoder().encode(credentialLabel),
        transports: ['internal']
      }]
    }});
    const payload = {
      challenge: toBase64url(challenge),
      id: assertion.id,
      rawId: toBase64url(assertion.rawId),
      authenticatorData: toBase64url(assertion.response.authenticatorData),
      clientDataJSON: toBase64url(assertion.response.clientDataJSON),
      signature: toBase64url(assertion.response.signature)
    };
    const response = await fetch('/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    const verification = await response.json();
    result.textContent = JSON.stringify(verification);
    document.documentElement.dataset.e2e = verification.ok ? 'passed' : 'failed';
  } catch (error) {
    result.textContent = JSON.stringify({ok: false, error: error.message});
    document.documentElement.dataset.e2e = 'failed';
  }
};
</script>`;
}

async function main() {
  const originalMapping = fs.readFileSync(mappingPath);
  const { entries, source } = loadMapping();
  const privateKey = fs.readFileSync(source.key_file);
  const publicKey = publicKeyFromRawPrivateKey(privateKey);
  const testEntry = {
    credential_id: testCredentialId,
    rp_id: testRpId,
    key_file: source.key_file,
  };

  fs.writeFileSync(mappingPath, JSON.stringify([
    ...entries.filter((entry) =>
      entry.credential_id !== testCredentialId || entry.rp_id !== testRpId),
    testEntry,
  ], null, 2));

  let server;
  let context;
  const profileDir = path.join(
    repoRoot,
    `.tmp-passkey-e2e-profile-${process.pid}`
  );
  try {
    server = http.createServer((request, response) => {
      if (request.method === 'GET' && request.url === '/') {
        response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
        response.end(html());
        return;
      }
      if (request.method === 'POST' && request.url === '/verify') {
        let body = '';
        request.on('data', chunk => { body += chunk; });
        request.on('end', () => {
          try {
            const assertion = JSON.parse(body);
            const clientData = JSON.parse(fromBase64url(assertion.clientDataJSON));
            const authData = fromBase64url(assertion.authenticatorData);
            const rpHash = crypto.createHash('sha256').update(testRpId).digest();
            const signed = Buffer.concat([
              authData,
              crypto.createHash('sha256').update(fromBase64url(assertion.clientDataJSON)).digest(),
            ]);
            const ok = assertion.id === testCredentialId
              && assertion.rawId === testCredentialId
              && clientData.type === 'webauthn.get'
              && clientData.challenge === assertion.challenge
              && clientData.origin === `http://${testRpId}:${port}`
              && authData.subarray(0, 32).equals(rpHash)
              && crypto.verify('sha256', signed, publicKey, fromBase64url(assertion.signature));
            response.writeHead(ok ? 200 : 400, {'Content-Type': 'application/json'});
            response.end(JSON.stringify({ok}));
          } catch (error) {
            response.writeHead(400, {'Content-Type': 'application/json'});
            response.end(JSON.stringify({ok: false, error: error.message}));
          }
        });
        return;
      }
      response.writeHead(404);
      response.end();
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });

    fs.rmSync(profileDir, {
      recursive: true,
      force: true,
      maxRetries: 20,
      retryDelay: 100,
    });
    context = await chromium.launchPersistentContext(profileDir, {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionDir}`,
        `--load-extension=${extensionDir}`,
      ],
    });
    const page = context.pages()[0] || await context.newPage();
    await page.goto(`http://${testRpId}:${port}`, {waitUntil: 'domcontentloaded'});
    await page.waitForFunction(() =>
      document.documentElement.getAttribute('data-facewinunlock-passkey-hook') === 'ready'
      && document.documentElement.getAttribute('data-facewinunlock-passkey-bridge') === 'ready',
      null,
      {timeout: 10000});
    await page.click('#run');
    await page.waitForFunction(() =>
      ['passed', 'failed'].includes(document.documentElement.dataset.e2e),
      null,
      {timeout: 30000});

    const result = JSON.parse(await page.textContent('#result'));
    if (!result.ok) {
      throw new Error(`Passkey E2E failed: ${JSON.stringify(result)}`);
    }
    console.log(`PASS: extension -> signer -> ECDSA verify (${source.key_file})`);
  } finally {
    if (context) {
      await context.close();
    }
    if (server) {
      await new Promise(resolve => server.close(resolve));
    }
    fs.writeFileSync(mappingPath, originalMapping);
    try {
      fs.rmSync(profileDir, {
        recursive: true,
        force: true,
        maxRetries: 20,
        retryDelay: 100,
      });
    } catch (error) {
      console.warn(`WARN: unable to remove temporary browser profile: ${error.message}`);
    }
  }
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
