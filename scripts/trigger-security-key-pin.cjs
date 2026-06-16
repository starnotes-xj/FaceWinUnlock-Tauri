'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const username = process.argv[2]
  || process.env.FACEWINUNLOCK_WEBAUTHN_USER
  || 'starnotes';
const observeSeconds = Number(
  process.env.FACEWINUNLOCK_PIN_OBSERVE_SECONDS || 20
);
const repoRoot = path.resolve(__dirname, '..');
const profileDir = path.join(repoRoot, '.tmp-native-passkey-profile');

function brokerPids() {
  const script = [
    'Get-Process credentialuibroker -ErrorAction SilentlyContinue',
    '| Select-Object -ExpandProperty Id',
  ].join(' ');
  try {
    return execFileSync('powershell', [
      '-NoProfile',
      '-Command',
      script,
    ], {encoding: 'utf8'})
      .split(/\s+/)
      .filter(Boolean)
      .map(Number);
  } catch {
    return [];
  }
}

async function main() {
  fs.rmSync(profileDir, {recursive: true, force: true});
  const before = new Set(brokerPids());
  const context = await chromium.launchPersistentContext(profileDir, {
    channel: 'chrome',
    headless: false,
    args: ['--disable-extensions'],
  });

  try {
    const page = context.pages()[0] || await context.newPage();
    await page.goto('https://webauthn.io', {
      waitUntil: 'domcontentloaded',
      timeout: 30000,
    });
    await page.getByPlaceholder('example_username').fill(username);
    await page.getByRole('button', {name: 'Authenticate'}).click();

    const deadline = Date.now() + 10000;
    let detected = [];
    while (Date.now() < deadline) {
      detected = brokerPids().filter(pid => !before.has(pid));
      if (detected.length > 0) {
        break;
      }
      await page.waitForTimeout(250);
    }

    if (detected.length === 0) {
      throw new Error(
        'credentialuibroker.exe was not detected; confirm the webauthn.io user has a registered passkey'
      );
    }

    console.log(
      `PASS: native security-key UI triggered in credentialuibroker.exe PID ${detected.join(', ')}`
    );
    console.log(
      `The PIN dialog will remain open for ${observeSeconds} seconds for manual inspection.`
    );
    await page.waitForTimeout(observeSeconds * 1000);
  } finally {
    await context.close();
    fs.rmSync(profileDir, {recursive: true, force: true});
  }
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
