# FaceWinUnlock Passkey Provider Lessons

## Current route

The supported passkey route is the official Windows passkey provider plugin:

- `PasskeyPlugin` owns and registers its own non-exportable WebAuthn keys.
- Sites must register a new credential whose public key belongs to this plugin.
- FaceWinUnlock only provides the local user-verification gate over
  `\\.\pipe\FaceWinUnlockPasskeyFaceAuth`.
- In vault-locked mode, successful face authorization is both user verification
  and the local operation confirmation, so the plugin can run silently without
  showing its own confirm window.

## What was proven

- The old browser-extension takeover path is not a valid way to reuse existing
  Windows Hello passkeys. Those private keys are non-exportable and Passport KSP
  rejects third-party silent signing. A locally constructed P-256 key can produce
  a syntactically valid signature, but it does not match the relying party public
  key that was registered earlier.
- WebAuthn sites such as webauthn.io correctly reject signatures whose public key
  does not match the registered credential.
- The successful path is: install/register/enable the official provider, register
  a new site passkey through it, then authenticate through the provider with
  FaceWinUnlock as the UV gate.

## Packaging decisions

- NSIS does not run `Add-AppxPackage`. MSIX packages are per-user, while NSIS is
  elevated/per-machine and may run under an administrator account that is not the
  desktop user.
- NSIS only trusts `FaceWinUnlock-Passkey.cer` at machine level
  (`LocalMachine\TrustedPeople` and `LocalMachine\Root`) and leaves MSIX install
  to the app UI/current user flow.
- Uninstall must remove both the app package and any certificate trust that was
  imported by install scripts or NSIS.

## Manual validation notes

Expected successful face-present flow:

1. Browser requests passkey authentication.
2. Plugin logs `passkey plugin requested face authorization`.
3. Camera opens and FaceWinUnlock returns `AUTHORIZED`.
4. Plugin signs through its own credential and the site reports authentication
   success without PIN input or an extra plugin confirmation popup.

Expected remote/no-face flow:

1. No confirmation popup is shown.
2. Camera opens but face recognition reports no face.
3. Plugin logs `passkey face authorization rejected`.
4. Site shows authentication failure. This is expected and does not indicate a
   signing-path regression.
