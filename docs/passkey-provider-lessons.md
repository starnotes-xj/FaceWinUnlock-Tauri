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

## Uninstall: preserving credentials for reinstall (issue #3)

Goal: after uninstall / full-update / reinstall, reuse passkeys already registered
through the plugin without re-registering on each site.

Storage model (two separate parts):

- **Private key**: NCrypt **Microsoft Software KSP** (`NCryptOpenStorageProvider(nullptr)`),
  deterministic key name `facewinunlock/<hex(userId)>` (`PluginAuthenticatorImpl.cpp`,
  constant `facewinunlock_plugin_key_domain`), stored under the user's
  `%APPDATA%\Microsoft\Crypto\Keys` — **not inside the MSIX package**. No uninstall path
  deletes it (there is no `NCryptDeleteKey` anywhere except the explicit Purge mode).
- **Credential metadata** (credentialId ↔ rpId ↔ userId): MSIX LocalState
  `%LOCALAPPDATA%\Packages\<PFN>\LocalState\CredentialsDB\credentials.dat`. Removed with
  the package on a normal `Remove-AppxPackage`. GetAssertion needs it to map the site's
  allow-list credentialId → userId → rebuild the key name → open the KSP key. **So losing
  metadata makes the still-present private key unusable** → that's why reinstall used to
  require re-registration.

Implementation (`passkey_plugin.rs` + `scripts/uninstall-passkey-plugin.ps1` + `nsis/hooks.nsh`):

- Two modes: `KeepCredentials` (default) / `Purge`.
- KeepCredentials: `Remove-AppxPackage -PreserveApplicationData` keeps LocalState; back up
  `credentials.dat` to `%LOCALAPPDATA%\FaceWinUnlock\PasskeyBackup` before removal (fallback
  if LocalState gets wiped); keep private key + cert + registry config.
- After install/reinstall, if LocalState has no metadata but a backup exists, restore it.
- Purge: remove MSIX data + `certutil -delkey facewinunlock/*` (KSP private keys) + cert +
  registry + backup.
- Core uninstall and NSIS app-uninstall default to KeepCredentials; the app's uninstall
  button offers both options. Full update already uses `Add-AppxPackage -Update` (keeps data).

Caveats / must-verify on real hardware:

- PackageFamilyName must stay stable (Identity `Name` + `Publisher` fixed) so the LocalState
  path is reused on reinstall.
- Private key is DPAPI per-user: same Windows user reinstall works; profile reset / different
  user invalidates it (expected).
- `-PreserveApplicationData` needs Win10 1709+ (passkey itself needs 24H2, so satisfied).
- End-to-end validation needs **Win11 24H2 + a previously registered site passkey**; the
  `-PreserveApplicationData` reuse, backup/restore and `certutil -delkey` cannot be verified
  on a dev box without that setup.

## In-app residual-key cleanup + simplified delete UI (issue #3)

Follow-up to the keep-credentials work above. Two user-reported papercuts:

1. The plugin's "clear / delete passkeys" actions only remove credential metadata and the
   Windows index — they never call `NCryptDeleteKey` (confirmed in
   `PluginManagement/PluginCredentialManager.cpp`). So repeatedly clicking "clear" leaves the
   KSP private keys behind under `%APPDATA%\Microsoft\Crypto\Keys` (tiny, but a privacy residue).
2. The plugin exposed too many delete entries (per-cache / per-local-store / all-locations) plus an
   "add (write cache)" debug button — users could not tell them apart.

Fixes:

- **In-app cleanup** (`passkey_plugin.rs::cleanup_passkey_residual_keys`, wired in `lib.rs`,
  "清理残留私钥" button in `Options.vue`): enumerates the Microsoft Software KSP via
  `certutil -user -key`, deletes every key whose name starts with `facewinunlock/` via
  `certutil -user -delkey`, returns the deleted count. Per-user, no uninstall required.
  Guarded by a confirm dialog because it invalidates previously registered site passkeys.
- **Simplified delete UI** (`PasskeyPlugin/MainPage.xaml` + `.xaml.cpp`): keep only
  "删除所选通行密钥" + "清空全部通行密钥"; the cache/local-store detail items and the
  "add (write cache)" button get `Visibility="Collapsed"`. **All `x:Name`s are kept** (code-behind
  in `MainPage.xaml.cpp` sets their `.Text()`/`.IsEnabled()`), so elements are hidden, not deleted —
  deleting them would break the C++/WinRT code-behind and the `LocalizedText` overrides.

Relationship to keep-credentials uninstall: cleanup is the **active** opposite of the passive
keep — uninstall preserves keys for reinstall, this button deliberately purges the residue when
the user no longer wants them. Same `certutil -delkey facewinunlock/*` primitive as Purge mode,
but invokable without uninstalling. Needs Win11 24H2 to verify the actual KSP deletion.

**Critical: `certutil -delkey` MUST include `-csp`.** Enumeration uses
`certutil -user -key -csp 'Microsoft Software Key Storage Provider'`, and the delete must specify
the SAME provider: `certutil -user -csp 'Microsoft Software Key Storage Provider' -delkey '<name>'`.
Without `-csp`, certutil queries the default provider, can't find the CNG KSP key, and returns
`NTE_BAD_KEYSET` (0x80090016) → 0 deleted. Both `cleanup_passkey_residual_keys` and the uninstall
Purge script enumerated with `-csp` but deleted without it, so they silently removed nothing.
The app runs elevated (`requireAdministrator`); elevation was suspected first, but a non-elevated
manual `-delkey` failed identically until `-csp` was added — the real cause was the missing `-csp`.
