# Passkey Provider Constraints

## Supported Route

The only supported browser passkey route is the official Windows Passkey Provider in `PasskeyPlugin/`.

- The plugin creates and owns each WebAuthn key.
- A website registers the public key created by this plugin.
- Unlock provides one local face user-verification decision.
- The plugin signs through the Windows plugin API and its per-user Software KSP key.

An existing Windows Hello passkey cannot be reused by constructing another local private key. The relying party verifies against the public key registered earlier, and Windows Hello/Passport private keys are non-exportable. The removed browser extension and local HTTP signer were therefore both unreliable and architecturally wrong.

## Generic Credential Provider Isolation

The generic Credential Provider must not handle passkey, security-key, FIDO2, or PIN-setup operations. Unlock monitors `Microsoft-Windows-WebAuthN/Operational` and exposes Ready/Active state. Active is a mandatory veto, including if the transaction begins after initial enumeration.

This isolation does not block the official plugin: it requests face authorization over its separate `FaceWinUnlockPasskeyFaceAuth` pipe.

## Packaging

- The Passkey Provider requires Windows 11 build 26100 or later.
- NSIS runs elevated/per-machine, while MSIX registration is per-user. The application installs or updates the package in the current desktop-user context.
- Machine-level certificate trust may be established by the installer, but enabling the provider and the one-time Windows verification remain explicit user actions.
- Package identity, provider CLSID, AAGUID, and KSP key naming must remain stable.

## Credential Storage

Two stores are required:

1. Private key: per-user Microsoft Software KSP, deterministic name `facewinunlock/<userId>`.
2. Metadata: package LocalState mapping credential ID, RP, user ID, and key name.

Removing the MSIX can remove LocalState while leaving the KSP key. The key then exists but cannot be found for an assertion. Keep mode therefore backs up metadata outside the package under:

```text
%ProgramData%\facewinunlock-tauri\PasskeyBackup
```

ProgramData was chosen so third-party uninstallers that clean `%APPDATA%` and `%LOCALAPPDATA%` FaceWinUnlock folders do not erase the recovery copy.

## Uninstall Modes

### Keep Credentials

- Back up metadata before package removal.
- Remove/replace the package as required.
- Keep per-user KSP keys and restore metadata after reinstall.
- Core and NSIS uninstall default to this mode.

### Purge

- Remove package metadata and external backups.
- Delete matching `facewinunlock/*` keys from Microsoft Software Key Storage Provider.
- Remove certificate trust and plugin configuration.

`certutil -delkey` must specify the same `-csp 'Microsoft Software Key Storage Provider'` used for enumeration. Without `-csp`, deletion can report `NTE_BAD_KEYSET` and leave keys behind.

## Expected Results

- Uninstalled package: FaceWinUnlock no longer appears as a passkey save location.
- Keep uninstall/reinstall under the same Windows profile: previously registered FaceWinUnlock passkeys work after metadata restoration.
- Different Windows profile or profile reset: old per-user keys are intentionally unusable.
- Purge: previously registered site credentials no longer work and should be removed from the site account.

Manual cases are listed in [testing.md](testing.md).
