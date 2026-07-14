# FaceWinUnlock Passkey Provider

`PasskeyPlugin/` is a C++/WinRT Windows Passkey Manager plugin derived from Microsoft's sample. It uses the official Windows plugin API and owns each credential's P-256 key in Microsoft Software KSP.

FaceWinUnlock supplies only local user verification over:

```text
\\.\pipe\FaceWinUnlockPasskeyFaceAuth
```

The service replies `AUTHORIZED`, `REJECTED`, or `TIMEOUT`. It never exports or signs with a Windows Hello passkey key.

## Requirements

- Windows 11 24H2 (build 26100) or later
- Windows SDK 10.0.26100 or later
- Visual Studio 2022 C++ desktop and UWP workloads
- NuGet/MSBuild network access for the first build

## Build

```powershell
.\scripts\build-passkey-plugin.ps1
```

Outputs:

```text
target\release\FaceWinUnlock-Passkey.msix
target\release\FaceWinUnlock-Passkey.cer
```

Release signing requires a certificate whose subject exactly matches `Package.appxmanifest`.

## Install And Enable

Use the FaceWinUnlock application or:

```powershell
.\scripts\install-passkey-plugin.ps1
```

Windows performs a one-time system verification when the provider is enabled. That operating-system gate is intentionally not automated. Sites must save a new passkey through FaceWinUnlock before they can authenticate with it.

## Storage And Uninstall

- Private keys are per-user Microsoft Software KSP keys named `facewinunlock/<userId>`.
- Credential metadata is stored in the package's LocalState.
- Reinstall backups are stored outside the package under `%ProgramData%\facewinunlock-tauri\PasskeyBackup`.
- Keep mode preserves recoverable credentials. Purge mode deletes metadata, backups, certificate trust, and matching KSP keys.

Third-party uninstallers may delete `%LOCALAPPDATA%` and `%APPDATA%` application folders; the ProgramData backup is designed to survive that cleanup. A Windows profile reset or different user cannot reuse the per-user keys.

## Stable Identity

- Provider CLSID: `04acca15-3530-4a85-ac6a-28035a31f711`
- AAGUID: `5ebe674a-f273-4c65-9312-4412ff384f93`
- Package identity: `FaceWinUnlock.PasskeyManager`

Do not change these identities after credentials have been issued.

See [../docs/passkey-provider-lessons.md](../docs/passkey-provider-lessons.md) and [../docs/testing.md](../docs/testing.md).
