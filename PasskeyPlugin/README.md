# FaceWinUnlock Passkey Plugin

Windows Passkey Manager plugin authenticator based on Microsoft's Passkey
Manager sample. The plugin owns each credential's P-256 key and performs
WebAuthn signatures through the official Windows plugin API.

User verification is delegated to the local FaceWinUnlock service through:

```text
\\.\pipe\FaceWinUnlockPasskeyFaceAuth
```

The service replies with `AUTHORIZED`, `REJECTED`, or `TIMEOUT`. A successful
face match returns `S_OK` before the sample's Windows Hello verification call,
so normal passkey operations do not ask for a PIN.

## Requirements

- Windows 11 with Passkey Manager plugin support
- Windows SDK 10.0.26100 or newer
- Visual Studio 2022 Build Tools with Desktop C++ and UWP workloads
- NuGet/MSBuild network access on the first build

## Build

From the repository root:

```powershell
.\scripts\build-passkey-plugin.ps1
```

Development output:

```text
target\release\FaceWinUnlock-Passkey.msix
target\release\FaceWinUnlock-Passkey.cer
```

For release distribution, pass `-CertificateThumbprint` for a certificate
whose subject exactly matches the `Publisher` in `Package.appxmanifest`.

## Install

```powershell
.\scripts\install-passkey-plugin.ps1
```

After registration, Windows requires a one-time system verification when the
provider is enabled under passkey advanced settings. That operating-system
gate is intentionally not automated.

## Stable Identity

- CLSID: `04acca15-3530-4a85-ac6a-28035a31f711`
- AAGUID: `5ebe674a-f273-4c65-9312-4412ff384f93`

Do not change either value after credentials have been issued.

## Upstream

Derived from the Microsoft Windows App Development samples Passkey Manager
plugin. See `THIRD_PARTY_LICENSE.txt`.
