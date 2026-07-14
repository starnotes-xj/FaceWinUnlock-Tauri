# FaceWinUnlock-Tauri

[中文](README.md) | [Releases](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases) | [Test guide](docs/testing.md)

FaceWinUnlock-Tauri provides local face-assisted Windows sign-in for ordinary cameras that are not supported by Windows Hello. It combines a Tauri/Vue management app, a Rust recognition service, a Windows Credential Provider, and an optional Windows Passkey Provider.

This fork is fully buildable and open source. The current implementation does not use UI Automation, inspect protected dialog controls, synthesize PIN keystrokes, or ship the removed lock-screen animation.

## Features

- Face verification for Windows logon, workstation unlock, and UAC.
- Password reveal and password-fill verification in Chrome, Edge, Brave, Opera, Vivaldi, 360, and Chromium.
- A WebAuthn activity guard that keeps passkeys, security keys, FIDO2, and PIN setup out of the generic Credential Provider.
- An optional FaceWinUnlock Passkey Provider on Windows 11 24H2+. The plugin owns its non-exportable keys; face recognition is only its local user-verification gate.
- Camera prewarming, automatic locking, brightness control, camera rotation, CPU/OpenCL inference, and local differential updates.
- Passkey metadata backup under `%ProgramData%\facewinunlock-tauri\PasskeyBackup` for reinstall recovery.

## Security Boundary

This is not equivalent to Windows Hello. An ordinary RGB camera and application-level liveness checks do not provide the same guarantees as Hello infrared hardware, TPM-backed policy, and the Windows biometric stack. The Credential Provider must read and submit the locally configured Windows account credentials, so this software is intended for personal or otherwise controlled devices.

Face processing and credential handling stay on the local machine. Install only builds published by this repository and keep a working password or Windows PIN available during initial testing.

## Requirements

- Windows 10/11 x64. The Passkey Provider requires Windows 11 24H2 (build 26100) or later.
- A camera available through Windows Media Foundation or DirectShow.
- Administrator rights for installation, Credential Provider registration, and scheduled tasks.
- A compatible driver for OpenCL/FP16. Switch back to CPU if GPU inference is slow or unreliable.

## Install

1. Download the latest stable installer from [Releases](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases).
2. Install as administrator and complete the initialization wizard.
3. Enroll a face and run the in-app consistency check.
4. Keep a working password or PIN, then validate workstation unlock with `Win+L`.
5. On Windows 11 24H2+, optionally install and enable the Passkey plugin. Sites must register a new credential created by FaceWinUnlock.

Validate release candidates with [docs/testing.md](docs/testing.md) before promoting them to a stable release.

## Architecture

```text
UI (Tauri + Vue)
  |-- SQLite settings, enrollment, deployment, updates
  `-- ui_release / ui_done camera coordination

Credential Provider DLL (Server)
  |-- logon, unlock, UAC, and selected CredUI scenarios
  |-- rejects generic activation while WebAuthn is active
  `-- drives Unlock and submits credentials through named pipes

FaceWinUnlock-Server.exe (Unlock)
  |-- OpenCV matching, camera prewarm, automatic locking
  |-- WebAuthn Operational event monitor
  `-- dedicated face-authorization pipe for the passkey plugin

PasskeyPlugin (optional MSIX)
  `-- official Windows plugin API, plugin-owned keys, local face UV
```

See [architecture](docs/architecture.md) and the [code map](docs/code_map.md).

## Build

The maintained Windows environment uses Rust under `D:\Rust` and OpenCV 4.12 under `D:\OpenCV`:

```powershell
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME = "D:\Rust\CARGO"
$env:PATH = "D:\Rust\CARGO\bin;$env:PATH"

cargo build --release
.\scripts\build-passkey-plugin.ps1
Set-Location UI
npm ci
npm run build
npm run tauri build
```

Run `.\build.ps1` for the complete local pipeline. Stable installers are built by [GitHub Actions](.github/workflows/release.yml); release tags synchronize all package versions.

## Verify

```powershell
cargo test -p winlogon
cargo test -p unlock
cargo test -p facewinunlock-tauri --lib
cargo check --workspace
```

The elevated UI binary test harness may fail with Windows error 740 in a normal terminal. The library tests do not require elevation.

## Documentation

- [Release test checklist](docs/testing.md)
- [Architecture](docs/architecture.md)
- [CredUI and automatic-lock design](docs/credui-broker-scene-and-autolock-fixes.md)
- [Passkey Provider constraints](docs/passkey-provider-lessons.md)
- [Update system](docs/incremental-update-design.md)
- [OpenCV packaging and Windows 10 camera compatibility](docs/opencv-world-packaging-fix.md)

## License

See [LICENSE](LICENSE). Third-party notices for the Microsoft-derived Passkey sample are in `PasskeyPlugin/THIRD_PARTY_LICENSE.txt`.
