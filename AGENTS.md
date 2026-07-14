# AGENTS.md

This file is the repository-specific operating guide for coding agents. Product behavior and test expectations are documented under `docs/`; do not reconstruct behavior from old plans or release notes.

## Repository

FaceWinUnlock-Tauri has four active components:

| Path | Package/output | Responsibility |
|---|---|---|
| `Server/` | `winlogon` / `FaceWinUnlock_Tauri.dll` | Windows Credential Provider COM DLL |
| `Unlock/` | `unlock` / `FaceWinUnlock-Server.exe` | Camera, recognition, WebAuthn monitor, auto-lock, passkey face gate |
| `UI/` | `facewinunlock-tauri` | Tauri 2 + Vue 3 management app and NSIS installer |
| `PasskeyPlugin/` | `FaceWinUnlock-Passkey.msix` | Windows 11 Passkey Provider with plugin-owned keys |

The workspace root contains the three Rust packages. The C++/WinRT Passkey plugin is built by `scripts/build-passkey-plugin.ps1`.

## Non-Negotiable Constraints

- Never introduce UI Automation, `IUIAutomation`, `AutomationElement`, protected-dialog control scraping, or UIA COM activation.
- Never synthesize, alter, suppress, or submit PIN/password input with `SendInput`, keyboard hooks, or blind injection. The existing read-only low-level input hook may only trigger recognition after user activity.
- Never restore the removed browser-extension/passkey-key-capture route. `BrowserExt/`, `key_capture/`, and the old local signer were deleted because they cannot reuse Windows Hello passkey private keys safely or correctly.
- Never restore the Credential Provider lock-screen animation or DComp/D2D/D3D/DWrite/DXGI dependencies. The animation caused old-Windows load failures and lifecycle regressions.
- WebAuthn Active is a mandatory veto for the generic Credential Provider. The official Passkey plugin uses its separate face-authorization pipe.
- Unknown browser password fill is allowed only for the maintained Chromium-family allowlist, when the WebAuthn monitor is Ready and not Active, the window is not private, and `CREDUI_BROWSER_PASSWORD_FILL=1`.
- Keep browser support broad: Chrome, Edge, Brave, Opera/Opera GX, Vivaldi, Chromium, and 360 browsers.
- On monitor failure, unknown broker scenarios fail closed to Windows PIN. Do not infer “password” from the absence of a WebAuthn event alone.
- Keep Passkey CLSID/AAGUID/package identity stable after credentials have been issued.
- Do not log credential serialization bytes, passwords, PINs, RP data, usernames, or WebAuthn request content.

Migration-only references to `FaceWinUnlock-UIA-Helper.exe`, `CREDUI_UIA_DETECT`, or `ANIMATION_UI_ENABLED` may remain in uninstall/upgrade cleanup code. They delete historical artifacts and are not runtime features.

## Windows Environment

```powershell
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME = "D:\Rust\CARGO"
$env:PATH = "D:\Rust\CARGO\bin;$env:PATH"
```

OpenCV 4.12 and its OpenVINO runtime are expected under `D:\OpenCV` in the maintained local and CI environments. `UI/src-tauri/tauri.conf.json` defines bundled runtime paths.

## Build And Test

```powershell
cargo test -p winlogon
cargo test -p unlock
cargo test -p facewinunlock-tauri --lib
cargo check --workspace
cargo build --release

.\scripts\build-passkey-plugin.ps1
Set-Location UI
npm ci
npm run build
npm run tauri build
```

When `unlock` tests cannot load OpenCV, prepend `target\debug\resources` or the configured OpenCV `bin` directory to `PATH`. The full UI binary harness may require elevation because its manifest requests administrator rights; `--lib` is the normal unit-test target.

Formal installers are built by `.github/workflows/release.yml`. Release tags synchronize the Tauri, Cargo, npm, and MSIX versions. Tags containing `-rc`, `-beta`, or `-alpha` must remain pre-releases and must not replace the stable `latest` release.

## Architecture Rules

### Credential Provider

- `SetUsageScenario` performs the first classification; `Advise` and pipe submission repeat the WebAuthn Active check to cover races.
- `CPUS_LOGON` and `CPUS_UNLOCK_WORKSTATION` may use face credentials.
- `CPUS_CREDUI` is filtered by owner process, explicit password/passkey/PIN signals, privacy state, registry policy, and WebAuthn monitor state.
- Returning `E_NOTIMPL` is the expected safe handoff to Windows.
- Host UI threads must not wait on blocking pipe teardown. Background threads that outlive COM calls must hold a DLL reference.

### Unlock Service

- Camera ownership is coordinated through `ui_release` and `ui_done`.
- Manual PIN unlock must release the camera and keep prewarm suppressed until the old credential client disconnects and a new session is observed.
- The WebAuthn monitor uses the Windows Event Log pull subscription model and publishes only named Ready/Active events.
- Auto-lock runs as SYSTEM but launches a short helper in the active interactive WTS session; Session 0 must not call `LockWorkStation` directly.
- The auto-lock setting is saved immediately by the UI and re-read by the service every 30 seconds.

### Passkey Provider

- The plugin owns each credential key and signs through the official Windows plugin API.
- Unlock supplies one `AUTHORIZED`, `REJECTED`, or `TIMEOUT` decision over `FaceWinUnlockPasskeyFaceAuth`.
- Metadata backups live under `%ProgramData%\facewinunlock-tauri\PasskeyBackup`; private KSP keys remain per-user.

## Editing And Verification

- Read existing code and `docs/architecture.md` before changing behavior.
- Do not revert unrelated dirty-worktree changes. Use a clean worktree for release work.
- Use `rg` for literal searches and CodeGraph for symbol/call-impact questions when its index is initialized.
- Use `apply_patch` for manual edits. Keep changes scoped and avoid new dependencies unless explicitly required.
- For cleanup, write a bounded plan, run regression tests first, delete dead code before adding abstractions, then rerun tests and static scans.
- Update the relevant document and `docs/testing.md` whenever a public workflow or release-critical invariant changes.

Before declaring completion, run `git diff --check`, Rust tests/checks, the Vue production build when frontend files changed, and scans for forbidden UIA/PIN-injection code. Real lock-screen, sleep/resume, camera, UAC, and Passkey behavior still requires installed Windows testing.

## Lore Commits

Commit subjects state why the change exists. Add useful git trailers after a blank line:

```text
Prevent passkey requests from entering the generic credential path

Constraint: Credential Provider fields cannot distinguish password fill from WebAuthn
Rejected: UI Automation dialog inspection | unavailable and prohibited
Confidence: high
Scope-risk: moderate
Directive: Keep WebAuthn Active as a mandatory veto
Tested: cargo test -p winlogon; cargo test -p unlock
Not-tested: installed Win11 24H2 passkey flow
```

## Canonical Documents

- `docs/architecture.md`: component and trust boundaries
- `docs/code_map.md`: source ownership and IPC
- `docs/testing.md`: release-candidate acceptance tests
- `docs/credui-broker-scene-and-autolock-fixes.md`: broker and auto-lock invariants
- `docs/passkey-provider-lessons.md`: Passkey storage and uninstall behavior
- `docs/incremental-update-design.md`: current updater behavior
- `docs/opencv-world-packaging-fix.md`: OpenCV packaging and camera backend rules
