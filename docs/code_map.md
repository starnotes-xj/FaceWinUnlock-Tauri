# Code Map

## Workspace

| Path | Main entry | Output |
|---|---|---|
| `Server/` | `src/lib.rs` | `FaceWinUnlock_Tauri.dll` |
| `Unlock/` | `src/main.rs` | `FaceWinUnlock-Server.exe` |
| `UI/src-tauri/` | `src/lib.rs`, `src/main.rs` | `facewinunlock-tauri.exe` |
| `PasskeyPlugin/` | `PasskeyManager.sln` | `FaceWinUnlock-Passkey.msix` |

## Server

- `lib.rs`: COM exports, DLL lifetime, shared credential state, logging, owner-window context, browser allowlist, WebAuthn event handles, broker classification and tests.
- `CSampleProvider.rs`: usage-scenario filtering, broker policy, credential enumeration, listener lifecycle.
- `CSampleCredential.rs`: face tile fields, credential serialization and failed-result cleanup.
- `CPipeListener.rs`: control/credential threads, WebAuthn race checks, broker fallback, asynchronous teardown, DLL lifetime guards.
- `Pipe.rs`: Win32 named-pipe operations and payload parsing.

## Unlock

- `main.rs`: supervisor/worker entry, three named-pipe servers, face-recognition loop, camera prewarm, UI camera yield, WTS session-idle auto-lock, helper launch, service logging.
- `power_events.rs`: traditional suspend/resume plus console-display power notifications, with a combined camera-blocking generation state for Modern Standby.
- `webauthn_activity.rs`: Event Log channel/provider validation, ten-minute replay, pull subscription, transaction tracking/expiry, Ready/Active named events.
- `passkey/mod.rs`: serialized face-authorization state machine for the official Passkey plugin.

## UI Backend

- `modules/init.rs`: administrator checks, component registration, registry defaults, obsolete-value migration cleanup.
- `modules/faces.rs`: enrollment detection, alignment, feature extraction, passive-liveness burst capture and consistency checks.
- `modules/liveness.rs`: pinned PAD model contract, expanded square preprocessing, Softmax probability and median fusion.
- `modules/passkey_plugin.rs`: current-user MSIX management, metadata backup/restore, purge and residual-key cleanup.
- `modules/update_check.rs`: semantic-version and same-version hash checks.
- `modules/update_download.rs`: manifest validation, SHA-256 diff and staging.
- `utils/api.rs`: camera/model lifecycle, scheduled tasks, service restart, update replacement, app lifecycle.
- `nsis/hooks.nsh`: machine-level install/uninstall, certificate trust, runtime copy/repair, historical artifact cleanup.

## UI Frontend

- `src/views/Faces/`: enrollment and face management.
- `src/views/Options.vue`: camera, inference, system integration, automatic lock, Passkey and update controls.
- `src/layout/MainLayout.vue`: shell, tray/window behavior, update prompts.
- `src/stores/`: SQLite-backed options and face state.

## Passkey Plugin

- `PluginAuthenticatorImpl.*`: WebAuthn authenticator operations and plugin-owned key use.
- `PluginManagement/`: credential metadata and Windows index management.
- `MainPage.xaml*`: management UI.
- `Package.appxmanifest`: package identity, COM server and minimum Windows build.

## Important Configuration

Registry root: `HKLM\SOFTWARE\facewinunlock-tauri`.

| Value | Default | Meaning |
|---|---:|---|
| `UNLOCK_SCENE` | `1,2,4` | Logon, unlock, CredUI scenarios |
| `SHOW_TILE` | `1` | Show FaceWinUnlock tile |
| `CONNECT_TO_PIPE` | `1` | Enable Unlock IPC |
| `DLL_LOG_PATH` | install `logs` | Credential Provider log directory |
| `UNLOCK_GRACE_PERIOD` | `0.0` | Delay before first recognition request |
| `RETRY_DELAY` | `1.0` | Recognition retry base delay |
| `CREDUI_ALLOW_GENERIC` | `0` | Allow generic CredUI such as RDP |
| `CREDUI_ALLOW_BROKER` | `1` | Enable broker scene classification |
| `CREDUI_BROKER_FALLBACK_TIMEOUT` | `5` or installer `6` | Face timeout before Windows fallback |
| `CREDUI_BROWSER_PASSWORD_FILL` | `1` | Guarded unknown browser password-fill fallback |

`CREDUI_UIA_DETECT`, `CREDUI_BROKER_TRY_FACE_UNKNOWN`, animation settings, and old takeover flags are obsolete. Their remaining uses must only delete old installations.

## Release Outputs

`.github/workflows/release.yml` publishes:

- `FaceWinUnlock_Tauri.dll`
- `FaceWinUnlock-Server.exe`
- `FaceWinUnlock-Passkey.msix`
- `FaceWinUnlock-Passkey.cer`
- `update_manifest.json`
- NSIS setup executable

Release candidates remain pre-releases; stable update checks use GitHub's latest stable release.
