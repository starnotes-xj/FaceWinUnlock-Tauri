# UI: Tauri Management Application

`UI/` is the Tauri 2 and Vue 3 application used to install components, enroll faces, edit settings, inspect logs, manage the optional Passkey plugin, and apply updates.

## Stack

- Vue 3, Vue Router, Pinia, Vue I18n, Element Plus, Vite
- Tauri 2 Rust backend
- SQLite for local options, face records, and application logs
- OpenCV for enrollment, consistency checks, and camera preview

## Important Behavior

- Enrollment starts model loading early and sends `ui_release` before opening the camera so the Unlock prewarm loop yields the device.
- `stop_camera` always sends `ui_done`; failed camera opens use a guard so the background service is not left suppressed.
- Auto-lock settings are written immediately. The Unlock service polls the database every 30 seconds, which is why the UI reports “about 30 seconds to take effect.”
- Component deployment writes current Credential Provider registry defaults and removes obsolete UIA/animation flags from upgrades.
- Passkey MSIX install runs for the current desktop user. The elevated NSIS installer only establishes machine-level prerequisites and cleanup.

## Development

```powershell
Set-Location UI
npm ci
npm run dev
npm run build
npm run tauri dev
npm run tauri build
```

Rust backend checks run from the repository root:

```powershell
cargo test -p facewinunlock-tauri --lib
cargo check -p facewinunlock-tauri
```

The packaged application requests administrator privileges, so directly starting its full binary test harness from a non-elevated terminal may fail with Windows error 740.

## Structure

| Path | Role |
|---|---|
| `src/views/Faces/` | Enrollment and face management |
| `src/views/Options.vue` | Recognition, integration, auto-lock, update, and Passkey settings |
| `src/stores/` | SQLite-backed frontend state |
| `src-tauri/src/modules/` | Deployment, face processing, Passkey management, updates |
| `src-tauri/src/utils/api.rs` | Camera, service, scheduled-task, and application commands |
| `src-tauri/nsis/` | Installer and uninstall hooks |

See [../docs/architecture.md](../docs/architecture.md) and [../docs/testing.md](../docs/testing.md).
