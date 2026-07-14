# CLAUDE.md

`AGENTS.md` is the canonical repository guide and applies to Claude as well. Read it before modifying code.

## Current Project Facts

- All three Rust components and the Tauri UI are buildable; the old upstream statement that the core is closed or cannot compile is obsolete.
- The supported passkey path is `PasskeyPlugin/`, built on the Windows Passkey Provider API with plugin-owned keys.
- `BrowserExt/`, `key_capture/`, the local HTTP signer, and the lock-screen animation were deliberately deleted.
- UI Automation and automatic PIN/password input are prohibited. Do not propose them as fallbacks.
- The generic Credential Provider must skip active WebAuthn, passkey, security-key, FIDO2, PIN-setup, private-browser, and unclassified unhealthy-monitor scenarios.
- Supported browser owners for guarded password-fill fallback are Chrome, Edge, Brave, Opera/Opera GX, Vivaldi, Chromium, and 360.
- Auto-lock is implemented by launching the signed helper in the active WTS user session and confirming the session lock state; Session 0 cannot lock the workstation directly.
- Lock-screen animation code and graphics imports must stay absent.

## Required Checks

```powershell
cargo test -p winlogon
cargo test -p unlock
cargo test -p facewinunlock-tauri --lib
cargo check --workspace
git diff --check
```

Use [docs/testing.md](docs/testing.md) for installed release validation. Code completion alone is not enough to close sleep/resume issue #26 or auto-lock issue #27; both require repeated real Windows tests and camera-release observation.
