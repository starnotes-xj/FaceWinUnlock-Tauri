# Unlock: Face Recognition Service

`Unlock/` builds `FaceWinUnlock-Server.exe`, a supervisor/worker service that runs the camera and recognition pipeline outside LogonUI.

## Responsibilities

- Serve the Credential Provider control and credential pipes.
- Load enabled face records and OpenCV models, open the configured camera, and match faces.
- Prewarm the lock-screen camera and release it after inactivity or manual PIN unlock.
- Coordinate camera ownership with the UI through `ui_release`/`ui_done`.
- Subscribe to `Microsoft-Windows-WebAuthN/Operational` and publish WebAuthn Ready/Active named events.
- Serve the dedicated `FaceWinUnlockPasskeyFaceAuth` authorization pipe.
- Monitor idle time and request automatic locking in the active interactive WTS session.

## Process Model

The scheduled task starts a SYSTEM supervisor. It starts the worker with `--facewinunlock-worker` and restarts it with bounded backoff after failures.

`LockWorkStation` cannot lock an interactive user from Session 0. Auto-lock therefore selects the active WTS session, obtains its user token, launches the same executable with `--lock-workstation-once` on `winsta0\default`, and confirms the WTS session lock flag.

## Camera Policy

Camera opening uses the maintained MSMF, DirectShow, then Any fallback order. MSMF hardware transforms are disabled before first open. The UI can temporarily own the device; every successful or failed UI camera session must eventually emit `ui_done`.

No enabled face records means no lock-screen camera prewarm. After a manual PIN unlock, prewarm remains blocked until the old credential session has disconnected and a new session is observed.

## Build And Test

```powershell
cargo test -p unlock
cargo build --release -p unlock
```

Output: `target\release\FaceWinUnlock-Server.exe`.

If the test executable cannot locate `opencv_world4120.dll`, prepend `target\debug\resources` or the configured OpenCV `bin` directory to `PATH`.

Installed behavior, including issue #26 and #27 regression steps, is covered by [../docs/testing.md](../docs/testing.md).
