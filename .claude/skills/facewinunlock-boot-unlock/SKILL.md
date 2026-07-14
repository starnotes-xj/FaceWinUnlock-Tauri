---
name: facewinunlock-boot-unlock
description: Diagnose slow or missing FaceWinUnlock camera startup after boot, lock, sleep, or resume.
---

# FaceWinUnlock Boot And Unlock Diagnostics

Use this playbook when lock-screen recognition is delayed, the camera does not open, the worker restarts, or the camera remains active after manual PIN unlock.

## 1. Collect Evidence

Read the installed logs before changing code:

```powershell
$install = 'D:\facewinunlock-tauri'
Get-Content "$install\logs\unlock.log" -Tail 300
Get-Content "$install\logs\facewinunlock.log" -Tail 300
```

Record the exact sequence: boot or resume time, `Win+L`, first mouse/keyboard activity, camera LED on/off, face result, PIN submission, and desktop arrival.

## 2. Classify The Delay

- Repeated `worker exited` or exit code 101: inspect the first panic line and supervisor restart cadence.
- Long gap inside `open camera backend`: camera backend or driver delay.
- `prepare` without `run`: Credential Provider/session trigger problem.
- `run` followed by no frames: camera ownership or model/backend problem.
- PIN unlock followed by camera reopen: verify `release`, credential-client disconnect, and new-session gate logs.
- Browser/passkey-only delay: inspect WebAuthn Ready/Active and broker classification; do not apply lock-screen fixes blindly.

## 3. Known Invariants

- Elapsed-time initialization must use `Instant::checked_sub`; early boot uptime can be shorter than a requested offset.
- Supervisor restart uses backoff and resets only after a stable run. Never create a tight crash loop.
- Camera open order is MSMF, DirectShow, then Any, with MSMF hardware transforms disabled before first open.
- The UI sends `ui_release` before camera use and `ui_done` on success, failure, cancellation, and close.
- Manual PIN unlock must release the camera and suppress prewarm until the previous credential client has disconnected.
- No face records means no prewarm.
- Do not reintroduce lock-screen animation, UI Automation, or PIN injection while investigating latency.

## 4. Verify A Fix

```powershell
cargo test -p unlock
cargo test -p winlogon
cargo check --workspace
```

Install a CI-built candidate and repeat:

1. Cold boot, then first lock/unlock.
2. `Win+L`, wake by mouse, face unlock.
3. `Win+L`, keep face away, enter PIN, verify camera off within 5 seconds.
4. Sleep/resume and repeat steps 2-3 at least six times.
5. Confirm browser password and Passkey flows still follow `docs/testing.md`.

Do not close issue #26 or #27 from unit tests alone. Both need installed Windows evidence and camera-release observation.
