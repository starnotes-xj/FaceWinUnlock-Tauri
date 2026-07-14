# Release Candidate Test Guide

Use this checklist for `v0.5.10-rc1` and later candidates. Test on the installed CI package, not a loose DLL/EXE copy. Keep a working Windows password or PIN available.

## Before Testing

1. Download the candidate from its GitHub pre-release page and verify the tag and installer name.
2. Note the Windows build, camera model, browser versions, account type, and selected inference backend.
3. Install over the current version unless the case explicitly asks for a clean install.
4. Confirm the dashboard reports the core service running and the Credential Provider installed.
5. Use CPU inference for the release gate; test OpenCL separately.
6. Clear or archive the installed logs so each scenario is easy to identify.

Default log paths:

```text
<install dir>\logs\unlock.log
<install dir>\logs\facewinunlock.log
<install dir>\logs\app.log
```

## Fast Acceptance Order

Run these first. Stop the release if any item fails.

1. Add or edit a face; camera preview appears without a long black screen.
2. `Win+L`, move the mouse, and unlock by face.
3. `Win+L`, keep the face away, enter Windows PIN manually, and confirm the camera LED turns off within 5 seconds.
4. Reveal a saved browser password; face verification succeeds.
5. Fill a website password such as QQ Mail; face verification succeeds.
6. Perform a Google or webauthn.io passkey action and choose Windows Hello or a security key; the generic Credential Provider must not start its camera.
7. Separately choose a passkey saved with FaceWinUnlock; the plugin's dedicated face authorization starts the camera and succeeds.
8. Enable automatic lock with a 30-second timeout and confirm it locks through the interactive-session helper.
9. Sleep/resume and repeat face unlock plus manual PIN unlock.

## Enrollment And Camera Ownership

### No Face Records

1. Temporarily disable/delete all enrolled faces.
2. Press `Win+L`, move the mouse, then unlock with Windows PIN.
3. Expected: the camera should not prewarm when no enabled face record exists.
4. Expected: after desktop arrival, the camera LED is off and stays off.

### Enrollment Startup

1. With lock-screen prewarm recently active, unlock manually and immediately open Add Face.
2. Click camera capture as soon as the page is ready.
3. Expected: the Unlock service releases the camera after `ui_release`; the preview is not black.
4. Expected: model loading and camera opening proceed concurrently where possible; the UI remains responsive.
5. Cancel, return, and repeat six times. The camera must close after every exit/error path.

### Virtual Camera

Repeat once with NVIDIA Broadcast or another virtual camera. A longer warmup is acceptable, but frames must stabilize and the UI must still release the device on exit.

## Lock, Unlock, And Issue #26

Run each case at least six consecutive times:

| Case | Expected result |
|---|---|
| Face present after `Win+L` | Recognition starts after input and desktop opens |
| Face absent, manual PIN | Windows PIN works; camera off within 5 seconds |
| Wrong/no face for 45 seconds | Prewarm releases and LED turns off |
| Sleep then resume, face | No frozen LogonUI; face unlock works |
| Sleep then resume, manual PIN | No frozen LogonUI; PIN works; camera releases |
| Rapid lock/unlock | No stale credentials, duplicate autologon, or same-session camera reopen |

Issue #26 is ready to close only after sleep/resume and manual PIN release pass repeatedly on an installed build. Unit tests alone are insufficient.

## Automatic Lock And Issue #27

“About 30 seconds to take effect” means the UI saves immediately but Unlock reloads the options database every 30 seconds. It does not mean the workstation always locks after 30 seconds.

1. Enable automatic lock and set timeout to 30 seconds.
2. Wait 35 seconds for the service configuration poll.
3. Move the mouse once to reset idle time.
4. Leave the camera view and do not touch mouse/keyboard for 30-40 seconds.
5. Expected: camera checks briefly, then the active local or RDP session locks.
6. Unlock and remain in view; repeat idle wait.
7. Expected: an authorized face prevents locking and the next check follows `max(60 seconds, configured timeout)`.
8. Test once on the physical console and, when available, once in an active RDP session.

Useful success log lines include a lock request sent to an interactive session and workstation lock confirmation. API errors, helper nonzero exit, or missing WTS confirmation are failures. Issue #27 is ready to close only after real SYSTEM scheduled-task testing passes.

## Browser Password Matrix

Test Chrome and Edge first, then at least one of Brave, Opera/Opera GX, Vivaldi, Chromium, or 360.

| Scenario | Expected generic Provider behavior |
|---|---|
| Reveal/show saved password | Face starts and succeeds |
| Website saved-password fill | Face starts and succeeds |
| Explicit password manager verification | Face starts and succeeds |
| Google Passkey or webauthn.io | Generic Provider skips; Windows/plugin flow remains usable |
| Hardware security key | Generic Provider skips |
| Set/change Windows PIN | Generic Provider skips |
| Incognito/InPrivate unknown prompt | Falls back to Windows PIN |
| Unsupported browser unknown prompt | Falls back to Windows PIN |

Check `facewinunlock.log` for the owner process, scene, `webauthn_ready`, and `webauthn_active`. Logs must not contain credential serialization hex, passwords, PINs, RP IDs, or usernames from WebAuthn requests.

### Registry Kill Switch

In an administrator terminal:

```powershell
reg add HKLM\SOFTWARE\facewinunlock-tauri /v CREDUI_BROWSER_PASSWORD_FILL /t REG_SZ /d 0 /f
```

Unknown browser fill must now return to Windows PIN. Restore the release default after the test:

```powershell
reg add HKLM\SOFTWARE\facewinunlock-tauri /v CREDUI_BROWSER_PASSWORD_FILL /t REG_SZ /d 1 /f
```

### Monitor Failure

Only run this case if you are comfortable changing an Event Log channel. Record its current state first, disable it, restart the FaceWinUnlock service, and verify unknown browser fill falls back to PIN. Re-enable the channel immediately afterward:

```powershell
wevtutil gl Microsoft-Windows-WebAuthN/Operational
wevtutil sl Microsoft-Windows-WebAuthN/Operational /e:false
wevtutil sl Microsoft-Windows-WebAuthN/Operational /e:true
```

The guard itself has no disable switch. Monitor unavailability must never be interpreted as permission to run face recognition for an unknown request.

## Passkey Plugin

On Windows 11 24H2+:

1. Install and enable the plugin; complete the one-time Windows verification manually.
2. Save a new passkey on Google or webauthn.io and select FaceWinUnlock as the location.
3. Sign in with that passkey. Expected: the plugin requests face authorization and signs with its own key.
4. Test no face/remote use. Expected: `REJECTED` or `TIMEOUT`, with no silent approval.
5. Change the plugin PIN, delete it, and rebuild it using the plugin's normal UI.
6. Uninstall with Keep Credentials, reinstall, and verify the saved passkey still works.
7. Uninstall with Geek, confirm the ProgramData backup remains, reinstall, and verify restoration.
8. Purge only on a disposable credential; verify metadata, backup, and `facewinunlock/*` KSP keys are removed.

After uninstall, FaceWinUnlock must disappear from “where to save a passkey.” After reinstall, it must reappear only when the package is installed and enabled.

## UAC And Compatibility

- Trigger an administrator action from a standard/elevated boundary; face works and cancellation returns cleanly.
- Confirm RDP generic credential prompts stay with Windows unless explicitly enabled.
- On Windows 10, core face unlock works and Passkey installation is skipped with a clear unsupported message.
- On GPU/OpenCL, perform enrollment consistency and six lock/unlock cycles; switch to CPU if tuning, accuracy, or latency regresses.

## Release Decision

Promote the candidate only when:

- All Rust tests/checks and the Vue production build pass.
- Fast acceptance passes.
- Issue #26 and #27 installed loops pass at least six times each.
- Browser password and WebAuthn negative cases pass.
- Passkey keep/reinstall behavior passes on Windows 11 24H2+.
- Camera release is timely after manual PIN, cancellation, sleep/resume, and enrollment exit.
- Logs contain no secrets and no unexplained monitor, helper, pipe, or worker failures.
