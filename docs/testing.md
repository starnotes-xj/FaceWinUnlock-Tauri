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
2. On a clean setup, finish the initialization lock-screen test. After automatic unlock, the dashboard must be visible immediately without clicking the app window.
3. `Win+L`, move the mouse, and unlock by face.
4. `Win+L`, keep the face away, enter Windows PIN manually, and confirm the camera LED turns off within 5 seconds.
5. Reveal a saved browser password; face verification succeeds.
6. Fill a website password such as QQ Mail; face verification succeeds.
7. Perform a Google or webauthn.io passkey action and choose Windows Hello or a security key; the generic Credential Provider must not start its camera.
8. Separately choose a passkey saved with FaceWinUnlock; the plugin's dedicated face authorization starts the camera and succeeds.
9. Enable automatic lock with a 30-second timeout and confirm it locks through the interactive-session helper.
10. Sleep/resume and repeat face unlock plus manual PIN unlock.

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

### Sleep And Hibernate Reproduction

First check which power states the machine supports:

```powershell
powercfg /a
```

Run these cases on an installed build, six consecutive times each:

1. From the desktop, choose **Sleep**, wait at least 20 seconds, wake the computer, and unlock by face.
2. Press `Win+L`, move the mouse so face scanning and the camera LED are active, keep your face out of view, then use the lock-screen power menu to choose **Sleep**. Wake the computer and unlock with Windows PIN.
3. Repeat case 2 but unlock by face after resume.
4. Hibernate from the desktop, wake the computer, then repeat both face and manual PIN unlock.

The Hibernate item can be absent when hibernation is disabled. In an administrator terminal, enable the full hibernation file and test directly even if the menu item remains hidden:

```powershell
powercfg /hibernate on
powercfg /h /type full
shutdown /h
```

Save open work before `shutdown /h`. If `powercfg /a` reports that S4 hibernation is unavailable, record that result and run the hibernate cases on another supported machine instead of treating Sleep as equivalent.

After every wake, confirm that the account tile, PIN/password field, and lower-left account controls are present; the spinner does not remain indefinitely; the desktop opens normally; and the camera LED turns off within 5 seconds after manual PIN unlock. Record the exact failure time and preserve `unlock.log`, `facewinunlock.log`, and `app.log` before reinstalling or clearing logs.

On Modern Standby (`powercfg /a` reports S0 Low Power Idle), the camera LED must turn off as soon as the console display becomes inactive and remain off for the entire sleep interval. The Unlock log must contain `console display inactive; camera closed and recognition paused`; a traditional S3/S4 transition can additionally log `power suspend detected`. After wake it must contain `camera power gate cleared; stale camera state discarded`. A camera prewarm/open line after the inactive-display line and before the gate-cleared line is a failure.

Also test ordinary display timeout separately from **Sleep**. While the display is off, continuous vivo/Sunlogin/ToDesk input must still prevent automatic locking. With no local or remote input, automatic lock may lock the session but must log `locking without camera` and must not turn on the camera LED.

Issue #26 is ready to close only after the active-camera Sleep case, hibernate/resume, face unlock, and manual PIN release all pass repeatedly on an installed build. Unit tests alone are insufficient.

## Passive Liveness And Photo/Replay Attacks

Run this matrix on the installed package with CPU inference first. Use the enrolled user's face and keep distance, angle, brightness, and apparent face size comparable across genuine and attack cases.

| Presentation | Expected result |
|---|---|
| Genuine user, normal expression | Unlocks without a requested blink, head turn, or spoken action |
| Matte printed portrait | Does not release credentials; native PIN/password remains usable |
| Glossy printed portrait | Does not release credentials |
| Portrait displayed on a phone | Does not release credentials |
| Recorded face video on a phone/tablet | Does not release credentials |
| Genuine user after sleep/resume | Unlocks after camera exposure stabilizes |
| Face changes between two enrolled users during the decision window | Old samples are discarded; no mixed-identity authorization |

Repeat each case at least ten times in normal indoor light and once in dim light and monitor backlight. A single credential release or Passkey `AUTHORIZED` result for a printed photo or screen replay is a release blocker.

Also verify fail-closed behavior:

1. Rename `resources\anti_spoof_mn3.onnx`, restart the service, and try face unlock.
2. Restore it, rename `resources\face_liveness.onnx`, restart, and repeat.
3. Restore both models before continuing.
4. Expected in both missing-model cases: no credential or Passkey authorization, no worker crash loop, and native PIN/password remains available.
5. Confirm a genuine decision normally takes at least 350 ms of samples and remains within the product's acceptable unlock latency on CPU.
6. Confirm logs contain only generic PAD pass/fail/error events, not frames, raw biometric scores, credentials, or WebAuthn request content.

RGB passive PAD reduces common 2D attacks but is not an IR/depth proof. Record the tested camera and display/print media with release evidence.

### Enrollment consistency and inference backends

1. Enable liveness for enrollment consistency, capture a genuine face, and enter verification.
2. Expected: the UI reports passive sampling for the first four frames, then passes without requesting a blink, turn, or spoken action.
3. Monitor Task Manager while repeating verification on a low-end CPU. Each UI command must consume one camera frame and one liveness inference, not synchronously capture four extra frames. Pause camera verification for more than three seconds; expected: sampling restarts at `1/5` instead of reusing stale live frames.
4. Start the management UI without opening the face-enrollment page. Expected: it does not parse or initialize any OpenCV model.
5. Select Intel NPU on a supported Core Ultra system with the packaged OpenVINO runtime. Confirm the log reports `(backend=2, target=9)` and does not contain an ONNX importer error.
6. Temporarily rename one NPU `.xml` or `.bin` asset and reload the backend. Expected: UI and Unlock report a CPU fallback; enrollment and native Windows PIN/password remain usable.

### Differential model update

1. On a disposable installed copy, rename one file under `resources` (test one `.onnx` and one OpenVINO `.xml`/`.bin` pair).
2. Check for updates against a release that publishes the current `update_manifest.json`.
3. Expected: the missing or changed resource paths appear in the differential download, retain their `resources/<filename>` paths, and pass size and SHA-256 validation.
4. Download, close the UI, and restart it. Expected: the resources are restored beside the other model files, including when a locked target first had to be staged as `.new`.
5. Re-run CPU enrollment verification and, on supported hardware, Intel NPU verification. Expected: both backends load the restored assets and the Unlock service remains healthy.

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
9. Connect with a console-sharing remote-control tool such as vivo Office Suite, Sunlogin, or ToDesk. Keep moving/clicking/typing for longer than the configured timeout.
10. Expected: remote input keeps the active Windows session non-idle, so the camera does not open and automatic lock does not run. Stop all remote input and move out of camera view; automatic lock should work again after the timeout.

Useful success log lines include a lock request sent to an interactive session and workstation lock confirmation. `cannot read active-session idle time` must skip locking rather than treat the session as idle. API errors, helper nonzero exit, or missing WTS confirmation are failures. Issue #27 is ready to close only after real SYSTEM scheduled-task testing passes.

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
