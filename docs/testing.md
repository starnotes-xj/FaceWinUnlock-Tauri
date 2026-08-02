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

## Enrollment Passive Liveness And Issue #30

Use the default real-confidence threshold `0.50` on CPU first. Repeat the live
and attack sets on Windows 10 22H2 as reported in issue #30, then on a current
Windows 11 machine. Record the physical camera or virtual-camera source, light,
display/printer used for attacks, and every score.

| Case | Minimum repetitions | Expected result |
|---|---:|---|
| Live face, normal indoor light | 10 | Consistency check completes without any action prompt |
| Live face, deliberately still | 10 | Stillness alone is never classified as a photo |
| Live face, weak or side light | 10 | No crash/model-contract error; record false rejects |
| Face near each frame edge | 5 per edge | Reflection-padded crop remains valid |
| Printed enrolled-face photo | 10 | Rejected by passive liveness |
| Enrolled-face image on phone/monitor | 10 per display | Rejected; include moved and stationary display |
| Prerecorded face video | 10 | Record accepts as a security failure |
| Camera drops one or two detections | 10 | Check recovers when at least three valid samples remain |
| Missing/corrupt liveness model | 1 | Clear unavailable/error result; never silently pass |

The interaction must not ask for blinking, head movement, mouth movement, or a
multi-second rPPG wait. A virtual-camera pass is a compatibility result, not
proof of spoof resistance: virtual-camera injection and high-quality replay
remain outside the assurance of an ordinary RGB model.

Issue #30 is ready to close only when the live set no longer fails from the
former `80x80` input mismatch, the packaged model hash matches the documented
contract, and print/display attacks have been run on real hardware. Unit tests
cover preprocessing and output semantics but do not replace the attack matrix.

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

## Login Passive-Liveness Attack Matrix

This matrix is separate from enrollment testing. Use the same enrolled identity
and run every case through the actual credential path, not the UI preview.

| Path | Live subject | Printed/photo replay | Expected log evidence |
|---|---|---|---|
| `Win+L` face unlock | Unlocks after the short PAD window | No credential is released | `face and passive liveness matched` only for live subject |
| Chrome saved-password reveal | Password fills after PAD passes | Windows verification remains open or fails closed | No `face matched` without the passive-liveness suffix |
| Chrome website password fill | Fill succeeds after PAD passes | No password is submitted | `passive liveness rejected face authorization` or timeout |
| FaceWinUnlock Passkey | Plugin receives one `AUTHORIZED` decision | Plugin receives `REJECTED`/`TIMEOUT` | `face and passive liveness matched for passkey authorization` only for live subject |

For each path repeat a printed photo, a phone/monitor image, and a prerecorded
video at least ten times. Move the mouse only when the scenario normally needs
user input; movement must not bypass the PAD window. Temporarily remove or
corrupt either login model once and verify the service fails closed without
releasing a password or Passkey decision.

## Browser Password Matrix

Test Chrome and Edge first, then at least one of Brave, Opera/Opera GX, Vivaldi, Chromium, or 360.
Before testing website autofill, confirm the browser's built-in Windows authentication
setting (Chrome: **Use Windows Hello when filling passwords**) is enabled. The setting is
profile scoped. If autofill succeeds without any `CPUS_CREDUI`/`credentialuibroker.exe` entry in
`facewinunlock.log`, the browser filled the page directly and the Credential Provider was
never invoked; this is not a provider classification failure.

| Scenario | Expected generic Provider behavior |
|---|---|
| Reveal/show saved password | Face starts and succeeds |
| Website saved-password fill with explicit password/PIN prompt | Face starts automatically and succeeds; no extra click is required |
| Repeat the same website password fill twice | Both attempts start face recognition and fill successfully; both scenes may prewarm after `prepare`, but each `run` still requires mouse/keyboard input; the second may arrive with legacy `0x200` flags and no serialization |
| Generic browser login/security-key confirmation | No camera prewarm or face before user choice; cancelling closes/releases the camera; after explicit input, the normal guard runs and WebAuthn/native flow remains in control |
| Explicit password manager verification | Face starts and succeeds |
| Google account login / Passkey / security-key confirmation without serialized password credentials | Generic Provider skips; no generic camera request before confirmation; after confirmation, Windows/plugin flow performs exactly one Passkey face authorization |
| webauthn.io Passkey | Generic Provider skips; Windows/plugin flow remains usable |
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
