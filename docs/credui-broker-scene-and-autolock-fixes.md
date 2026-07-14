# CredUI Broker And Automatic Lock Invariants

## Why CredUI Needs A Guard

Chromium password reauthentication and WebAuthn operations can both be hosted by `credentialuibroker.exe` with the same Credential Provider usage scenario and flags. `ICredentialProvider::SetUsageScenario` does not expose the caller's prompt text, so `CPUS_CREDUI` and `dwFlags` alone cannot safely distinguish password fill from passkey.

UI Automation was tested and rejected: protected broker contexts do not provide a dependable UIA surface, and UIA adds a fragile cross-integrity dependency. The project permanently prohibits UIA, protected-control inspection, and PIN keystroke injection.

## Current Broker Context

`Server/src/lib.rs` builds a context from:

- foreground, owner, and root-owner window titles
- owner/root-owner process names
- CredUI flags
- WebAuthn monitor Ready and Active state
- private-window markers

The maintained browser process allowlist is:

```text
chrome.exe
msedge.exe
brave.exe
vivaldi.exe
opera.exe
opera_gx.exe
chromium.exe
360se.exe
360chrome.exe
```

## Decision Priority

1. WebAuthn Active: classify as passkey and skip.
2. Explicit passkey/security key/WebAuthn/FIDO2/PIN setup: skip.
3. System Settings, biometric enrollment, Incognito, or InPrivate: disable unknown fallback.
4. Explicit password manager/reveal/show/fill-password signal: allow face.
5. Unknown allowlisted browser: allow only when monitor Ready, not Active, non-private, and `CREDUI_BROWSER_PASSWORD_FILL=1`.
6. Otherwise return `E_NOTIMPL`.

Passkey words override password words. Active is checked again after initial classification and before every meaningful pipe/submission step. If a transaction starts mid-recognition, the DLL requests `broker_release`, stops the generic camera path, hides its tile, and re-enumerates Windows credentials.

## WebAuthn Monitor

`Unlock/src/webauthn_activity.rs` uses the Windows Event Log pull subscription model for `Microsoft-Windows-WebAuthN/Operational`.

- Startup validates the channel, provider metadata, and event IDs 1000-1008.
- A ten-minute replay restores an unfinished transaction after service restart.
- Transaction IDs track concurrent starts/completions; duplicates are idempotent.
- Missing completion expires after ten minutes.
- Subscription errors clear both Ready and Active before retry/backoff.
- Logs contain only event ID, active-count transition, and errors.

State is exposed through synchronize-only named events:

```text
Global\FaceWinUnlockTauriWebAuthnReady
Global\FaceWinUnlockTauriWebAuthnActive
```

The guard cannot be disabled. When it is unhealthy, unknown broker requests fail closed to Windows PIN.

## Automatic Lock

The UI writes `autoLockEnabled` and `autoLockTimeout` immediately. The Unlock worker reloads them every 30 seconds. The status message “about 30 seconds to take effect” describes this polling delay, not the idle timeout.

After the configured idle interval:

1. Skip if the workstation is already locked or the UI owns the camera.
2. Open the configured camera and check for an authorized face.
3. Authorized face: do not lock; cool down for `max(60 seconds, autoLockTimeout)`.
4. No/unknown face: select the active WTS session.
5. Query its user token and launch the same signed executable with `--lock-workstation-once` on `winsta0\default`.
6. Confirm the WTS session reports locked; retry bounded failures, then back off.

This indirection is required because a SYSTEM service in Session 0 cannot use `LockWorkStation` to lock the user's interactive desktop.

## Regression Rules

- Do not weaken WebAuthn Active from a veto into a hint.
- Do not add “no event means password.” Ready plus allowlisted owner plus policy is required.
- Do not narrow browser support without a demonstrated incompatibility and tests.
- Do not log titles together with secret request content.
- Do not lock a disconnected console when an RDP session is active.
- API/open-desktop errors are unknown/failure, never proof that the workstation locked.
- Unit tests must cover classification priority, private mode, monitor failure, kill switch, concurrent transactions, replay, expiry, active RDP selection, and lock-flag mapping.
- Installed validation follows [testing.md](testing.md), including six consecutive #26/#27 loops.
