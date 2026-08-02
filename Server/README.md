# Server: Windows Credential Provider

`Server/` builds the `FaceWinUnlock_Tauri.dll` COM Credential Provider loaded by Windows logon hosts and selected CredUI hosts.

## Responsibilities

- Advertise credentials for configured logon, unlock, and CredUI scenarios.
- Classify broker-hosted requests without UI Automation or control inspection.
- Refuse generic activation while WebAuthn is active or the scene is unsafe/unknown.
- Send `prepare`/`run` commands to the Unlock service and receive matched credentials.
- Pack credentials with `CredPackAuthenticationBufferW` and notify Windows through `CredentialsChanged`.
- Release pipe I/O and camera sessions without blocking LogonUI or CredentialUIBroker UI threads.

## Source Map

| File | Role |
|---|---|
| `src/lib.rs` | DLL exports, registry/logging, broker context and classification |
| `src/CSampleProvider.rs` | `ICredentialProvider`, scenario policy, enumeration |
| `src/CSampleCredential.rs` | Tile fields, serialization, result handling |
| `src/CPipeListener.rs` | Client/credential listener threads, fallback and teardown |
| `src/Pipe.rs` | Named-pipe primitives and credential parsing |

## IPC

| Pipe | Direction | Messages |
|---|---|---|
| `MansonWindowsUnlockRustServer` | DLL to Unlock | `prepare`, `run`; ambiguous browser/security-key scenes connect only after explicit input |
| `MansonWindowsUnlockRustUnlock` | Unlock to DLL; UI control | credentials, `release`, `broker_release`, `ui_release`, `ui_done`, health/exit control |

Credentials use null-delimited UTF-8 (`username\0password\0domain\0`) or the compatibility JSON format. Never log payload bytes.

## Broker Policy

The Credential Provider cannot read Chromium's `CredUIPromptForWindowsCredentials` message text through the provider API. Classification therefore combines owner/root-owner process context, explicit safe/unsafe title signals, private-window state, registry policy, and the named WebAuthn Ready/Active events.

Active WebAuthn always wins and returns control to Windows. For a browser login/authentication
title, the Advise-time serialization metadata and CredUI mode are checked: a request without
serialized password credentials is handed to native Windows/Passkey only when the V2 CredUI
flag is present. Legacy 0x200 password-fill requests remain eligible for the generic Provider.
This avoids treating the Lanzou password-fill PIN dialog as Passkey merely because its page title
contains “登录”.
Unknown password-fill fallback is allowed only for the maintained
Chromium-family process list when the monitor is healthy and `CREDUI_BROWSER_PASSWORD_FILL=1`.

Password-fill CredUI scenes connect early and issue `prepare` to warm the camera, but the first
guarded `run` still requires mouse/keyboard input. This preserves the 0.5.10/Win+L response time
without allowing an opened dialog to authorize by itself. A login-title prompt without serialized
credentials and with V2 mode never enters that generic Provider path; after the user confirms the
operation, the native browser/Passkey flow owns the single face authorization. Legacy-mode (`0x200`)
password-fill prompts remain input-gated but accept mouse movement for repeated fills. An ambiguous
browser prompt must never connect to Unlock, prewarm the
camera, or start face recognition merely because the prompt opened. Once the user clicks or
presses a key, the normal
`prepare`/WebAuthn guard/`run` sequence resumes.
If the broker dialog is then cancelled or closed, teardown sends a background `release` so an
in-flight camera open cannot leave the indicator on after the dialog disappears.
Direct page autofill that never opens CredUI remains outside the provider boundary; the
browser's own Windows Hello password-fill setting must be enabled for that path.

Do not add UI Automation, keyboard injection, or Credential Provider graphics/animation dependencies.

## Build And Test

```powershell
cargo test -p winlogon
cargo build --release -p winlogon
```

Output: `target\release\FaceWinUnlock_Tauri.dll`.

Use `pipe_sniffer.ps1` only on an isolated test machine. Installed regression steps are in [../docs/testing.md](../docs/testing.md).
