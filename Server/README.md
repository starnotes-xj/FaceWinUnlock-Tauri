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
| `MansonWindowsUnlockRustServer` | DLL to Unlock | `prepare`, `run` |
| `MansonWindowsUnlockRustUnlock` | Unlock to DLL; UI control | credentials, `release`, `broker_release`, `ui_release`, `ui_done`, health/exit control |

Credentials use null-delimited UTF-8 (`username\0password\0domain\0`) or the compatibility JSON format. Never log payload bytes.

## Broker Policy

The Credential Provider cannot read Chromium's `CredUIPromptForWindowsCredentials` message text through the provider API. Classification therefore combines owner/root-owner process context, explicit safe/unsafe title signals, private-window state, registry policy, and the named WebAuthn Ready/Active events.

Active WebAuthn always wins and returns control to Windows. Unknown password-fill fallback is allowed only for the maintained Chromium-family process list when the monitor is healthy and `CREDUI_BROWSER_PASSWORD_FILL=1`.

Do not add UI Automation, keyboard injection, or Credential Provider graphics/animation dependencies.

## Build And Test

```powershell
cargo test -p winlogon
cargo build --release -p winlogon
```

Output: `target\release\FaceWinUnlock_Tauri.dll`.

Use `pipe_sniffer.ps1` only on an isolated test machine. Installed regression steps are in [../docs/testing.md](../docs/testing.md).
