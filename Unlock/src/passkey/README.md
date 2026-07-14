# Unlock Passkey Face Gate

This directory contains only the active local user-verification gate in `mod.rs`.

The Windows Passkey Provider owns each WebAuthn credential and its non-exportable P-256 key. Before signing, it connects to:

```text
\\.\pipe\FaceWinUnlockPasskeyFaceAuth
```

Unlock serializes authorization requests, starts one face-recognition attempt, and returns exactly one of:

- `AUTHORIZED`
- `REJECTED`
- `TIMEOUT`

Authorization is bound to the current request ID and cannot be reused after completion or timeout.

The removed browser-extension/local-signer experiment is not part of this module. Do not recreate HTTP signing, captured-key stores, UI Automation, or native PIN injection here.
