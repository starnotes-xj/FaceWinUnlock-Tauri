# CredUI Probe Fixtures

This is a native x64 MSVC **fixture harness**, not a browser hook or product component. Its command line accepts only four self-tests and rejects arbitrary executables. It never attaches to an existing PID or opens a real credential dialog.

Build and run the fixtures from the repository root:

```powershell
.\scripts\build-credui-probe.ps1 -Test
```

The fixture host loads the System32 `credui.dll` to verify that the operating-system module and exports can be discovered, but it does not call those exports. It calls synthetic functions in `CredUIProbeFixture.dll` that use the same x64 parameter layout. The tests cover W/A entry points, one nested call, unreadable and over-limit display-text pointers, worker threads, debug-register restoration, module unload, and second-chance crash cleanup.

The probe reads only the fixture's `CREDUI_INFO` parent HWND and bounded message-text metadata. It never serializes the message text, caption, authentication package, credential input/output buffers, passwords, PINs, usernames, or WebAuthn data. The purpose field remains `unknown`.

Passing these tests does not prove that Chrome, Edge, or another browser calls this API, that Windows maps API flags to Provider flags in a particular way, or that an HWND identifies the same CredUI request. No live-browser mode is exposed until a separately reviewed test launcher can validate the signed browser image, use an isolated profile, and clean up without touching an existing browser session.
