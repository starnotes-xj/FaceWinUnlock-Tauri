# FaceWinUnlock-Tauri

**FaceWinUnlock-Tauri** is a modern Windows facial recognition unlock tool built on the Tauri framework. It injects a custom Credential Provider (DLL) into the Windows login interface, combining a Vue 3 frontend with OpenCV face recognition to deliver a Windows Hello-like unlock experience using any standard webcam.

## Downloads
[Lanzou Cloud - Password: 5969 (Recommended: no speed limit, no login required)](https://wwbqv.lanzoul.com/b019vlktwf)

[Baidu Cloud - Code: 2ugj](https://pan.baidu.com/s/1UxEflXFxJN6wQBjBbwK9vw)

[Tianyi Cloud - Code: u9gv](https://cloud.189.cn/t/FNvee2mQfumm)

[Community mirror by Douyin @czm529797](https://download.mingqwq.top/)

## About This Fork

This repository is a fork of the original project. After the original author removed the core source code (v0.3.5), the **entire DLL source code under `Server/`** was reconstructed through reverse engineering, making it compilable again. Several bugs were also fixed and new features added.

**Key changes from the upstream:**
- ✅ Full `Server/src/` restoration — DLL compiles with `cd Server && cargo build --release`
- ✅ Fixed Issue #102: continued login attempts after incorrect password (clears credential flags on `ReportResult` failure)
- ✅ Fixed Issue #118: browser PIN dialog freeze (`SetUsageScenario` returns `E_NOTIMPL` for unlisted scenarios)
- ✅ Added Issue #122: mirrored camera preview during face enrollment (CSS `scaleX(-1)`, does not affect recognition)
- ✅ Added Issue #125: inference backend selection (CPU / OpenCL GPU / OpenCL FP16 / Intel NPU), configurable in Preferences → Recognition Parameters
- ✅ Face unlock scenarios now default to UAC/application layer support (`UNLOCK_SCENE` defaults to `"1,2,4"`), configurable in Preferences → System Integration
- ✅ Fixed multi-process log loss: Chrome CredUI loads the DLL in a separate `credentialuibroker.exe` process — logs now use append+shared write mode, startup entries include PID
- ✅ Adjusted Google/passkey (WebAuthn) fallback: CredUI hosted by `credentialuibroker.exe` tries face unlock first, then hands control back to Windows PIN if passkey rejects the credential or recognition times out; Chrome/Edge password reveal keeps face unlock
- ✅ Added camera rotation option: 0° / clockwise 90° / 180° / counter-clockwise 90°, for laptops used sideways or other non-standard orientations, configurable in Preferences → Recognition Parameters, real-time in preview and unlock ([#96](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/96))
- ✅ Added unlock brightness boost: automatically raises screen brightness during face recognition and restores it when done — improves unlock success rate in low-light environments ([#99](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/99))

**Original upstream notice:** The original author closed the source in March 2026 after discovering the software was being resold. Core Rust code was removed, leaving only the v0.3.2 framework. This fork reconstructs the missing code for educational and research purposes.

If you're interested in a particular feature, feel free to open an issue.

**Current build status:** All build configuration files (root workspace Cargo.toml + Server + UI + Unlock) have been restored. `cargo build --release` from the repository root compiles all three components. Some Rust source modules (`init.rs`, `faces.rs`, Unlock main logic) required reconstruction as their original implementations were deleted. The Vue 3 frontend is fully intact. See the Building from Source section below for details.

## 📖 Background

This project was born from a moment of "tech envy":

One day, a new colleague joined the team. His laptop, equipped with an infrared camera, let him unlock Windows just by looking at the screen. Meanwhile, my own powerful machine — lacking Windows Hello-capable hardware — still required typing a long, complex password every single time.

**"Why can he unlock with his face and I can't?"**

With a "hardware deficiency, code will fill the gap" mentality, I decided to build my own solution. If the OS doesn't support face unlock for regular webcams, I'll write a component that injects into the Windows login interface myself. That's how FaceWinUnlock-Tauri came to be — so that every Windows device with a camera can enjoy this little bit of convenience.

## 📝 Changelog

| Version | Date | Changes | Notes |
|---------|------|---------|-------|
| v0.3.5-fork | 2026-05-25 | Fork code restoration, bug fixes, feature additions | **This fork adds:** Restored Server DLL source (compilable), fixed password-error login bug (#102), fixed browser PIN freeze with UAC/app-layer defaults (#118), mirrored camera preview (#122), inference backend selection (#125), configurable face recognition scenarios, fixed multi-process log loss (Chrome CredUI), added auto-lock idle monitor with face verification (#132), **added camera rotation option (0°/CW 90°/180°/CCW 90°)** for sideways/non-standard camera orientations (#96), **added unlock brightness boost** — auto-raises screen brightness during face recognition and restores on completion to improve low-light unlock success rate (#99). |
| v0.4.0 | 2026-05-29 | Features, bug fixes, CI/CD | **Windows Hello-style animation UI** (DComp + Direct2D, 60 FPS, 4 states, adaptive refresh rate)<br />**Chrome CredUI double-trigger fix** (unified input hook triggers)<br />**Boot-time face unlock reliability** (BootTrigger delay + LogonTrigger fallback)<br />**No-face auto retry** (Unlock EXE retries up to 3 rounds internally)<br />**Inference backend selection** (CPU / OpenCL GPU / OpenCL FP16 / Intel NPU)<br />**Camera rotation** (0°/90°/180°/270°) (#96)<br />**Unlock brightness boost** (#99)<br />**Dark mode** (#92)<br />**Domain account login** (#104)<br />**Unlock tile refinement** (#91)<br />Fixed face-disabled phantom login (#103)<br />Fixed NVIDIA Broadcast virtual camera artifacts (#94)<br />Fixed init wizard environment check freeze<br />Fixed dashboard tab white screen<br />Fixed animation pipeline race conditions<br />**GitHub Actions CI/CD auto-build release workflow** |
| v0.4.1 | 2026-05-29 | CI/release fixes | Corrected NSIS/MSI release artifact upload paths (artifacts live at workspace-root target)<br />Committed ONNX models & animation_frames.bin to the repo for CI builds<br />Normalized LLVM to `D:\LLVM` and verified libclang<br />Fixed trailing null bytes in tauri.conf.json |
| v0.4.2 | 2026-05-30 | Bug fixes | Fixed boot-time face service failing to self-recover after a cold start / silent crash |
| v0.4.3 | 2026-05-30 | Performance, bug fixes | Model loading now retries persistently instead of giving up early<br />Greatly shortened boot-time face recognition recovery time |
| v0.4.4 | 2026-06-05 | Critical bug fix, stability hardening | **Fixed the ~30s delay before face recognition triggers on boot / lock screen**: root cause was the Unlock service panicking (exit 101) from `Instant::now() - Duration` arithmetic underflow during the first 60s after boot, crash-looping under the supervisor. Switched to `checked_sub` safe fallback — the worker now starts on the first try and recognition completes in 1-2s<br />supervisor restart now uses exponential backoff to prevent crash storms from flooding logs / burning CPU<br />panic-safety hardening: SystemTime clock-anomaly unwrap, concurrent handle double-close<br />Added worker panic logging (location + reason to unlock.log) for faster crash diagnosis<br />Intel NPU inference backend now auto-falls back to CPU when the OpenVINO runtime is absent, no longer erroring on selection |
| v0.4.5 | 2026-06-06 | Critical bug fix | **Kept browser password-reveal face unlock and added Google/passkey (WebAuthn) PIN fallback**: browser password reveal and passkey verification expose identical `CPUS_CREDUI`, `dwflags`, auth package, CLSID, and `rgbSerialization` at the Credential Provider layer, so they cannot be reliably distinguished. CredUI hosted by `credentialuibroker.exe` now tries face unlock first; if credentials are not received within 5 seconds or `ReportResult` reports rejection, the provider hides itself and lets Windows native PIN continue. |
| v0.5.0 | 2026-06-21 | Official Passkey Provider route + stability fixes | **Added the FaceWinUnlock Passkey Provider plugin**: the plugin owns non-exportable WebAuthn keys, so sites can store credentials created by this provider and authenticate with them<br />FaceWinUnlock authorizes plugin signing through a named-pipe face UV gate; it does not extract Windows Hello private keys, store PINs, or depend on a browser extension<br />Silent face authorization is supported: successful face recognition proceeds without an extra confirmation popup, while remote/no-face sessions reject as expected<br />The installer bundles the MSIX and certificate; NSIS only trusts the certificate at machine level, and the current desktop user installs/updates/opens the MSIX manager from the app<br />Disabled the old key-capture/browser-takeover experiment to avoid shipping an unverifiable fake-signature path<br />**Chrome password reveal now forces face recognition**: the broker distinguishes password-reveal / passkey / set-PIN by the triggering app's window title, so choosing native Windows Hello for a passkey no longer wrongly triggers face recognition<br />**Fixed auto-lock camera flicker**: authorization cooldown changed from a fixed 60s to max(60s, detection interval), cutting presence re-checks 5x while the user is present, plus added auto-lock camera logging<br />**Fixed opencv_world4120.dll / FaceWinUnlock-Server.exe missing from the installer** (runtime "opencv_world4120.dll not found", background service failing to auto-start): Tauri v2 + NSIS drops single files mapped to the install root when a directory-expansion mapping is present; moved them to the resources/ subfolder + copied to root via NSIS hooks<br />**Intel NPU inference enabled**: ships the OpenVINO runtime + a WITH_OPENVINO build of opencv_world; selectable as the intel_npu backend after installing the NPU driver<br />**Removed prebuilt OpenCV from git history** (.git 493MB→81MB)|
| v0.5.1 | 2026-06-21 | Performance and interaction improvements, compatibility fix | **Significantly reduced UI GPU usage**: animations pause when the window is unfocused or hidden, continuous background drift was removed, decorative particles were reduced, and backdrop blur is less expensive<br />**Improved UI responsiveness**: 3D parallax updates are frame-throttled, while route transitions and dashboard card animations complete faster<br />**Fixed core-component deployment on Windows installations outside C:** the actual System32 directory is now resolved dynamically for initialization, registration, and uninstall |
| v0.5.2 | 2026-06-21 | Critical compatibility fix (older Win10) | **Fixed older Windows 10: no face tile on lock screen / no auto-unlock / no DLL log** ([issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)): the animation UI made the Credential Provider DLL statically import `dcomp.dll!DCompositionWaitForCompositorClock` (only on Win10 1803+) and other graphics exports, so LogonUI failed to load the DLL on older Win10 and the provider never worked (no tile, no `facewinunlock.log`, unlock failed), while the original — without graphics deps — loaded fine. Graphics APIs are now loaded at runtime via `LoadLibrary`+`GetProcAddress`; `dumpbin` confirms the DLL no longer statically depends on d3d11/dcomp/dwrite/d2d1, so it loads on any Win8.1+/Win10/Win11, and the animation degrades gracefully (face unlock unaffected) when an export is missing<br />**Fixed init step 3 Passkey plugin error `0x80073CFD` on Win10**: the third-party passkey provider is a Windows 11 24H2-only feature; the wizard now detects the OS build and gracefully skips this step on older systems with a friendly notice instead of an install error (face unlock unaffected) |
| v0.5.3 | 2026-06-22 | GPU backend optimization + Passkey uninstall keeps credentials + fixes | **Passkey uninstall now keeps credentials by default** ([issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)): uninstall / full-update / reinstall no longer requires re-registration — the private key lives in the Microsoft Software KSP (key name `facewinunlock/<userId>`, per-user, never removed by MSIX uninstall), and credential metadata is now kept via `Remove-AppxPackage -PreserveApplicationData` plus an out-of-package backup/restore fallback; uninstall offers "keep credentials" / "purge" options, with core/NSIS uninstall defaulting to keep<br />**OpenCL kernel tuning cache optimization**: the Unlock service and UI set `OPENCV_OCL4DNN_CONFIG_PATH` to a persistent writable directory (ProgramData for SYSTEM, LOCALAPPDATA for the UI). Without it, OpenCV's ocl4dnn re-runs kernel compilation + auto-tuning on every `forward` (GPU/FP16 first inference up to ~90s) and **repeats it on every unlock/recognition**; now only the first run tunes and later runs load from cache instantly (fixes "slow" only; insufficient FP16 precision causing "can't match" still needs CPU)<br />**GPU (OpenCL / OpenCL FP16) backend experimental warning**: on some devices the GPU backend is extremely slow or can't match (lock screen spinning, consistency check black screen, high usage); switching now warns it is experimental and advises reverting to CPU on issues<br />**Fixed "already on the latest version but keeps prompting to update"**: the update check's `CARGO_PKG_VERSION` (`UI/src-tauri/Cargo.toml`) wasn't synced on release; bumped it and CI now syncs **both** `tauri.conf.json` and `Cargo.toml` from the tag<br />**Fixed noticeable lag when first opening Preferences → App Config**: multiple external processes (schtasks / named pipe / PowerShell `Get-AppxPackage`) were spawned synchronously during setup, competing with first paint; moved to `onMounted` and staggered, with the slowest Passkey status query further delayed<br />**Compiler warning cleanup**: Server 7→1 (naming-style `#![allow]` + dead-code removal, only the workspace profile note remains), Unlock 32→0 (module-level allow for the experimental NGC module), UI 3→0 (unused imports/fields) |
| v0.5.4 | 2026-06-22 | Important fix (Win10 lock screen won't auto-unlock) | **Fixed Win10 lock screen "face detected but never matches" / no auto-unlock** ([issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)): the same version unlocks on Win11 but not on Win10. Root cause — v0.5.3 changed the **unlock-side camera backend to DShow-first** for faster startup, while the **enrollment side** uses CAP_ANY (usually resolved to MSMF on Windows); DShow (DirectShow) and MSMF differ in color / exposure / resolution on some devices/systems, shifting the same face's 128-d SFace feature so cosine drops below the threshold (default 0.60) → face detected but never matches (login tile appears, spinner keeps spinning, camera on but no login). Win11 happened to have close-enough frames between the two backends and hid the issue; Win10 exposed it; the old version matching at the same machine's lock screen with CAP_ANY also confirms this. Fix: the unlock side reverts to **CAP_ANY-first**, same feature space as enrollment, consistent across Win10 / Win11<br />**MSIX manifest version now auto-synced from the tag (root-fixes "plugin UI changes can't be pushed via Update")**: the plugin manifest version was hardcoded and not synced by CI, so plugin UI/code changes (like this delete-menu simplification) couldn't reach already-installed users — the in-app "Update" button skipped them as the same version; CI now syncs the manifest version from the tag (x.y.z→x.y.z.0) so "Update" works without uninstall/reinstall.<br />**Fixed: clicking the update notification didn't open the download page** — it now uses the Tauri opener (openUrl); window.open is blocked inside the webview. |
| v0.5.5 | 2026-06-30 | Unlock animation removed, antivirus self-healing, stability hardening | **Removed the Windows Hello-style unlock animation completely** ([issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3), [#14](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/14), [#15](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/15), [#16](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/16), [#17](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/17)): the DComp/D2D/D3D11/DWrite rendering pipeline, frame resources, and registry switches were deleted. The Credential Provider DLL no longer depends on graphics libraries, avoiding old Win10 LogonUI load failures, lock-screen flicker, and sleep/resume spinner stalls at the root. The lock screen keeps a lightweight text status prompt instead.<br />**Fixed a Win10 camera-open delay where recognition was triggered but the camera opened about 40 seconds later**: offline analysis of #3 logs showed this was not model loading or a worker crash; v0.5.4's CAP_ANY-first path can block for a long time on some Win10 cameras. The unlock service now uses the same order as enrollment (`MSMF → DShow → Any`) and logs per-backend open times, avoiding both the old DShow-first feature mismatch and the CAP_ANY long block.<br />**Fixed Passkey Manager remaining after app uninstall** ([#17](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/17)): elevated uninstall now backs up each user's `credentials.dat`, then removes the MSIX package with `Remove-AppxPackage -AllUsers`, so the desktop user's Passkey Manager app is removed even when NSIS runs under an administrator context. KSP private keys are still kept, and metadata can be restored from backup after reinstall.<br />**Added runtime self-healing for antivirus false positives**: the installer compresses `opencv_world4120.dll` and `FaceWinUnlock-Server.exe` into `resources/runtime-backup.zip`, then registers the `FaceWinUnlockHealer` scheduled task to restore missing files on boot / logon / every 15 minutes and restart the core service. This mitigates Huorong / Defender deleting unsigned runtime files and causing "opencv_world4120.dll not found" or a missing background service.<br />**The installer tries to add a Windows Defender exclusion for the install directory**; with third-party antivirus products such as Huorong, manually add the install directory to the trusted / allow list. |

---

## 📢 Important Notices

> **Risk Warning:** This project involves low-level **registry modification** and **Winlogon process injection**. In extreme cases (e.g., DLL crash, path misconfiguration), it may prevent the Windows login screen from displaying normally, potentially **preventing you from reaching the desktop**.

> **Recommendation:** Before deployment, carefully read the on-screen notifications and take photos or notes for recovery reference (though the probability is extremely small).

> **Important:** Enter your **account password**, not your PIN. Many users unlock via PIN and then enter their PIN in the software, resulting in "username or password incorrect" errors. **This software does not support PINs — use your account password.**

> **If you see repeated password errors, uninstall the software immediately. Do not continue, or Microsoft may lock your account!**

> **Antivirus false-positive notice:** `opencv_world4120.dll` (OpenCV runtime) and `FaceWinUnlock-Server.exe` (background face service) are currently unsigned. Some antivirus products, including Huorong and Windows Defender, may misclassify and delete them, causing startup errors such as "`opencv_world4120.dll` not found" after a day or two. Starting with v0.5.5, the installer creates a compressed backup and a `FaceWinUnlockHealer` scheduled task, and it tries to add a Windows Defender exclusion. If you use Huorong or another third-party antivirus, manually add the install directory to the trusted / allow list.

---

## 🎯 Scope & Security Notes

* **Security Warning:** This project is based on **2D facial recognition**. Compared to Windows Hello's 3D structured light or infrared liveness detection, 2D recognition can potentially be bypassed with photos or videos.
* **Recommended Use:** Only recommended for **low-security** personal/home computers or development environments where convenience is prioritized. **Do not use in office or server environments storing highly confidential data.**
* **System Requirements:** Windows 10/11 64-bit (Windows 7 64-bit not yet tested).
* **Notice:** Do not use this software for illegal purposes. The user bears full responsibility for any misuse.

---

## 🛠️ Installation & Usage

> Before starting, make sure you have read and understood the **Risk Warning** above.

1. **Step 1: System Initialization**
   Run the software. The system will automatically detect camera permissions and registry environment. It is strongly recommended to take a photo at step 2 for recovery reference.
   ![Important notice](data/1-1.png "Important notice")
   ![1-2](data/1-2.png "1-2")
   After clicking Execute, the software will lock your account and unlock it automatically after 5 seconds. Do not unlock manually. Successful unlock means initialization is complete.

2. **Step 2: Personalization**
   After successful initialization, click Preferences and select a camera device.
   ![2-1](data/2-1.png "2-1")

3. **Step 3: Face Enrollment**
   Click Face Management → Add New Face.
   ![3-1](data/3-1.png "3-1")
   Choose one of the following methods to add a face.
   ![3-2](data/3-2.png "3-2")

4. **Step 4: Account Association**
   After adding a face, enter an alias, Windows account type, username (auto-checked), and password. Click Add to complete.
   ![4-1](data/4-1.png "4-1")
   Face list features:
   ![4-2](data/4-2.png "4-2")

5. **Step 5: Testing**
   Press `Win + L` to lock the screen. Move the mouse or press a key (wait for any configured delay), and face recognition will activate.
   ![5-1](data/5-1.png "5-1")

6. **Step 6: Uninstallation**
   Click Preferences → Uninstall Core Components (skipping this step leaves residual files).
   ![6-1](data/6-1.png "6-1")
   Open the installation directory and run *uninstall.exe* to remove the main program.
   ![6-2](data/6-2.png "6-2")
   Finally, delete any remaining database and log files. Uninstallation is now complete with no residual files.
   ![6-3](data/6-3.png "6-3")

7. **Appendix: Consistency Verification**
   On the Add/Edit Face screen, use the consistency verification to compare the current face against a reference.
   ![7-1](data/7-1.png "7-1")
   Click to activate the camera; real-time face similarity is displayed on the right.
   ![7-2](data/7-2.png "7-2")

8. **Appendix: Performance**
   System resource usage during face verification:
   ![8-1](data/8-1.png "8-1")
   Background process resource usage:
   ![8-2](data/8-2.png "8-2")

---

## 💡 Roadmap

* [x] System initialization wizard
* [x] Real-time camera face enrollment
* [x] Multiple faces per account
* [x] Multiple faces across multiple accounts (contributed by [@Xiao-yu233](https://github.com/Xiao-yu233))
* [x] DLL and application preferences
* [x] Log viewer
* [x] Silent auto-start
* [x] Local account & Microsoft account support
* [x] Liveness detection (contributed by [@tztztzy](https://github.com/tztztzy))
* [x] Login security features (contributed by [@tztztzy](https://github.com/tztztzy))
* [x] Last frame capture on unlock failure
* [x] Interaction optimization: face recognition only on user action (completed 2026-01-18)

## Future Plans

* [ ] Encrypted Windows credential storage
* [x] Unlock service performance optimization
* [x] Log clearing
* [ ] Fix face unlock during sleep/hibernation
* [x] Timeout when no face detected
* [ ] Password recovery
* [ ] Simplified cache clearing
* [x] Retry support for delay timer
* [ ] New face recognition invocation mode
* [x] Tiered face unlock support (boot, lock screen, UAC, user layer)
* [ ] Liveness detection optimization
* [x] One-click uninstall script (generated by Claude)
* [x] Update checker with incremental downloads
* [ ] Dynamic feedback during recognition (completed 2026-02-17, styling pending)
* [ ] Replace OpenCV to reduce 70MB footprint and fix Chinese path issues (under consideration...)

---

## ⚠️ Known Issues

These are current technical challenges. Contributions via PR are welcome:

* **Lock Screen UI Enhancement:** Due to Windows lock screen isolation, native animations and dynamic notifications (similar to Windows Hello) are not currently possible. (Improved 2026-02-17, but still limited)

---

## ✨ Features

* **Modern UI:** Built with Vue 3 + Element Plus, leaving behind the "dated" look of traditional desktop software.
* **System-Level Integration:** Automatically registers a WinLogon Credential Provider.
* **Dual Account Support:** Supports both local accounts and Microsoft online accounts (MSA).
* **Lightweight Backend:** Rust backend ensures efficient file I/O and registry operation safety.
* **Privacy Protection:** Credentials are stored locally via SQLite — **never uploaded to the cloud**.

---

## 🛠️ Tech Stack

* **Frontend:** Vue 3 (Composition API), Pinia, Element Plus
* **Backend:** Rust (Tauri), Windows API
* **Database:** SQLite 3
* **Face Recognition:** OpenCV (face detection & feature matching)
* **Unlock Component:** Custom WinLogon Credential Provider DLL written in Rust

---

## 📦 Repository Structure

* [WinLogon DLL](Server/) - Core component that interfaces with the system login screen.
* [GUI Application](UI/) - Main program for face enrollment and configuration management.
* [Unlock Service](Unlock/) - Handles unlock requests and communicates with the WinLogon DLL.
* [Pipe Library](windows_pipes/) - Named pipe utilities shared across components.
* [Face Recognition](face_library/) - Provides face recognition capabilities for the unlock service and GUI.

---

## 🔨 Building from Source

This project consists of three independent Rust components with a **root workspace `Cargo.toml`**. Running `cargo build --release` from the repository root builds all three.

### Build Status

| Component | Cargo.toml | Buildable? |
|-----------|-----------|------------|
| Root workspace | ✅ Restored | ✅ `cargo build --release` (from repo root) |
| `Server/` (DLL) | ✅ Restored | ✅ Compiles |
| `UI/src-tauri/` (Tauri backend) | ✅ Restored (deps inferred from source) | ⚠️ Compiles, some modules are stubs |
| `Unlock/` (Unlock service) | ✅ Restored | ✅ Compiles with full face recognition |

### Build All (from root)

```powershell
# Set Rust environment first, then:
cd FaceWinUnlock-Tauri
cargo build --release
```

This builds all three workspace members: Server DLL, UI Tauri app, and Unlock service.

### Server DLL

```powershell
cd Server
cargo build --release
# Output: target/release/FaceWinUnlock_Tauri.dll
```

### UI Frontend (standalone)

The Vue 3 frontend code is complete and can be previewed via Vite dev server (without the Rust backend):

```powershell
cd UI
npm install
npm run dev
```

Full Tauri build (`npm run tauri build`) requires all resource files and ONNX models. See [CLAUDE.md](CLAUDE.md) for detailed build instructions.

### ONNX Models

Download the three required ONNX models:
```powershell
cd UI/resources
.\download_models.ps1
```

### Rust Environment

Rust is installed at a non-standard location (`D:\Rust`). Set environment variables before building:

```powershell
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME  = "D:\Rust\CARGO"
$env:PATH        = "D:\Rust\CARGO\bin;" + $env:PATH
```

External dependencies required: LLVM 19, OpenCV 4.9.0. See [CLAUDE.md](CLAUDE.md) for the complete setup guide.

---

## ⚠️ Disclaimer

This project involves modifying Windows kernel login behavior. When using or developing based on this software, please understand:

1. Incorrect operations may prevent normal system login.
2. It is recommended to debug in a virtual machine (VMware/Hyper-V) environment.
3. The author assumes no responsibility for any data loss, system crash, or security vulnerabilities resulting from use of this software.

---

## 🔐 Passkey Provider

FaceWinUnlock now uses the official Windows Passkey Provider plugin path.

1. The installer bundles `FaceWinUnlock-Passkey.msix` and its signing certificate.
2. Install or update the FaceWinUnlock Passkey plugin from the initialization wizard or **Preferences → System Integration**.
3. Open the plugin manager and complete the one-time Windows registration and enablement step.
4. Register a new passkey on each site with this plugin. Later logins are signed by the plugin-owned non-exportable key; FaceWinUnlock only supplies face-recognition based user verification.

The old browser-extension interception, NGC private-key extraction, and PIN autofill path is disabled. Existing Windows Hello passkey private keys are non-exportable and cannot be migrated into this plugin, so sites must be re-registered when moving to the formal provider. Keep a recovery login method available.

## 🔍 Update Check

On startup, the app checks the latest GitHub Release and uses **semantic version comparison**: it only prompts when the latest version is newer than the current one. If the version is the same, it still compares `update_manifest.json` SHA256 hashes against local runtime files, and will prompt again if the published assets changed under the same version. When an update is needed, it downloads only the changed runtime files, verifies them, and applies them when the app exits. Older releases without a manifest still fall back to a notification that opens the Release page.

| Item | Details |
|------|---------|
| URL | `https://api.github.com/repos/starnotes-xj/FaceWinUnlock-Tauri/releases/latest` |
| Method | GET |
| Data sent | Only standard HTTP headers (User-Agent), no user data |
| Downloads | `update_manifest.json` plus changed files from the same official GitHub Release |
| Verification | Expected byte size and SHA256 must match before files enter the update staging directory |
| Application | Staged files replace runtime binaries on exit; locked files use the existing `.new` recovery path |

**Related source files** (complete chain, traceable from any entry point):

| Layer | File | Description |
|-------|------|-------------|
| Version check | `UI/src-tauri/src/modules/update_check.rs` | `check_update`: GET GitHub API → semantic version comparison → same-version manifest/hash check |
| Incremental download | `UI/src-tauri/src/modules/update_download.rs` | Downloads the manifest, computes the diff, downloads and verifies changed files |
| File application | `UI/src-tauri/src/utils/api.rs` | Applies verified files from `update_temp` during `close_app` |
| Frontend | `UI/src/layout/MainLayout.vue` | Checks version → shows diff → downloads → prompts to exit |

## 📄 License

This project is open source under the [GNU Affero General Public License v3.0](LICENSE).

---

**If you find this project interesting, give it a ⭐ Star to follow progress!**
