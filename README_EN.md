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
- ✅ Added camera rotation option: 0° / clockwise 90° / 180° / counter-clockwise 90°, for laptops used sideways or other non-standard orientations, configurable in Preferences → Recognition Parameters, real-time in preview and unlock ([#96](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/96))
- ✅ Added unlock brightness boost: automatically raises screen brightness during face recognition and restores it when done — improves unlock success rate in low-light environments ([#99](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/99))

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
| v0.1.0 | 2026-01-10 | Initial release | Basic face enrollment, multi-account unlock, system initialization wizard |
| v0.1.1 | 2026-01-13 | Bug fixes | Fixed infinite loop when clicking tile with wrong credentials (#1), fixed unlock failure when tile is hidden (#4). **Re-initialization required** |
| v0.2.0 | 2026-01-19 | Features, bug fixes | Added operation-based face recognition, retry on failure (#10), face disable, retry timer, silent startup, version display. Fixed tile display bug (#15), thread safety, duplicate credential class, thumbnail auto-enable, boot-on-battery issues (#16, #17). **Re-initialization required** |
| v0.2.1 | 2026-01-21 | Bug fixes, system enhancements | Fixed silent startup window bug, tray icon visibility, added password hint, minimum retry of 1s, tray retry mechanism. **Re-initialization required** |
| v0.2.2 | 2026-01-26 | Features, security, UI improvements | Contributed by [@tztztzy](https://github.com/tztztzy). Added liveness detection (ModelScope MiniFASNetV2-RGB), application password lock, UI polish. **Re-initialization required** |
| v0.3.0 | 2026-02-03 | Features, performance, bug fixes | Boot-time face unlock (#25, #18, #42, #40, #30), last frame capture on failure, service logging, liveness in consistency check, multi-face fix, multi-account fix (by [@Xiao-yu233](https://github.com/Xiao-yu233)), memory optimization (#33, #40), 0xc000007b fix (#43). **Re-initialization required** |
| v0.3.1 | 2026-02-07 | Bug fixes | Account name/type edit prompt, liveness accuracy improvements (#56, #51, #35), Program directory read/write fix (#50, #46, #44), boot database read fix (#60, #61). |
| v0.3.2 | 2026-02-13 | Features, performance, bug fixes | No-face-detected stop recognition (#32, #22, #73), liveness enable warning, face alignment option, liveness algorithm optimization, RAF error fix (#63). |
| v0.3.3 | 2026-03-01 | Features, bug fixes | Log clearing (#24), last-frame delete notice, camera capture failure service stop fix (#84), retry-timer manual unlock bug fix. |
| v0.3.4 | 2026-03-15 | System enhancements, size optimization, bug fixes | NSIS one-click uninstall, donation feature, no-face camera call fix, Win11 user-layer DLL log fix, application/UAC layer face unlock fix, log overflow mitigation, camera config in initialization, code reuse optimization, DLL size optimization. |
| v0.3.5 | 2026-04-10 | Features, system enhancements, bug fixes | Unlock scene settings (#97, #93, #87, #74), Win11 application-layer unlock support (#87, #74), delay+retry support, improved wrong-password messaging (#45), dynamic unlock feedback (#45), moved unlock method/retry to DLL, fixed post-password-error login bug (#102), fixed delay-time infinite recognition bug. **Re-initialization required** |
| v0.3.5-fork | 2026-05-25 | Fork code restoration, bug fixes, feature additions | **This fork adds:** Restored Server DLL source (compilable), fixed password-error login bug (#102), fixed browser PIN freeze with UAC/app-layer defaults (#118), mirrored camera preview (#122), inference backend selection (#125), configurable face recognition scenarios, fixed multi-process log loss (Chrome CredUI), added auto-lock idle monitor with face verification (#132), **added camera rotation option (0°/CW 90°/180°/CCW 90°)** for sideways/non-standard camera orientations (#96), **added unlock brightness boost** — auto-raises screen brightness during face recognition and restores on completion to improve low-light unlock success rate (#99). |
| v0.4.0 | 2026-05-29 | Features, bug fixes, CI/CD | **Windows Hello-style animation UI** (DComp + Direct2D, 60 FPS, 4 states, adaptive refresh rate)<br />**Chrome CredUI double-trigger fix** (unified input hook triggers)<br />**Boot-time face unlock reliability** (BootTrigger delay + LogonTrigger fallback)<br />**No-face auto retry** (Unlock EXE retries up to 3 rounds internally)<br />**Inference backend selection** (CPU / OpenCL GPU / OpenCL FP16 / Intel NPU)<br />**Camera rotation** (0°/90°/180°/270°) (#96)<br />**Unlock brightness boost** (#99)<br />**Dark mode** (#92)<br />**Domain account login** (#104)<br />**Unlock tile refinement** (#91)<br />Fixed face-disabled phantom login (#103)<br />Fixed NVIDIA Broadcast virtual camera artifacts (#94)<br />Fixed init wizard environment check freeze<br />Fixed dashboard tab white screen<br />Fixed animation pipeline race conditions<br />**GitHub Actions CI/CD auto-build release workflow** |

---

## 📢 Important Notices

> **Risk Warning:** This project involves low-level **registry modification** and **Winlogon process injection**. In extreme cases (e.g., DLL crash, path misconfiguration), it may prevent the Windows login screen from displaying normally, potentially **preventing you from reaching the desktop**.

> **Recommendation:** Before deployment, carefully read the on-screen notifications and take photos or notes for recovery reference (though the probability is extremely small).

> **Important:** Enter your **account password**, not your PIN. Many users unlock via PIN and then enter their PIN in the software, resulting in "username or password incorrect" errors. **This software does not support PINs — use your account password.**

> **If you see repeated password errors, uninstall the software immediately. Do not continue, or Microsoft may lock your account!**

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
* [ ] Tiered face unlock support (boot, lock screen, UAC, user layer)
* [ ] Liveness detection optimization
* [x] One-click uninstall script (generated by Claude)
* [ ] Update checker
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

## 📄 License

This project is open source under the [GNU Affero General Public License v3.0](LICENSE).

---

**If you find this project interesting, give it a ⭐ Star to follow progress!**
