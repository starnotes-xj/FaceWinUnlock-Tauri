# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a fork of [FaceWinUnlock-Tauri](https://github.com/zs1083339604/FaceWinUnlock-Tauri) that **reconstructs the deleted core Rust source code** (v0.3.5). The original author closed the source in March 2026 (commit `94025f8`, "闭源核心代码"); this fork reverse-engineers and restores the missing files so the full project can be built.

**Three separate executables, all in the same repo:**

| Directory | Type | Role |
|-----------|------|------|
| `Server/` | Rust `cdylib` | Windows Credential Provider DLL injected into `winlogon.exe` |
| `UI/` | Tauri (Rust + Vue 3) | GUI for face enrollment, config management, log viewer |
| `Unlock/` | Rust binary | Background service; drives the camera and face recognition |

`UI` embeds `Server/target/release/FaceWinUnlock_Tauri.dll` and `Unlock/target/release/Unlock.exe` as bundled resources at install time (configured in `UI/src-tauri/tauri.conf.json`).

**Important:** The repository has a root `Cargo.toml` workspace tying together all three sub-crates. Running `cargo build --release` from the repository root builds all three components.

---

## Build Commands

### Environment Setup (Non-standard Rust path)

Rust is installed to `D:\Rust`, not the default location. Set env vars before running `cargo`:

```powershell
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME  = "D:\Rust\CARGO"
$env:PATH        = "D:\Rust\CARGO\bin;" + $env:PATH
```

### Server DLL (Fully buildable)

```powershell
cd Server
cargo build --release
# Output: Server/target/release/FaceWinUnlock_Tauri.dll
# Cargo package name: "winlogon", lib name: "FaceWinUnlock_Tauri"
```

Deploy the built DLL for live testing:
```powershell
Copy-Item Server\target\release\FaceWinUnlock_Tauri.dll D:\facewinunlock-tauri\resources\
```

Release profile: `opt-level=3, lto=true, codegen-units=1, panic=abort, strip=true`

### UI (Tauri App) — Partially buildable

```powershell
cd UI
npm install        # first time only
npm run tauri dev  # development with hot-reload
npm run tauri build  # production installer
```

> **Note:** `tauri.conf.json` version field is stuck at `"0.3.2"` (original author did not update it). The `bundle.resources` is an empty `{}` — resource files must be placed manually in the install directory.

### Unlock Server EXE — Fully buildable

```powershell
cd Unlock
cargo build --release
# Output: Unlock/target/release/Unlock.exe
```

Complete implementation (607 lines): named pipe servers (control + unlock), OpenCV face detection/feature extraction/cosine similarity matching, SQLite face record loading, auto-lock monitor with idle detection, test credentials file support. Uses `rusqlite` for database access.

---

## Architecture

### Pipe IPC Protocol

Two named pipes bridge the three processes:

```
UI app (Tauri)
    └── Tauri commands → SQLite options DB
    └── check_process_running / delete_process_running
            → connects to MansonWindowsUnlockRustUnlock (send "hello server" / "exit")

Unlock.exe (FaceWinUnlock-Server.exe)
    ├── Creates pipe: \\.\pipe\MansonWindowsUnlockRustServer   (DLL Client thread sends "prepare"/"run")
    ├── Creates pipe: \\.\pipe\MansonWindowsUnlockRustUnlock   (DLL Creds thread waits for credentials; UI sends "hello server"/"exit")
    └── Face recognition loop: loads OpenCV models, matches camera frames against stored features

Server DLL (winlogon.exe / credentialuibroker.exe)
    ├── Client thread: connects to MansonWindowsUnlockRustServer → sends "prepare", then "run" (with backoff #115)
    └── Creds thread: connects to MansonWindowsUnlockRustUnlock → blocks on ReadFile, receives credentials → CredentialsChanged
```

Credential wire format — **two supported formats** (see `Server/src/Pipe.rs:parse_credentials`):

```
# Format 1: null-delimited UTF-8
"username\0password\0domain\0"

# Format 2: simple JSON (no serde dependency)
{"user_name":"...","user_pwd":"...","domain":"..."}
```

**Note:** `UI/src-tauri/src/utils/api.rs` `check_process_running` connects to `MansonWindowsUnlockRustUnlock` and sends `"hello server"` to verify the Unlock EXE is alive; `delete_process_running` sends `"exit"` to shut it down. The pipe client (`UI/src-tauri/src/utils/pipe.rs`) is the thin RAII wrapper used for these calls.

### Server DLL (Credential Provider COM)

Files in `Server/src/`:

- **`lib.rs`** — DLL entry points (`DllMain`, `DllGetClassObject`, `DllCanUnloadNow`), global ref-count, registry reader. Log file is opened with `OpenOptions::append(true).share_mode(FILE_SHARE_READ|WRITE)` so multiple host processes (winlogon, credentialuibroker) can write simultaneously; PID is logged at startup.
- **`CSampleProvider.rs`** — `ICredentialProvider` impl; reads `UNLOCK_SCENE` registry key (default `"1,2,4"`) to filter which scenarios activate face unlock; starts `CPipeListener` in `Advise()`; returns `E_NOTIMPL` for unlisted scenarios (fixes browser PIN freeze, #118). `SetUsageScenario` 中通过 `dwflags & CREDUIWIN_GENERIC` 检测应用凭据弹窗（如 RDP），配合 `CREDUI_ALLOW_GENERIC` 注册表键进行过滤 (#114). `GetCredentialCount` 始终初始化所有输出指针防止 UB；autologon 由 `SharedCredentials.is_unlocked` 控制（脉冲信号，由 GetSerialization 消费重置），解决 UAC 场景多次调用导致 autologon 丢失问题 (#112).
- **`CSampleCredential.rs`** — `ICredentialProviderCredential` impl; `GetSerialization` packs credentials via `CredPackAuthenticationBufferW` with `CRED_PACK_PROTECTED_CREDENTIALS` flag (#126 修复微软应用程式密码支持); 成功后重置 `SharedCredentials.is_unlocked` 防止重复 autologon (#112); `ReportResult` clears credentials on failure (#102).
- **`CPipeListener.rs`** — Two background threads managed by `Arc<Mutex<CPipeListener>>`:
  - **Client thread**: reads `CONNECT_TO_PIPE` registry key (default `"1"`), connects to `MansonWindowsUnlockRustServer` (30s timeout first, 10s reconnect), sends `"prepare"`, waits `UNLOCK_GRACE_PERIOD` (default 5s, prevents immediate re-unlock after Dynamic Lock triggers #116), then sends `"run"` on a `RETRY_DELAY` loop with exponential backoff (#115). Outer reconnect loop handles Unlock EXE crashes (#113).
  - **Creds thread**: connects to `MansonWindowsUnlockRustUnlock` (5s timeout, reconnect loop), blocks on `ReadFile`, receives credentials, calls `CredentialsChanged` to trigger auto-login.
  - `stop_and_join()`: sets stop flag, closes creds pipe handle to unblock `ReadFile`, joins both threads. In primary scenarios (LOGON/UNLOCK), if face was never recognized (manual unlock), sends "exit" to Unlock EXE to release camera (#117). CREDUI scenarios never send exit (Unlock EXE might still be needed by lock screen).
- **`Pipe.rs`** — Named pipe primitives (`pipe_connect_to_server`, `pipe_create_unlock_server`, `pipe_wait_for_unlock_client`, `pipe_read_raw`, `pipe_write_raw`, `pipe_connect_write_only`, `pipe_disconnect`, `parse_credentials`).

**Critical windows-rs 0.59 quirks** (different from older versions):
- `CreateNamedPipeW` returns `HANDLE` (not `Result<HANDLE>`) — check `handle.is_invalid()` manually
- `windows_core::BOOL` ≠ `windows::Win32::Foundation::BOOL` — COM trait impls must use `Foundation::BOOL`
- COM method `CredentialsChanged` is `unsafe fn`
- `Win32_System_IO` feature required for `WriteFile`/`ReadFile`/`ConnectNamedPipe`
- Rust 2021 partial capture: avoid `closure.struct_field.method()` patterns; use wrapper methods so the entire struct is captured (see `SendableEvents::notify_changed()` in `CPipeListener.rs`)

### 已修复原仓库 Issue

| Issue | 描述 | 修复方式 |
|-------|------|----------|
| [#102](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/102) | 密码错误后仍然尝试登录 | `ReportResult` 中登录失败时清除 `is_ready` 标志，防止 Windows 持续用错误凭据重试 |
| [#118](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/118) | 浏览器 PIN 弹窗卡顿 | `SetUsageScenario` 对 `UNLOCK_SCENE` 列表外的场景返回 `E_NOTIMPL`，阻止不受支持的场景（如 CredUI 4）激活面容识别 |
| [#120](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/120) | 微软账户解锁问题 | 同上 #118 修复：CredUI 场景过滤后，微软账户浏览器 PIN 弹窗不再被拦截 |
| [#126](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/126) | 微软应用程式密码不支持 | `GetSerialization` 中 `CredPackAuthenticationBufferW` 改用 `CRED_PACK_PROTECTED_CREDENTIALS`，凭据加密后正确路由到 CloudAP 身份提供程序 |
| [#113](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/113) | 解锁核心服务突然故障 | DLL Client 线程添加外层重连循环，Unlock EXE 崩溃后自动重连；UI 添加 `restart_unlock_service` 命令用于守护重启 |
| [#112](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/112) | UAC 面容解锁磁贴弹一下就消失 | `GetCredentialCount` 始终初始化输出指针消除 UB；`is_unlocked` 改为 `SharedCredentials` 中的脉冲信号，由 `GetSerialization` 消费后重置，解决 UAC 多次调用 `GetCredentialCount` 导致的 autologon 竞态丢失 |
| [#115](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/115) | 锁屏后风扇狂转 | Client 线程 `"run"` 重试添加指数退避策略：前10次正常间隔，11-30次 5× 间隔，31次后 20× 间隔，避免无人时持续高频人脸识别消耗 CPU |
| [#114](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/114) | 应用和UAC解锁冲突（RDP干扰） | `SetUsageScenario` 检测 `dwflags` 中的 `CREDUIWIN_GENERIC` 标志，配合注册表 `CREDUI_ALLOW_GENERIC`（默认`"0"`）过滤 RDP 等应用的通用凭据弹窗，保留 UAC 系统提权的人脸解锁 |
| [#108](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/108) | 休眠/重启后不自启动 | `add_scheduled_task` 计划任务 XML 额外添加 `SessionStateChangeTrigger(SessionUnlock)` 触发器，确保休眠唤醒解锁后自动启动 Unlock EXE（`MultipleInstancesPolicy:IgnoreNew` 防止重复实例） |
| [#116](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/116) | Win11 原生动态锁失效 | Client 线程首次连接后添加可配置宽限期 `UNLOCK_GRACE_PERIOD`（默认 5 秒），锁屏后给用户足够时间走开再开始面容识别，避免动态锁触发后用户被立即面容解锁 |
| [#117](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/117) | 启动不自启 + 手动解锁后摄像头占用 | Part1 由 #108（SessionUnlock 触发器）+ #113（`restart_unlock_service`）覆盖；Part2 `stop_and_join` 在主场景（登录/解锁）中若面容未识别（手动解锁）则发送 "exit" 通知 Unlock EXE 释放摄像头，CREDUI 场景不发送 |
| [#121](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/121) | 一致性验证极其卡顿（1-2 FPS） | `verify_face` 添加 `VERIFY_CACHE` 缓存参考图特征（首帧提取，后续帧复用），避免每帧重复 JPEG 解码+DNN检测+128维特征提取；前端帧间延迟从 100ms 降至 33ms |
| [#92](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/92) | 深色模式 | 新增加 `useTheme` composable（localStorage 持久化 + 系统偏好跟随），导入 `element-plus/theme-chalk/dark/css-vars.css`，侧边栏添加 Sun/Moon 切换按钮，所有硬编码色值改为 CSS 变量 |
| [#91](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/91) | 解锁磁贴优化 | 自有磁贴 `CPFT_LARGE_TEXT` 改为 `CPFT_SMALL_TEXT`（更小巧/状态指示器风格），标签文字精简为"面容解锁"；在用户账户磁贴上添加标记无法实现（Windows 凭据提供程序架构限制：一个 Provider 不能修改另一个的磁贴） |
| [#94](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/94) | NVIDIA Broadcast 虚拟摄像头无法工作 | `try_open_camera_with_backend` 和 Unlock EXE 摄像头打开处设置默认 640×480 帧尺寸 + 10 帧预热，解决虚拟摄像头输出异常分辨率/格式导致的花屏或黑帧问题 |
| [#103](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/103) | 面容被禁用后进行"虚空"登录 | Unlock EXE `load_face_records` 过滤 `view=false`（禁用）和 `lock=true`（锁定）的面容；DLL Creds 线程拒绝空用户名凭据 |
| [#104](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/104) | 支持域账户登录 | `AccountAuthForm` 新增"域账户"类型 + 域名输入框；Unlock EXE `JsonData`/`FaceRecord` 新增 `domain` 字段，管道凭据组装用实际域名替代硬编码 `"."` |

### Registry Keys

Location: `HKLM\SOFTWARE\facewinunlock-tauri`

| Key | Values | Notes |
|-----|--------|-------|
| `UNLOCK_SCENE` | comma-separated ints (e.g. `"1,2,4"`) | 1=Logon, 2=Unlock, 4=CredUI (UAC/app-layer); **default `"1,2,4"`**; returning `E_NOTIMPL` for unlisted scenarios prevents browser PIN freezes |
| `RETRY_DELAY` | float seconds | How long before re-sending "run" to Unlock EXE; read by Client thread; minimum clamped to 1.0s |
| `CONNECT_TO_PIPE` | `"1"` / `"0"` | Whether DLL Client thread connects to Unlock EXE at all |
| `SHOW_TILE` | `"1"` / `"0"` | Show/hide credential provider tile in login screen |
| `DLL_LOG_PATH` | path string | Directory for `facewinunlock.log`; defaults to `C:` |
| `CREDUI_ALLOW_GENERIC` | `"0"` / `"1"` | Default `"0"`; when `"0"`, skip CREDUI prompts that request generic credentials (e.g. RDP/mstsc), keeping face unlock only for UAC elevation (#114) |
| `UNLOCK_GRACE_PERIOD` | float seconds | Default `5.0`; delay after lock screen appears before starting face recognition, gives user time to walk away (Dynamic Lock compatibility) (#116) |

DLL reads registry via `read_facewinunlock_registry()` in `lib.rs`. UI writes via `write_to_registry` Tauri command (`UI/src-tauri/src/modules/options.rs`, uses `winreg` crate).

DLL-level settings are mirrored to both SQLite and the registry when the user clicks "同步至系统注册表": `showTile` (→ `SHOW_TILE`), `unlockScene` (→ `UNLOCK_SCENE`, comma-separated, default `"1,2,4"`).

**Scenario 4 (CredUI) notes:** Chrome's CredUI loads the DLL inside `credentialuibroker.exe`, a separate process from `winlogon.exe`. The log file is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE` (append mode) so both processes can write to the same `facewinunlock.log`. Each DLL startup logs its PID for disambiguation. Passkey PIN creation (NGC/TPM) is a completely different auth path and is NOT affected by the credential provider.

### Unlock EXE (Face Recognition Service)

`Unlock/src/main.rs` (607 lines) — Complete background service:

- **`run_control_server`** — Creates `MansonWindowsUnlockRustServer` pipe, reads "run" commands from DLL, sets `run_requested` flag
- **`run_unlock_server`** — Creates `MansonWindowsUnlockRustUnlock` pipe, spawns per-client handler threads:
  - UI clients: read commands ("hello server" health check, "exit" shutdown)
  - DLL clients: wait for matched credentials and push them via pipe
- **`face_recognition_loop`** — Main recognition loop:
  - On `run_requested`: opens camera (CAP_ANY, indices 0-3), captures up to 60 frames, runs face detection (FaceDetectorYN) + feature extraction (FaceRecognizerSF), computes cosine similarity against stored `.face` feature files from `<exe_dir>/faces/`
  - Loads face records from SQLite `faces` table via `rusqlite`
  - Periodically reloads face records (every 30s) to pick up changes
  - Checks `block/test_creds.tmp` for test credentials (UI test mode)
- **`auto_lock_monitor`** — Auto-lock monitor thread:
  - Reads `autoLockEnabled` / `autoLockTimeout` from SQLite options table (polled every 30s)
  - Uses `GetLastInputInfo` for idle detection
  - On idle timeout: opens camera, verifies face (max 15 frames), if unauthorized user or no face detected → calls `LockWorkStation()`
  - If authorized face detected, updates last-active timestamp and continues monitoring

### UI Backend (Tauri / Rust)

Key files in `UI/src-tauri/src/`:

- **`lib.rs`** — App setup; global `lazy_static!` singletons:
  - `APP_STATE: Mutex<AppState>` — holds loaded OpenCV models (`detector`, `recognizer`, `liveness`) and open `camera` (all `Option<OpenCVResource<T>>`).
  - `GLOBAL_TRAY` / `TRAY_IS_READY` — system tray state.
  - `ROOT_DIR` — computed from `current_exe().parent()` at startup; used for resource paths.
  - Silent launch: if any arg equals `-s`, `--silent`, or `--s`, the main window starts hidden.
  - `CloseRequested` is intercepted to hide the window (not exit).
  - `WTSRegisterSessionNotification` + `SetWindowSubclass` inject `wnd_proc_subclass` to receive `WM_WTSSESSION_CHANGE`.
- **`main.rs`** — Sets `WEBVIEW2_USER_DATA_FOLDER` to `{exe_dir}\cache`; applies SDDL `D:(A;OICI;FA;;;WD)` (all users full control) to that directory; falls back to `C:\ProgramData\facewinunlock-tauri` if creation fails.
- **`proc.rs`** — `wnd_proc_subclass`: calls `stop_camera()` on `WTS_SESSION_LOCK`; no-op on `WTS_SESSION_UNLOCK`.
- **`tray.rs`** — `create_system_tray`: waits up to 5s for tray service, creates tray, on failure spawns a retry thread (max 30 attempts × 1s). Also spawns a monitor thread (every 5s) to detect and rebuild a disappeared tray. Menu items: "显示窗口", "退出".
- **`modules/options.rs`** — `write_to_registry(items: Vec<RegistryItem>)` — writes to `HKLM\SOFTWARE\facewinunlock-tauri` using the `winreg` crate.
- **`modules/init.rs`** — All 4 commands fully implemented: `check_admin_privileges` (TokenElevation check), `check_camera_status` (OpenCV camera probing indices 0-3), `deploy_core_components` (copy DLL to System32 + COM/CLSID registry registration), `uninstall_init` (delete registry keys + DLL).
- **`modules/faces.rs`** — All 4 commands fully implemented with OpenCV pipeline: face detection (FaceDetectorYN), feature extraction/alignment (FaceRecognizerSF), liveness detection (custom ONNX), cosine similarity matching. `verify_face` uses `VERIFY_CACHE` (LazyLock<Mutex>) to cache reference image features across frames (#121).
- **`utils/api.rs`** — Mixed: most utility commands are open, some are stubs (see Code Status below).
- **`utils/pipe.rs`** — Thin RAII pipe client: `Client { handle: HANDLE }` + `write(handle, String)`. Used by `check_process_running` and `delete_process_running`.
- **`utils/custom_result.rs`** — `CustomResult { code: i32, msg: String, data: Value }` with `::success()` / `::error()` constructors.

### UI Frontend

Vue 3 + Pinia + Element Plus, Vue Router with hash history.

Routes: `/init` → `/login` → `/` (MainLayout with children: Dashboard, `/faces`, `/faces/add`, `/options`, `/logs`)

Key stores:
- `src/stores/options.js` — SQLite table `options (id, key, val, lastTime)`; `saveOptions({key: val})` upserts; `getOptionValueByKey(key)` reads. All keys are strings.
- `src/stores/faces.js` — SQLite table `faces (id, user_name, user_pwd, account_type, face_token, json_data, createTime)`. `json_data` is JSON string: `{ alias, threshold (int 0-100), faceDetectionThreshold (float 0-1) }`.

Settings saved to SQLite (via `optionsStore`) include: `camera`, `cameraList`, `faceRecogType`, `retryDelay`, `notFaceDelay`, `inferenceBackend`, `livenessEnabled`, `livenessThreshold`, `faceAlignedType`, `loginEnabled`, `loginPassword`, `loginMethod`, `silentRun`.

DLL-level settings are mirrored to both SQLite and the registry when the user clicks "同步至系统注册表": `showTile` (→ `SHOW_TILE`), `unlockScene` (→ `UNLOCK_SCENE`, comma-separated, default `"1,2,4"`).

### OpenCV Models and Inference Backend

Models are stored in `resources/` at the install location:

| File | Purpose |
|------|---------|
| `face_detection_yunet_2023mar.onnx` | Face detection (`FaceDetectorYN`) |
| `face_recognition_sface_2021dec.onnx` | Face recognition / feature matching (`FaceRecognizerSF`) |
| `face_liveness.onnx` | Anti-spoofing liveness check (`dnn::Net`) |

Models are loaded into `APP_STATE` by `load_opencv_model(backend, target)`. All three models share the same backend/target. `unload_model()` sets all three to `None`. Camera is stored as `app_state.camera` and cleared by `stop_camera()`.

| `inferenceBackend` setting | backend | target | Notes |
|---------------------------|---------|--------|-------|
| `"cpu"` (default) | 0 | 0 | CPU |
| `"opencl"` | 3 | 1 | OpenCL GPU |
| `"opencl_fp16"` | 3 | 2 | OpenCL FP16 |
| `"intel_npu"` | 2 | 9 | Intel NPU via OpenVINO (requires separate OpenVINO runtime) |

`load_opencv_model` is idempotent per model: only loads if `app_state.detector.is_none()` etc. To force reload with new backend: call `unload_model` first, then `load_opencv_model`.

---

## Debugging Tools

**`Server/pipe_sniffer.ps1`** — Run as Administrator to intercept pipe communication:
- Impersonates `MansonWindowsUnlockRustServer` to capture "prepare"/"run" messages from the DLL
- Can inject test credentials into `MansonWindowsUnlockRustUnlock` to simulate a face match

```powershell
# Run as Administrator
.\Server\pipe_sniffer.ps1
```

**DLL log file**: written to the path in registry `DLL_LOG_PATH` as `facewinunlock.log`. Multiple processes append to the same file; each startup entry includes `(PID: XXXX)`.

**UI log file**: written to `{install_dir}\logs\app.log` via `tauri-plugin-log`.

---

## Code Status (Reconstructed vs Closed)

### Source Files

| File | Status |
|------|--------|
| `Server/src/lib.rs` | ✅ Open & compilable |
| `Server/src/CSampleProvider.rs` | ✅ Open & compilable |
| `Server/src/CSampleCredential.rs` | ✅ Open & compilable |
| `Server/src/CPipeListener.rs` | ✅ Open & compilable |
| `Server/src/Pipe.rs` | ✅ Open & compilable |
| `UI/src-tauri/src/lib.rs` | ✅ Open |
| `UI/src-tauri/src/main.rs` | ✅ Open |
| `UI/src-tauri/src/proc.rs` | ✅ Open |
| `UI/src-tauri/src/tray.rs` | ✅ Open |
| `UI/src-tauri/src/utils/pipe.rs` | ✅ Open (RAII Client wrapper) |
| `UI/src-tauri/src/utils/custom_result.rs` | ✅ Open |
| `UI/src-tauri/src/modules/options.rs` | ✅ Open (`write_to_registry`) |
| `UI/src-tauri/src/utils/api.rs` | ✅ Open — all commands implemented (see table below) |
| `UI/src-tauri/src/modules/init.rs` | ✅ Open — admin check, camera probe, DLL deploy/uninstall |
| `UI/src-tauri/src/modules/faces.rs` | ✅ Open — full OpenCV face detection/recognition/liveness pipeline with verification cache (#121) |
| `Unlock/src/main.rs` | ✅ Open — 607-line complete implementation: pipe servers, face recognition, auto-lock monitor, SQLite |

### `utils/api.rs` Command Status

| Command | Status |
|---------|--------|
| `get_now_username` | ✅ Open — `GetUserNameW` |
| `stop_camera` | ✅ Open — sets `APP_STATE.camera = None` |
| `close_app` | ✅ Open — WTS unregister, hide tray, `app_handle.exit(0)` |
| `load_opencv_model` | ✅ Open — loads all 3 models with backend/target params |
| `unload_model` | ✅ Open — sets all 3 model fields to `None` |
| `get_uuid_v4` | ✅ Open — `uuid::Uuid::new_v4()` |
| `get_cache_dir` | ✅ Open — returns `%ProgramData%\facewinunlock-tauri\EBWebView` |
| `open_directory` | ✅ Open — `explorer <path>` |
| `disable_scheduled_task` | ✅ Open — `schtasks /Delete /TN <name> /F` |
| `check_scheduled_task` | ✅ Open — `schtasks /Query /TN <name>` |
| `run_scheduled_task` | ✅ Open — `schtasks /Run /TN <name>` |
| `check_trigger_via_xml` | ✅ Open — `schtasks /Query /XML`, detects `<LogonTrigger>` / `<BootTrigger>` |
| `check_process_running` | ✅ Open — connects to `MansonWindowsUnlockRustUnlock`, sends `"hello server"` |
| `delete_process_running` | ✅ Open — connects to `MansonWindowsUnlockRustUnlock`, sends `"exit"` |
| `init_model` | ✅ Open — loads models with backend 0,0 (CPU only, no params) |
| `get_camera` | ⚠️ Partial — `get_windows_video_devices()` returns placeholder names; `is_camera_index_valid` is open |
| `test_win_logon` | ✅ Open — writes creds file + `LockWorkStation` |
| `open_camera` | ✅ Open — tries MSMF→DShow→Any backends, stores in `APP_STATE.camera` |
| `add_scheduled_task` | ✅ Open — full XML task creation with BootTrigger/LogonTrigger + SessionUnlock trigger (#108) |
| `restart_unlock_service` | ✅ Open — checks pipe + runs scheduled task + polls for startup (#113) |

### Build Configuration Files

| File | Status |
|------|--------|
| `Cargo.toml` (root workspace) | ✅ Restored |
| `Server/Cargo.toml` | ✅ Restored (package: `winlogon`, lib: `FaceWinUnlock_Tauri`) |
| `UI/src-tauri/Cargo.toml` | ✅ Restored |
| `UI/src-tauri/build.rs` | ✅ Restored |
| `Unlock/Cargo.toml` | ✅ Restored (complete 607-line implementation) |
| `UI/src-tauri/tauri.conf.json` | ⚠️ Intact but version stuck at `"0.3.2"`, `bundle.resources` is empty `{}` |
| `UI/package.json` | ✅ Intact |
