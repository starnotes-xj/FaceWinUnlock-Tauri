/*!
 * FaceWinUnlock-Server — 人脸解锁后台服务
 *
 * 管道拓扑:
 *   MansonWindowsUnlockRustServer  — 本进程作 Server，DLL 作 Client
 *       DLL 发送 "prepare" (初始化/心跳)，锁屏鼠标或键盘输入后发送 "run"
 *
 *   MansonWindowsUnlockRustUnlock  — 本进程作 Server，DLL 和 UI 均作 Client
 *       DLL 连接后静默等待，本进程写入凭据到此连接完成解锁
 *       UI 发送 "hello server"（心跳检测）或 "exit"（关闭服务）
 */

#![windows_subsystem = "windows"]

mod ngc;
mod passkey;
mod webauthn_activity;

use std::{
    ffi::OsStr,
    fs::{create_dir_all, OpenOptions},
    io::Write,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicIsize, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use opencv::{
    core::{Mat, Ptr, Size},
    objdetect::{FaceDetectorYN, FaceRecognizerSF},
    prelude::*,
    videoio::{self, VideoCapture},
};
use rusqlite::{params, types::ValueRef, Connection};
use serde::Deserialize;
use windows::Win32::{
    Foundation::{
        CloseHandle, GetLastError, BOOL, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        WriteFile, ReadFile, PIPE_ACCESS_DUPLEX,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe,
            PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
        },
        Shutdown::LockWorkStation,
        Threading::CreateMutexW,
    },
    UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
};
use windows_core::PCWSTR;

// ─── Constants ────────────────────────────────────────────────────────────────

const PIPE_SERVER_NAME: &str = r"\\.\pipe\MansonWindowsUnlockRustServer";
const PIPE_UNLOCK_NAME: &str = r"\\.\pipe\MansonWindowsUnlockRustUnlock";
const PIPE_PASSKEY_FACE_NAME: &str = r"\\.\pipe\FaceWinUnlockPasskeyFaceAuth";
const BUF_SIZE: u32 = 4096;
// 预热帧数恢复到 10（issue #94：NVIDIA Broadcast 等虚拟摄像头需足够预热帧才稳定输出，
// 否则花屏/黑帧）。有了「摄像头预热（秒解锁）」后，这段预热多在锁屏预开阶段完成、不在解锁关键路径上。
const CAMERA_WARMUP_MAX_FRAMES: usize = 10;
const CAMERA_WARMUP_READY_FRAMES: usize = 10;
// 摄像头预热（秒解锁）空闲超时：锁屏预开摄像头后，这段时间内无 "run"（用户到场）则释放摄像头
// 并抑制预热（关指示灯、省电），直到收到 run 或 release。
const PREWARM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const WORKER_ARG: &str = "--facewinunlock-worker";
/// UI（录入 / 一致性校验 / 预览）请求让位摄像头后，抑制预热 + 自动开摄像头的兜底时长（毫秒）。
/// UI 发 "ui_release" 时把 `camera_yield_until` 设为 now+此值，发 "ui_done"(stop_camera) 时清零。
/// 修复「录入采集黑屏」——后台预热(prewarm)占着摄像头时 UI open_camera 抢不到、只出黑帧；
/// 兜底超时应对 UI 崩溃未发 ui_done（超时后自动恢复预热，不影响秒解锁）。
const UI_CAMERA_YIELD_FALLBACK_MS: i64 = 60_000;

// ─── Shared state ─────────────────────────────────────────────────────────────

struct State {
    exe_dir:           PathBuf,
    should_exit:      AtomicBool,
    prepare_requested: AtomicBool,
    run_requested:    AtomicBool,
    recognition_active: AtomicBool,
    release_requested: AtomicBool,
    /// Stops only generic broker recognition. Official passkey-plugin face
    /// authorization must remain available while this flag is set.
    broker_guard_release_requested: AtomicBool,
    /// Monotonic cancellation generation for already-connected generic broker
    /// credential handlers. New connections capture the latest generation.
    broker_guard_release_generation: AtomicU64,
    /// DLL 在 MansonWindowsUnlockRustUnlock 上等待凭据的连接句柄（raw isize）
    dll_creds_pipe:   AtomicIsize,
    /// 人脸匹配到的 (username, password, domain)。所有场景统一只交密码（Approach B）。
    matched_creds:    Mutex<Option<(String, String, String)>>,
    /// 上一次用户活跃的时间戳（Unix 秒），用于自动锁屏
    last_user_active: AtomicI64,
    active_pipe_handlers: AtomicUsize,
    /// DLL 是否已发送过至少一次 "run" 命令。delay 模式必须收到 DLL 的显式
    /// run 后才允许自动重试——防止冷启动时 DLL 仅发 "prepare" 就触发识别，
    /// 导致凭据在系统未就绪时提交、桌面加载卡死（白色圆点转圈→强制关机）。
    dll_run_received: AtomicBool,
    /// 上次面容识别成功的时间戳（Unix 秒）。0 表示尚未成功解锁过。
    /// 重锁宽限期：成功解锁后重新锁屏时，delay 模式在 RE_LOCK_GRACE_SECS
    /// 内不触发，防止用户刚锁屏离开就被立即识别解锁。
    last_successful_unlock_at: AtomicI64,
    /// 连续识别失败次数，用于 delay 退避。每次识别失败 +1，成功后清零。
    /// delay 重新布防的冷却时间 = face_recog_delay × 2^min(failures, 4)，
    /// 防止无人时摄像头反复打开导致风扇狂转、电池耗尽。
    consecutive_failures: AtomicU32,
    /// broker PIN 回退后的冷却截止时间（Unix 毫秒）。
    /// DLL 在 broker 场景发送 "release" 后设置此值，Unlock EXE
    /// 在冷却期内拒绝所有新的 "run" 命令和 delay 自动触发。
    /// 0 表示无冷却。冷却解决 credentialuibroker.exe 每次请求
    /// 创建新进程导致 DLL 端 static 变量归零的问题。
    after_release_cooldown_until: AtomicI64,
    /// UI 让位摄像头的截止时间（Unix 毫秒）。UI 录入 / 一致性校验 / 预览前发 "ui_release"
    /// 设为 now + UI_CAMERA_YIELD_FALLBACK_MS，发 "ui_done" 清零。> now 时后台不预热、不自动
    /// 开摄像头，把摄像头让给 UI，修复录入采集黑屏（UI 与后台服务争抢同一摄像头）。
    camera_yield_until: AtomicI64,
    /// 浏览器 passkey assertion 的一次性人脸授权门。
    passkey_face_gate: Arc<passkey::FaceAuthorizationGate>,
}

impl State {
    fn new(exe_dir: PathBuf) -> Arc<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        Arc::new(Self {
            exe_dir,
            should_exit:     AtomicBool::new(false),
            prepare_requested: AtomicBool::new(false),
            run_requested:   AtomicBool::new(false),
            recognition_active: AtomicBool::new(false),
            release_requested: AtomicBool::new(false),
            broker_guard_release_requested: AtomicBool::new(false),
            broker_guard_release_generation: AtomicU64::new(0),
            dll_creds_pipe:  AtomicIsize::new(INVALID_HANDLE_VALUE.0 as isize),
            matched_creds:   Mutex::new(None),
            last_user_active: AtomicI64::new(now),
            active_pipe_handlers: AtomicUsize::new(0),
            dll_run_received: AtomicBool::new(false),
            last_successful_unlock_at: AtomicI64::new(0),
            consecutive_failures: AtomicU32::new(0),
            after_release_cooldown_until: AtomicI64::new(0),
            camera_yield_until: AtomicI64::new(0),
            passkey_face_gate: Arc::new(passkey::FaceAuthorizationGate::default()),
        })
    }
}

// ─── Face record ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct FaceRecord {
    id:         i64,
    user_name:  String,
    user_pwd:   String,
    feature_bytes: Vec<u8>,
    threshold:  i64,   // 0~100，对应余弦相似度
    domain:     String,
}

#[derive(Default, Deserialize)]
struct JsonData {
    threshold: Option<i64>,
    lock: Option<bool>,
    domain: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InferenceBackend {
    key: &'static str,
    label: &'static str,
    backend_id: i32,
    target_id: i32,
}

const CPU_INFERENCE: InferenceBackend = InferenceBackend {
    key: "cpu",
    label: "CPU",
    backend_id: 0,
    target_id: 0,
};

// ─── Named pipe helpers ───────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn pipe_security_attributes(sd: &mut PSECURITY_DESCRIPTOR) -> Option<SECURITY_ATTRIBUTES> {
    let sddl = to_wide("D:(A;;GA;;;WD)");
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl.as_ptr()),
            SDDL_REVISION_1,
            sd,
            None,
        )
    }.is_err() {
        return None;
    }

    Some(SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 as *mut _,
        bInheritHandle: BOOL::from(false),
    })
}

fn create_named_pipe(name: &str) -> windows::core::Result<HANDLE> {
    let wide = to_wide(name);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let sa = pipe_security_attributes(&mut sd);
    let h = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUF_SIZE, BUF_SIZE, 0,
            sa.as_ref().map(|attrs| attrs as *const _),
        )
    };
    if !sd.0.is_null() {
        unsafe { let _ = LocalFree(Some(HLOCAL(sd.0))); }
    }
    if h.is_invalid() { Err(windows::core::Error::from_win32()) } else { Ok(h) }
}

fn wait_for_client(pipe: HANDLE) -> windows::core::Result<()> {
    match unsafe { ConnectNamedPipe(pipe, None) } {
        // ERROR_PIPE_CONNECTED: 客户端已连接，视为成功
        Err(e) if e.code() == windows_core::HRESULT(0x80070217u32 as i32) => Ok(()),
        r => r,
    }
}

fn pipe_write(pipe: HANDLE, data: &[u8]) -> windows::core::Result<()> {
    let mut w = 0u32;
    unsafe { WriteFile(pipe, Some(data), Some(&mut w), None) }
}

fn pipe_read(pipe: HANDLE) -> windows::core::Result<Vec<u8>> {
    let mut buf = vec![0u8; BUF_SIZE as usize];
    let mut n = 0u32;
    unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut n), None)?; }
    buf.truncate(n as usize);
    Ok(buf)
}

/// 在 timeout 内非阻塞地检测管道是否有待读数据
fn peek_has_data(pipe: HANDLE, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let mut avail = 0u32;
        if unsafe { PeekNamedPipe(pipe, None, 0, None, Some(&mut avail), None).is_ok() } && avail > 0 {
            return true;
        }
        if Instant::now() >= deadline { return false; }
        thread::sleep(Duration::from_millis(10));
    }
}

fn close_handle(h: HANDLE) {
    if !h.is_invalid() { unsafe { let _ = CloseHandle(h); } }
}

struct SendPipe(HANDLE);
unsafe impl Send for SendPipe {}

impl SendPipe {
    fn into_handle(self) -> HANDLE {
        self.0
    }
}

fn acquire_named_mutex(exe_dir: &Path, name: &str, duplicate_message: &str) -> Option<HANDLE> {
    let name_wide = to_wide(name);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let sa = pipe_security_attributes(&mut sd);
    let result = unsafe {
        CreateMutexW(
            sa.as_ref().map(|attrs| attrs as *const _),
            true,
            PCWSTR(name_wide.as_ptr()),
        )
    };
    if !sd.0.is_null() {
        unsafe { let _ = LocalFree(Some(HLOCAL(sd.0))); }
    }

    match result {
        Ok(handle) => {
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                log_service(exe_dir, "INFO", duplicate_message);
                close_handle(handle);
                None
            } else {
                Some(handle)
            }
        }
        Err(e) => {
            log_service(exe_dir, "WARN", &format!("single-instance mutex unavailable: {e:?}; exiting to avoid duplicate services"));
            None
        }
    }
}

fn acquire_single_instance_mutex(exe_dir: &Path) -> Option<HANDLE> {
    acquire_named_mutex(
        exe_dir,
        "Global\\FaceWinUnlockTauriUnlockService",
        "another FaceWinUnlock service instance is already running; exiting",
    )
}

pub(crate) fn log_service(exe_dir: &Path, level: &str, message: &str) {
    let logs_dir = exe_dir.join("logs");
    let _ = create_dir_all(&logs_dir);
    let log_path = logs_dir.join("unlock.log");
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seconds = elapsed % 86_400;
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        let _ = writeln!(
            file,
            "{:02}:{:02}:{:02} [{}] {}",
            hour, minute, second, level, message
        );
    }
}

// ─── Control pipe server（MansonWindowsUnlockRustServer）─────────────────────

fn handle_control_client(pipe: HANDLE, state: Arc<State>) {
    let mut control_buf = String::new();
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }
        match pipe_read(pipe) {
            Ok(data) if !data.is_empty() => {
                let cmd = String::from_utf8_lossy(&data);
                control_buf.push_str(&cmd);
                if control_buf.contains("run") {
                    // broker 冷却期内拒绝 "run"：防止新 CredUIBroker 进程
                    // 重新发送 "run" 激活摄像头
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    if now_ms < state.after_release_cooldown_until.load(Ordering::SeqCst) {
                        log_service(&state.exe_dir, "INFO", "run rejected: broker release cooldown active");
                        control_buf.clear();
                        continue;
                    }
                    if state.recognition_active.load(Ordering::SeqCst) {
                        log_service(&state.exe_dir, "INFO", "run ignored while recognition is active");
                    } else {
                        state.release_requested.store(false, Ordering::SeqCst);
                        state.run_requested.store(true, Ordering::SeqCst);
                        state.dll_run_received.store(true, Ordering::SeqCst);
                        log_service(&state.exe_dir, "INFO", "run requested from credential provider");
                    }
                    control_buf.clear();
                } else if control_buf.contains("prepare") {
                    state.prepare_requested.store(true, Ordering::SeqCst);
                    control_buf.clear();
                } else if control_buf.len() > 32 {
                    let keep_from = control_buf.len().saturating_sub(8);
                    control_buf = control_buf[keep_from..].to_string();
                }
            }
            _ => break,
        }
    }

    unsafe { let _ = DisconnectNamedPipe(pipe); }
    close_handle(pipe);
}

// 并发监听实例数量。登录界面会在短时间内创建多批 Credential Provider 实例，
// 4 个监听槽仍然会被启动风暴打满；提高到 32 保持足够空闲实例，避免 ERROR_PIPE_BUSY。
const PIPE_LISTENER_POOL: usize = 32;
const MAX_PIPE_HANDLER_THREADS: usize = 128;

struct PipeHandlerGuard(Arc<State>);

impl Drop for PipeHandlerGuard {
    fn drop(&mut self) {
        self.0.active_pipe_handlers.fetch_sub(1, Ordering::SeqCst);
    }
}

fn spawn_pipe_handler(
    state: Arc<State>,
    pipe: HANDLE,
    name: &'static str,
    handler: fn(HANDLE, Arc<State>),
) {
    if state
        .active_pipe_handlers
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
            (count < MAX_PIPE_HANDLER_THREADS).then_some(count + 1)
        })
        .is_err()
    {
        log_service(
            &state.exe_dir,
            "WARN",
            &format!("{name} pipe handler limit reached; closing new client"),
        );
        unsafe { let _ = DisconnectNamedPipe(pipe); }
        close_handle(pipe);
        return;
    }

    let send_pipe = SendPipe(pipe);
    thread::spawn(move || {
        let _guard = PipeHandlerGuard(state.clone());
        handler(send_pipe.into_handle(), state);
    });
}

fn control_accept_loop(state: Arc<State>) {
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let pipe = match create_named_pipe(PIPE_SERVER_NAME) {
            Ok(p) => p,
            Err(_) => { thread::sleep(Duration::from_millis(500)); continue; }
        };

        if wait_for_client(pipe).is_err() { close_handle(pipe); continue; }

        spawn_pipe_handler(state.clone(), pipe, "control", handle_control_client);
    }
}

fn run_control_server(state: Arc<State>) {
    let mut handles = Vec::with_capacity(PIPE_LISTENER_POOL);
    for _ in 0..PIPE_LISTENER_POOL {
        let st = state.clone();
        handles.push(thread::spawn(move || control_accept_loop(st)));
    }
    for h in handles { let _ = h.join(); }
}

// ─── Unlock pipe server（MansonWindowsUnlockRustUnlock）──────────────────────

fn unlock_accept_loop(state: Arc<State>) {
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let pipe = match create_named_pipe(PIPE_UNLOCK_NAME) {
            Ok(p) => p,
            Err(_) => { thread::sleep(Duration::from_millis(500)); continue; }
        };

        if wait_for_client(pipe).is_err() { close_handle(pipe); continue; }

        spawn_pipe_handler(state.clone(), pipe, "unlock", handle_unlock_client);
    }
}

fn run_unlock_server(state: Arc<State>) {
    let mut handles = Vec::with_capacity(PIPE_LISTENER_POOL);
    for _ in 0..PIPE_LISTENER_POOL {
        let st = state.clone();
        handles.push(thread::spawn(move || unlock_accept_loop(st)));
    }
    for h in handles { let _ = h.join(); }
}

fn handle_passkey_face_client(pipe: HANDLE, state: Arc<State>) {
    let response = match pipe_read(pipe) {
        Ok(data) if String::from_utf8_lossy(&data).trim() == "authorize" => {
            log_service(
                &state.exe_dir,
                "INFO",
                "passkey plugin requested face authorization",
            );
            match state
                .passkey_face_gate
                .request_and_wait(Duration::from_secs(60))
            {
                passkey::FaceAuthorizationResult::Authorized => b"AUTHORIZED".as_slice(),
                passkey::FaceAuthorizationResult::Rejected => b"REJECTED".as_slice(),
                passkey::FaceAuthorizationResult::TimedOut => b"TIMEOUT".as_slice(),
            }
        }
        Ok(_) => b"INVALID_REQUEST".as_slice(),
        Err(_) => b"READ_ERROR".as_slice(),
    };

    let _ = pipe_write(pipe, response);
    unsafe { let _ = DisconnectNamedPipe(pipe); }
    close_handle(pipe);
}

fn passkey_face_accept_loop(state: Arc<State>) {
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let pipe = match create_named_pipe(PIPE_PASSKEY_FACE_NAME) {
            Ok(pipe) => pipe,
            Err(_) => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        };

        if wait_for_client(pipe).is_err() {
            close_handle(pipe);
            continue;
        }

        spawn_pipe_handler(
            state.clone(),
            pipe,
            "passkey-face",
            handle_passkey_face_client,
        );
    }
}

fn run_passkey_face_server(state: Arc<State>) {
    let mut handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let st = state.clone();
        handles.push(thread::spawn(move || passkey_face_accept_loop(st)));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

fn handle_unlock_client(pipe: HANDLE, state: Arc<State>) {
    if peek_has_data(pipe, Duration::from_millis(50)) {
        // UI 客户端：读取命令
        if let Ok(data) = pipe_read(pipe) {
            let msg = String::from_utf8_lossy(&data);
            match msg.trim() {
                "exit" => {
                    log_service(&state.exe_dir, "INFO", "received exit command");
                    state.release_requested.store(true, Ordering::SeqCst);
                    state.should_exit.store(true, Ordering::SeqCst);
                }
                "release" => {
                    log_service(&state.exe_dir, "INFO", "received release command, closing camera");
                    state.run_requested.store(false, Ordering::SeqCst);
                    state.recognition_active.store(false, Ordering::SeqCst);
                    state.release_requested.store(true, Ordering::SeqCst);
                    *state.matched_creds.lock().unwrap() = None;
                }
                "ui_release" => {
                    // UI（录入 / 一致性校验 / 预览）要用摄像头：立即释放后台占用，并在兜底窗口内
                    // 抑制预热，把摄像头让给 UI，修复录入采集黑屏（与后台服务争抢同一摄像头）。
                    log_service(&state.exe_dir, "INFO", "received ui_release, yielding camera to UI");
                    state.run_requested.store(false, Ordering::SeqCst);
                    state.recognition_active.store(false, Ordering::SeqCst);
                    state.release_requested.store(true, Ordering::SeqCst);
                    *state.matched_creds.lock().unwrap() = None;
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    state
                        .camera_yield_until
                        .store(now_ms + UI_CAMERA_YIELD_FALLBACK_MS, Ordering::SeqCst);
                }
                "ui_done" => {
                    // UI 用完摄像头（stop_camera）：解除让位，允许预热恢复（不影响秒解锁）。
                    log_service(&state.exe_dir, "INFO", "received ui_done, resuming camera prewarm");
                    state.camera_yield_until.store(0, Ordering::SeqCst);
                }
                "broker_release" => {
                    log_service(&state.exe_dir, "INFO", "received broker_release command, closing camera with cooldown");
                    state.run_requested.store(false, Ordering::SeqCst);
                    state.recognition_active.store(false, Ordering::SeqCst);
                    state.release_requested.store(true, Ordering::SeqCst);
                    *state.matched_creds.lock().unwrap() = None;
                    // 设置冷却期：仅 broker 场景使用，防止新 CredUIBroker
                    // 进程重新激活面容识别。正常锁屏 "release" 不走此路径。
                    let cooldown_ms = load_broker_release_cooldown(
                        &state.exe_dir.join("database.db"));
                    let deadline = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64
                        + cooldown_ms;
                    state.after_release_cooldown_until.store(deadline, Ordering::SeqCst);
                    log_service(&state.exe_dir, "INFO", &format!(
                        "broker release cooldown set for {}ms", cooldown_ms));
                }
                "broker_guard_release" => {
                    log_service(
                        &state.exe_dir,
                        "INFO",
                        "received WebAuthn guard release; stopping generic broker recognition",
                    );
                    state.run_requested.store(false, Ordering::SeqCst);
                    state.recognition_active.store(false, Ordering::SeqCst);
                    state
                        .broker_guard_release_requested
                        .store(true, Ordering::SeqCst);
                    state
                        .broker_guard_release_generation
                        .fetch_add(1, Ordering::SeqCst);
                    *state.matched_creds.lock().unwrap() = None;
                }
                cmd if cmd.starts_with("pin:") => {
                    // Hello PIN NGC 解密请求：pin:<username>:<PIN>
                    let payload = &cmd[4..]; // 去掉 "pin:" 前缀
                    if let Some(colon_pos) = payload.find(':') {
                        let username = &payload[..colon_pos];
                        let pin = &payload[colon_pos + 1..];
                        log_service(
                            &state.exe_dir, "INFO",
                            &format!("收到 PIN 解锁请求 (用户: {})", username),
                        );
                        // 根据用户名查找 SID
                        let sid = ngc::find_sid_by_username(username);
                        match sid {
                            Ok(sid) => match ngc::recover_password(&sid, pin) {
                                Ok((ngc_user, password, domain)) => {
                                    log_service(
                                        &state.exe_dir,
                                        "INFO",
                                        &format!("NGC PIN 解密成功，用户: {}", ngc_user),
                                    );
                                    *state.matched_creds.lock().unwrap() =
                                        Some((ngc_user, password, domain));
                                    let _ = pipe_write(pipe, b"ok");
                                }
                                Err(e) => {
                                    log_service(
                                        &state.exe_dir,
                                        "WARN",
                                        &format!("NGC PIN 解密失败: {}", e),
                                    );
                                    let _ = pipe_write(pipe, format!("fail:{}", e).as_bytes());
                                }
                            },
                            Err(e) => {
                                log_service(
                                    &state.exe_dir,
                                    "WARN",
                                    &format!("查找 SID 失败: {}", e),
                                );
                                let _ = pipe_write(pipe, format!("fail:{}", e).as_bytes());
                            }
                        }
                    } else {
                        let _ = pipe_write(pipe, b"fail:invalid format, expected pin:<username>:<PIN>");
                    }
                }
                _ => {}
            }
        }
    } else {
        // DLL 客户端：登记为当前凭据连接，等待写入凭据。
        // 注意：不在此关闭被替换的旧句柄——每个连接由各自的处理线程在退出时关闭
        // 自己的 pipe（被替换者经下方 `dll_creds_pipe != pipe` 检测到后 break，并在
        // 函数末尾 close）。否则并发多客户端时同一句柄会被重复关闭，甚至在句柄值被
        // OS 重用后误关无关对象。
        let guard_generation = state
            .broker_guard_release_generation
            .load(Ordering::SeqCst);
        state.dll_creds_pipe.store(pipe.0 as isize, Ordering::SeqCst);
        log_service(&state.exe_dir, "INFO", "credential client connected");

        // 凭据提交（Approach B：密码）。所有场景统一只交密码——
        //   · 登录/解锁：密码永远可用且最快，秒过；
        //   · CredUI(UAC/查看密码)：密码优先；被拒时由 DLL 走「隐藏磁贴 → 交还 Windows
        //     原生 PIN」回退（#102 ReportResult 清标志 + broker 回退已实现），用户手输 PIN。
        // 不再注入 PIN：盲打慢（用户反馈登录/解锁体验不如密码），且曾诱发 broker 卡死。
        // 用 take：凭据就绪即取走并发出；若循环因 release/管道替换中途退出，matched_creds
        // 保留，由下个连接接力提交（broker 频繁重连场景）。
        loop {
            if state.should_exit.load(Ordering::SeqCst) { break; }
            if state.release_requested.load(Ordering::SeqCst) { break; }
            if state.dll_creds_pipe.load(Ordering::SeqCst) != pipe.0 as isize { break; }
            if state
                .broker_guard_release_generation
                .load(Ordering::SeqCst)
                != guard_generation
            {
                break;
            }

            // A DLL client can disconnect while no credentials are ready. Without
            // probing the pipe, the session stays latched forever and suppresses
            // auto-lock/prewarm state transitions.
            let mut available = 0u32;
            if unsafe {
                PeekNamedPipe(pipe, None, 0, None, Some(&mut available), None)
            }
            .is_err()
            {
                log_service(&state.exe_dir, "INFO", "credential client disconnected");
                break;
            }

            let creds = state.matched_creds.lock().unwrap().take();
            if let Some((username, password, domain)) = creds {
                let payload = format!("{}\0{}\0{}\0", username, password, domain);
                let _ = pipe_write(pipe, payload.as_bytes());
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }

        state.dll_creds_pipe.compare_exchange(
            pipe.0 as isize, INVALID_HANDLE_VALUE.0 as isize,
            Ordering::SeqCst, Ordering::SeqCst,
        ).ok();
    }

    unsafe { let _ = DisconnectNamedPipe(pipe); }
    close_handle(pipe);
}

// ─── Database ─────────────────────────────────────────────────────────────────

fn load_face_records(exe_dir: &Path, db_path: &Path) -> Vec<FaceRecord> {
    let conn = match Connection::open(db_path) { Ok(c) => c, Err(_) => return vec![] };
    let mut stmt = match conn.prepare(
        "SELECT id, user_name, user_pwd, account_type, face_token, json_data FROM faces",
    ) { Ok(s) => s, Err(_) => return vec![] };

    stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5).unwrap_or_default(),
        ))
    })
    .ok()
    .map(|rows| {
        rows.filter_map(|r| r.ok())
            .filter_map(|(id, u, p, account_type, t, j)| {
                let json = serde_json::from_str::<JsonData>(&j).unwrap_or_default();
                // 0.3.3 源码里 view 只控制缩略图显示；真正禁用识别的是 lock。
                if json.lock.unwrap_or(false) {
                    return None;
                }
                let thr = json.threshold.unwrap_or(60);
                let dm = json.domain.unwrap_or_else(|| match account_type.as_str() {
                    "online" => String::new(),
                    _ => ".".to_string(),
                });
                let feature_path = exe_dir.join("faces").join(format!("{}.face", t));
                let feature_bytes = std::fs::read(feature_path).ok()?;
                if feature_bytes.is_empty() {
                    return None;
                }
                Some(FaceRecord { id, user_name: u, user_pwd: p, feature_bytes, threshold: thr, domain: dm })
            })
            .collect()
    })
    .unwrap_or_default()
}

fn ensure_unlock_log_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS unlock_log(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            face_id INTEGER,
            is_unlock INTEGER NOT NULL,
            block_img TEXT,
            lastTime TEXT DEFAULT (datetime('now', 'localtime'))
        )",
        [],
    )?;
    Ok(())
}

fn insert_unlock_log(db_path: &Path, exe_dir: &Path, face_id: Option<i64>, is_unlock: bool, block_img: Option<&str>) {
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            log_service(exe_dir, "WARN", &format!("failed to open database for unlock_log: {:?}", e));
            return;
        }
    };
    let _ = conn.busy_timeout(Duration::from_secs(2));
    if let Err(e) = ensure_unlock_log_table(&conn) {
        log_service(exe_dir, "WARN", &format!("failed to ensure unlock_log table: {:?}", e));
        return;
    }
    if let Err(e) = conn.execute(
        "INSERT INTO unlock_log (face_id, is_unlock, block_img) VALUES (?1, ?2, ?3)",
        params![face_id, if is_unlock { 1 } else { 0 }, block_img],
    ) {
        log_service(exe_dir, "WARN", &format!("failed to insert unlock_log: {:?}", e));
    }
}

// ─── Face feature comparison ──────────────────────────────────────────────────

/// 从 Mat（feature 输出）中取出 f32 字节
fn feature_to_bytes(feat: &Mat) -> Vec<u8> {
    feat.data_bytes()
        .map(|b| b.to_vec())
        .unwrap_or_default()
}

/// 余弦相似度（0.0 ~ 1.0）
fn cosine_sim(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() || a.len() % 4 != 0 { return 0.0; }
    let to_f32 = |bytes: &[u8]| -> Vec<f32> {
        bytes.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    };
    let av = to_f32(a);
    let bv = to_f32(b);
    let dot: f64 = av.iter().zip(bv.iter()).map(|(x, y)| (*x as f64) * (*y as f64)).sum();
    let na: f64 = av.iter().map(|x| (*x as f64) * (*x as f64)).sum::<f64>().sqrt();
    let nb: f64 = bv.iter().map(|x| (*x as f64) * (*x as f64)).sum::<f64>().sqrt();
    if na == 0.0 || nb == 0.0 { 0.0 } else { (dot / (na * nb)).clamp(0.0, 1.0) }
}

// ─── OpenCV models ────────────────────────────────────────────────────────────

struct Models {
    detector:   Ptr<FaceDetectorYN>,
    recognizer: Ptr<FaceRecognizerSF>,
}

fn load_models(resources: &Path, inference: InferenceBackend) -> opencv::Result<Models> {
    let detector = FaceDetectorYN::create(
        resources.join("face_detection_yunet_2023mar.onnx").to_str().unwrap_or(""),
        "",
        Size::new(320, 320),
        0.9,
        0.3,
        5000,
        inference.backend_id,
        inference.target_id,
    )?;
    let recognizer = FaceRecognizerSF::create(
        resources.join("face_recognition_sface_2021dec.onnx").to_str().unwrap_or(""),
        "",
        inference.backend_id,
        inference.target_id,
    )?;
    Ok(Models { detector, recognizer })
}

fn load_models_with_fallback(
    resources: &Path,
    inference: InferenceBackend,
    exe_dir: &Path,
) -> Option<(Models, InferenceBackend)> {
    match load_models(resources, inference) {
        Ok(models) => {
            log_service(
                exe_dir,
                "INFO",
                &format!(
                    "opencv models loaded with {} backend ({},{})",
                    inference.label, inference.backend_id, inference.target_id
                ),
            );
            Some((models, inference))
        }
        Err(e) if inference != CPU_INFERENCE => {
            log_service(
                exe_dir,
                "WARN",
                &format!(
                    "failed to load opencv models with {} backend: {:?}; falling back to CPU",
                    inference.label, e
                ),
            );
            match load_models(resources, CPU_INFERENCE) {
                Ok(models) => Some((models, CPU_INFERENCE)),
                Err(cpu_err) => {
                    log_service(
                        exe_dir,
                        "ERROR",
                        &format!("failed to load opencv models with CPU backend: {:?}", cpu_err),
                    );
                    None
                }
            }
        }
        Err(e) => {
            log_service(
                exe_dir,
                "ERROR",
                &format!("failed to load opencv models with CPU backend: {:?}", e),
            );
            None
        }
    }
}

fn reload_models_if_inference_changed(
    resources: &Path,
    db_path: &Path,
    exe_dir: &Path,
    current: &mut InferenceBackend,
    models: &mut Models,
) {
    let next = load_inference_backend(db_path);
    if next == *current {
        return;
    }

    match load_models_with_fallback(resources, next, exe_dir) {
        Some((new_models, active)) => {
            *models = new_models;
            *current = next;
            log_service(
                exe_dir,
                "INFO",
                &format!(
                    "inference backend changed to {} (active: {})",
                    next.label, active.label
                ),
            );
        }
        None => {
            log_service(
                exe_dir,
                "WARN",
                "inference backend change ignored because model reload failed",
            );
        }
    }
}

/// 检测+提取特征，返回 None 表示无人脸或失败
fn detect_and_extract(models: &mut Models, frame: &Mat) -> Option<Mat> {
    models.detector.set_input_size(Size::new(frame.cols(), frame.rows())).ok()?;
    let mut faces = Mat::default();
    models.detector.detect(frame, &mut faces).ok()?;
    if faces.rows() == 0 { return None; }

    // 克隆第一行（BoxedRef → Mat）以满足 ToInputArray 要求
    let face_row = faces.row(0).ok()?.try_clone().ok()?;

    let mut aligned = Mat::default();
    models.recognizer.align_crop(frame, &face_row, &mut aligned).ok()?;
    let mut feature = Mat::default();
    models.recognizer.feature(&aligned, &mut feature).ok()?;
    Some(feature)
}

// ─── Screen brightness ───────────────────────────────────────────────────────

/// 从 SQLite 读取解锁亮度目标值（0 = 不调节，1-100 = 目标亮度）
fn load_unlock_brightness(db_path: &Path) -> u8 {
    let conn = match Connection::open(db_path) { Ok(c) => c, Err(_) => return 0 };
    if let Ok(mut stmt) = conn.prepare("SELECT val FROM options WHERE key = 'unlockBrightness'") {
        if let Ok(val) = stmt.query_row([], |row| row.get::<_, String>(0)) {
            return val.parse::<u8>().unwrap_or(0);
        }
    }
    0
}

/// 获取当前屏幕亮度（仅支持笔记本内置屏）
fn get_brightness() -> Option<u8> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile", "-NonInteractive", "-Command",
            "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness \
             -ErrorAction SilentlyContinue | Select-Object -First 1).CurrentBrightness",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse::<u8>().ok()
}

/// 设置屏幕亮度（0-100，仅支持笔记本内置屏）
fn set_brightness(level: u8) {
    let cmd = format!(
        "Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods \
         -ErrorAction SilentlyContinue | ForEach-Object {{ $_.WmiSetBrightness(1, {}) }}",
        level
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
        .output();
}

// ─── Camera rotation ─────────────────────────────────────────────────────────

fn load_camera_rotation(db_path: &Path) -> i32 {
    let conn = match Connection::open(db_path) { Ok(c) => c, Err(_) => return 0 };
    if let Ok(mut stmt) = conn.prepare("SELECT val FROM options WHERE key = 'cameraRotation'") {
        if let Ok(val) = stmt.query_row([], |row| row.get::<_, String>(0)) {
            return val.parse().unwrap_or(0);
        }
    }
    0
}

fn load_option_value(db_path: &Path, key: &str) -> Option<String> {
    let conn = Connection::open(db_path).ok()?;
    let mut stmt = conn.prepare("SELECT val FROM options WHERE key = ?1").ok()?;
    let value = stmt.query_row([key], |row| {
        let raw = row.get_ref(0)?;
        let value = match raw {
            ValueRef::Integer(v) => Some(v.to_string()),
            ValueRef::Real(v) if v.is_finite() => Some(v.to_string()),
            ValueRef::Text(v) => std::str::from_utf8(v).ok().map(|s| s.to_string()),
            _ => None,
        };
        Ok(value)
    }).ok()?;
    value
}

fn load_face_recog_type(db_path: &Path) -> String {
    match load_option_value(db_path, "faceRecogType").as_deref() {
        Some("delay") => "delay".to_string(),
        _ => "operation".to_string(),
    }
}

fn load_seconds_option(
    db_path: &Path,
    key: &str,
    default_seconds: f64,
    min_seconds: f64,
    max_seconds: f64,
) -> Duration {
    let seconds = load_option_value(db_path, key)
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .unwrap_or(default_seconds)
        .clamp(min_seconds, max_seconds);
    Duration::from_millis((seconds * 1000.0).round() as u64)
}

fn load_face_recog_delay(db_path: &Path) -> Duration {
    load_seconds_option(db_path, "faceRecogDelay", 10.0, 0.1, 120.0)
}

fn load_retry_delay(db_path: &Path) -> Duration {
    load_seconds_option(db_path, "retryDelay", 1.0, 1.0, 120.0)
}

fn load_not_face_delay(db_path: &Path) -> Duration {
    load_seconds_option(db_path, "notFaceDelay", 3.0, 1.0, 120.0)
}

/// broker "release" 后的冷却时间（毫秒）。
/// 在此期间 Unlock EXE 拒绝新的 "run" 命令和 delay 自动触发，
/// 防止 credentialuibroker.exe 新建进程后重新激活面容识别。
/// 默认 35 秒（CREDUI_BROKER_FALLBACK_TIMEOUT 默认 5s + 30s 余量）。
fn load_broker_release_cooldown(db_path: &Path) -> i64 {
    let secs = load_seconds_option(db_path, "brokerReleaseCooldown", 35.0, 5.0, 120.0);
    (secs.as_secs_f64() * 1000.0) as i64
}

fn inference_backend_from_key(key: &str) -> InferenceBackend {
    match key {
        "opencl" => InferenceBackend {
            key: "opencl",
            label: "OpenCL",
            backend_id: 3,
            target_id: 1,
        },
        "opencl_fp16" => InferenceBackend {
            key: "opencl_fp16",
            label: "OpenCL FP16",
            backend_id: 3,
            target_id: 2,
        },
        "intel_npu" => InferenceBackend {
            key: "intel_npu",
            label: "Intel NPU",
            backend_id: 2,
            target_id: 9,
        },
        _ => CPU_INFERENCE,
    }
}

fn load_inference_backend(db_path: &Path) -> InferenceBackend {
    let conn = match Connection::open(db_path) { Ok(c) => c, Err(_) => return CPU_INFERENCE };
    if let Ok(mut stmt) = conn.prepare("SELECT val FROM options WHERE key = 'inferenceBackend'") {
        if let Ok(val) = stmt.query_row([], |row| row.get::<_, String>(0)) {
            return inference_backend_from_key(val.trim());
        }
    }
    CPU_INFERENCE
}

fn load_camera_index(db_path: &Path) -> Option<i32> {
    let conn = Connection::open(db_path).ok()?;
    let index = conn
        .prepare("SELECT val FROM options WHERE key = 'camera'")
        .ok()?
        .query_row([], |row| {
            let raw = row.get_ref(0)?;
            let index = match raw {
                ValueRef::Integer(v) => i32::try_from(v).ok(),
                ValueRef::Real(v) if v.is_finite() && v >= 0.0 && v <= i32::MAX as f64 => {
                    Some(v as i32)
                }
                ValueRef::Text(v) => std::str::from_utf8(v)
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok()),
                _ => None,
            };
            Ok(index)
        })
        .ok()??;
    (index >= 0).then_some(index)
}

fn configured_camera_index(db_path: &Path) -> i32 {
    load_camera_index(db_path).unwrap_or(0)
}

fn warm_up_camera(cam: &mut VideoCapture) {
    let mut dummy = Mat::default();
    let mut ready_frames = 0usize;

    for _ in 0..CAMERA_WARMUP_MAX_FRAMES {
        if cam.read(&mut dummy).is_ok() && !dummy.empty() {
            ready_frames += 1;
            if ready_frames >= CAMERA_WARMUP_READY_FRAMES {
                break;
            }
        } else {
            ready_frames = 0;
        }
    }
}

fn open_configured_camera(index: i32, exe_dir: &Path) -> Option<(VideoCapture, &'static str)> {
    // 后端顺序必须与 UI 录入端 open_camera(None) 一致。v0.5.3 的 DShow 优先会造成
    // Win10 部分机器录入/解锁帧管线不一致；v0.5.4 的 CAP_ANY 优先又会在 issue #3
    // 的 Win10 机器上阻塞约 40 秒才亮摄像头。这里显式采用 UI 当前顺序并记录耗时，
    // 便于继续区分"打不开"和"某个后端打开过慢"。
    for (backend_name, backend) in [
        ("MSMF", videoio::CAP_MSMF),
        ("DShow", videoio::CAP_DSHOW),
        ("Any", videoio::CAP_ANY),
    ] {
        let started = Instant::now();
        if let Ok(mut c) = VideoCapture::new(index, backend) {
            if c.is_opened().unwrap_or(false) {
                let _ = c.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0);
                let _ = c.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0);
                warm_up_camera(&mut c);
                log_service(
                    exe_dir,
                    "INFO",
                    &format!(
                        "camera backend {} opened in {}ms",
                        backend_name,
                        started.elapsed().as_millis()
                    ),
                );
                return Some((c, backend_name));
            }
        }
        let elapsed_ms = started.elapsed().as_millis();
        if elapsed_ms >= 1000 {
            log_service(
                exe_dir,
                "WARN",
                &format!(
                    "camera backend {} unavailable after {}ms",
                    backend_name, elapsed_ms
                ),
            );
        }
    }
    None
}

/// 旋转帧（rotation: 0/90/180/270）
fn rotate_frame(frame: &Mat, rotation: i32) -> Option<Mat> {
    if rotation == 0 {
        return frame.try_clone().ok();
    }
    let code = match rotation {
        90  => opencv::core::ROTATE_90_CLOCKWISE,
        180 => opencv::core::ROTATE_180,
        270 => opencv::core::ROTATE_90_COUNTERCLOCKWISE,
        _   => return frame.try_clone().ok(),
    };
    let mut rotated = Mat::default();
    opencv::core::rotate(frame, &mut rotated, code).ok()?;
    Some(rotated)
}

// ─── Test-creds file ──────────────────────────────────────────────────────────

fn check_test_creds(exe_dir: &Path) -> Option<(String, String)> {
    let path = exe_dir.join("block").join("test_creds.tmp");
    if !path.exists() { return None; }
    let text = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);

    #[derive(Deserialize)]
    struct Creds { user_name: String, user_pwd: String }
    let c: Creds = serde_json::from_str(&text).ok()?;
    Some((c.user_name, c.user_pwd))
}

// ─── Face recognition loop ────────────────────────────────────────────────────

/// 返回 `secs` 秒之前的时刻；若自系统启动不足 `secs` 秒（开机早期），
/// `checked_sub` 会下溢，此时回退为当前时刻。
/// 修复：Windows 的 `Instant` 自系统启动计时，开机头一分钟内
/// `Instant::now() - Duration::from_secs(60)` 会触发
/// "overflow when subtracting duration from instant" panic，
/// 导致 worker 在开机早期反复崩溃重启（exit 101），烧掉数十秒。
fn instant_secs_ago(secs: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(secs))
        .unwrap_or_else(Instant::now)
}

fn face_recognition_loop(state: Arc<State>, exe_dir: PathBuf) {
    const COLD_BOOT_GRACE_SECS: u64 = 60;
    /// 重锁宽限期：成功面容解锁后若重新锁屏（Win+L 或自动锁屏），
    /// delay 模式在此时间内不触发，防止刚锁屏离开就被立即识别解锁。
    /// 宽限期过后自动启用——用户回来时无需触碰鼠标键盘即可被动解锁。
    const RE_LOCK_GRACE_SECS: i64 = 45;
    let resources = exe_dir.join("resources");
    let db_path   = exe_dir.join("database.db");

    let mut requested_inference = load_inference_backend(&db_path);
    // 延迟按需加载模型，启动时仅创建管道服务器。
    // DLL 可立即连接并发送 prepare/心跳，模型在首次 "run" 时加载——
    // 此时用户已在锁屏界面，GPU/DirectML 等系统组件早已完全初始化，一次加载即成功。
    let mut models: Option<(Models, InferenceBackend)> = None;
    let mut cam: Option<VideoCapture> = None;
    let mut records: Vec<FaceRecord> = vec![];
    let mut last_reload = instant_secs_ago(60);
    let mut camera_index = configured_camera_index(&db_path);
    let mut camera_rotation = load_camera_rotation(&db_path);
    let mut unlock_brightness = load_unlock_brightness(&db_path);
    let mut retry_delay = load_retry_delay(&db_path);
    let mut not_face_delay = load_not_face_delay(&db_path);
    let mut delayed_run_at: Option<Instant> = None;
    let mut delay_session_armed = false;
    let mut last_failed_at: Option<Instant> = None;
    let mut last_model_attempt = instant_secs_ago(5); // 首次尽快尝试（开机早期回退为 now）
    // 摄像头预热（秒解锁）：prewarm_at = 锁屏预开摄像头的时刻；
    // prewarm_suppressed = 空闲超时后抑制预热，直到下次 run（用户到场）或 release（锁屏消失）。
    let mut prewarm_at: Option<Instant> = None;
    let mut prewarm_suppressed = false;

    'main: loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        if state
            .broker_guard_release_requested
            .swap(false, Ordering::SeqCst)
        {
            state.run_requested.store(false, Ordering::SeqCst);
            state.recognition_active.store(false, Ordering::SeqCst);
            *state.matched_creds.lock().unwrap() = None;
            cam = None;
            prewarm_at = None;
            // 关键：抑制预热（=true，而非 false）。WebAuthn 守卫释放意味着当前正在走
            // 原生 passkey——此时若解除预热抑制，且 DLL 凭据连接尚未断开（has_credential_client
            // 仍为 true）、broker_guard_release 又不设冷却，下方预热块会立刻重新打开摄像头、
            // 在 passkey 进行中点亮指示灯（M1），与本特性「passkey 时不亮摄像头」的目标相悖。
            // 抑制到下次真正的 release / 成功识别再解除。
            prewarm_suppressed = true;
            log_service(
                &exe_dir,
                "INFO",
                "generic broker recognition cancelled by WebAuthn guard",
            );
        }

        if state.release_requested.swap(false, Ordering::SeqCst) {
            state.passkey_face_gate.reject_pending();
            cam = None;
            prewarm_at = None;
            prewarm_suppressed = false;
            delayed_run_at = None;
            delay_session_armed = false;
            last_failed_at = None;
            state.dll_run_received.store(false, Ordering::SeqCst);
            log_service(&exe_dir, "INFO", "camera released");
            state.prepare_requested.store(false, Ordering::SeqCst);
            state.run_requested.store(false, Ordering::SeqCst);
            state.recognition_active.store(false, Ordering::SeqCst);
            *state.matched_creds.lock().unwrap() = None;
            continue;
        }

        // 轮询 test_creds.tmp（UI 测试模式）
        if let Some((user, pwd)) = check_test_creds(&exe_dir) {
            *state.matched_creds.lock().unwrap() = Some((user, pwd, ".".to_string()));
            // 等待 DLL 消费（最多 30s）
            for _ in 0..300 {
                thread::sleep(Duration::from_millis(100));
                if state.matched_creds.lock().unwrap().is_none()
                    || state.should_exit.load(Ordering::SeqCst) { break; }
            }
            continue;
        }

        let has_credential_client =
            state.dll_creds_pipe.load(Ordering::SeqCst) != INVALID_HANDLE_VALUE.0 as isize;
        if !has_credential_client && !state.recognition_active.load(Ordering::SeqCst) {
            delayed_run_at = None;
            delay_session_armed = false;
        }

        if state.prepare_requested.swap(false, Ordering::SeqCst) {
            let face_recog_type = load_face_recog_type(&db_path);
            let face_recog_delay = load_face_recog_delay(&db_path);
            retry_delay = load_retry_delay(&db_path);
            not_face_delay = load_not_face_delay(&db_path);
            if records.is_empty() || last_reload.elapsed() > Duration::from_secs(5) {
                records = load_face_records(&exe_dir, &db_path);
                camera_index = configured_camera_index(&db_path);
                camera_rotation = load_camera_rotation(&db_path);
                unlock_brightness = load_unlock_brightness(&db_path);
                if let Some((ref mut m, ref mut inf)) = models.as_mut() {
                    reload_models_if_inference_changed(
                        &resources, &db_path, &exe_dir, inf, m,
                    );
                } else {
                    requested_inference = load_inference_backend(&db_path);
                }
                last_reload = Instant::now();
                log_service(&exe_dir, "INFO", &format!("prepared unlock config for camera {}", camera_index));
            }
            if face_recog_type == "delay" {
                // broker 冷却期内不武装 delay，防止新进程的 "prepare" 重新激活
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                if now_ms < state.after_release_cooldown_until.load(Ordering::SeqCst) {
                    log_service(&exe_dir, "INFO", "delay skipped: broker release cooldown active");
                    continue;
                }
                // delay 模式必须收到 DLL 的显式 "run" 后才允许自动重试。
                // 这确保首次面容识别始终由用户在锁屏界面的鼠标/键盘输入触发，
                // 防止冷启动时 DLL 仅发 "prepare" 就自动开始识别并提交凭据，
                // 导致系统未就绪时桌面加载卡死（白色圆点转圈→强制关机）。
                // 一旦 DLL 发送过 "run"，后续的重试/重新识别由 delay 计时器调度。
                if !delay_session_armed && state.dll_run_received.load(Ordering::SeqCst) {
                    let mut delay_deadline = Instant::now() + face_recog_delay;

                    // 重锁宽限期：成功解锁后若重新锁屏，在 RE_LOCK_GRACE_SECS
                    // 内禁止 delay 自动触发，防止用户刚按 Win+L 离开就被立即识别解锁。
                    // 宽限期过后自动启用——用户离开一段时间后回来即可被动解锁。
                    let last_unlock = state.last_successful_unlock_at.load(Ordering::SeqCst);
                    if last_unlock > 0 {
                        let now_unix = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        let elapsed = now_unix - last_unlock;
                        if elapsed < RE_LOCK_GRACE_SECS {
                            let remaining = (RE_LOCK_GRACE_SECS - elapsed) as u64;
                            let re_lock_deadline = Instant::now() + Duration::from_secs(remaining);
                            if re_lock_deadline > delay_deadline {
                                delay_deadline = re_lock_deadline;
                                log_service(
                                    &exe_dir,
                                    "INFO",
                                    &format!(
                                        "re-lock grace period: {}s since last unlock < {}s, \
                                         deferring by {}s",
                                        elapsed, RE_LOCK_GRACE_SECS, remaining,
                                    ),
                                );
                            }
                        }
                    }

                    // 连续失败退避：基于距上次失败的时间，而非从现在起算。
                    // 冷却 = face_recog_delay × 2^min(failures, 4)，封顶 16×。
                    // 若用户已离开很久（冷却早已过期），立即重试。
                    // 防止无人时摄像头反复打开跑 DNN 推理导致风扇狂转、电池耗尽。
                    let failures = state.consecutive_failures.load(Ordering::SeqCst);
                    if failures > 0 {
                        if let Some(ref failed_at) = last_failed_at {
                            let backoff_mult = 1u32 << failures.min(4); // 1,2,4,8,16
                            let backoff = (face_recog_delay * backoff_mult)
                                .max(Duration::from_secs(30));
                            let elapsed = failed_at.elapsed();
                            if elapsed < backoff {
                                let remaining = backoff - elapsed;
                                let backoff_deadline =
                                    Instant::now() + remaining;
                                if backoff_deadline > delay_deadline {
                                    delay_deadline = backoff_deadline;
                                    log_service(
                                        &exe_dir,
                                        "INFO",
                                        &format!(
                                            "delay backoff: {} consecutive failures, \
                                             {:.0}s elapsed, cooldown {:.0}s, \
                                             remaining {:.0}s",
                                            failures,
                                            elapsed.as_secs_f64(),
                                            backoff.as_secs_f64(),
                                            remaining.as_secs_f64(),
                                        ),
                                    );
                                }
                            }
                        }
                    }

                    // 冷启动保护：系统启动不足 COLD_BOOT_GRACE_SECS 秒时，
                    // 推迟面容识别至保护期结束后，避免开机早期 GPU/系统组件未就绪
                    // 导致模型加载失败或识别异常（exit 101 / 崩溃重启循环）。
                    // Windows 上 Instant 从系统启动计时，
                    // checked_sub(COLD_BOOT_GRACE_SECS) 失败即运行时间不足保护期。
                    if Instant::now()
                        .checked_sub(Duration::from_secs(COLD_BOOT_GRACE_SECS))
                        .is_none()
                    {
                        // 估算实际运行秒数：反向探测 checked_sub 的最大成功点
                        let now = Instant::now();
                        let uptime_secs = (0..COLD_BOOT_GRACE_SECS)
                            .rev()
                            .find_map(|s| {
                                now.checked_sub(Duration::from_secs(s))
                                    .map(|_| s)
                            })
                            .unwrap_or(0);
                        let remaining = COLD_BOOT_GRACE_SECS - uptime_secs;
                        let grace_deadline = Instant::now() + Duration::from_secs(remaining);
                        if grace_deadline > delay_deadline {
                            delay_deadline = grace_deadline;
                            log_service(
                                &exe_dir,
                                "INFO",
                                &format!(
                                    "cold boot protection: uptime ~{}s < grace {}s, deferring \
                                     face recognition by {}s",
                                    uptime_secs, COLD_BOOT_GRACE_SECS, remaining,
                                ),
                            );
                        }
                    }

                    delayed_run_at = Some(delay_deadline);
                    delay_session_armed = true;
                    log_service(
                        &exe_dir,
                        "INFO",
                        &format!(
                            "delayed face recognition scheduled after {:.1}s",
                            (delay_deadline.saturating_duration_since(Instant::now()))
                                .as_secs_f64()
                        ),
                    );
                }
            } else {
                delayed_run_at = None;
                delay_session_armed = false;
            }
        }

        if let Some(deadline) = delayed_run_at {
            if Instant::now() >= deadline && !state.recognition_active.load(Ordering::SeqCst) {
                delayed_run_at = None;
                state.release_requested.store(false, Ordering::SeqCst);
                state.run_requested.store(true, Ordering::SeqCst);
                log_service(&exe_dir, "INFO", "run requested by delayed recognition mode");
            }
        }

        // 后台尝试加载模型（每 1 秒一次），不阻塞管道响应。
        // 启动时 GPU 可能未就绪，周期性重试直到成功。
        // 加载成功后 `models.is_some()` 跳过此块，零开销。
        if models.is_none() && last_model_attempt.elapsed() >= Duration::from_secs(1) {
            last_model_attempt = Instant::now();
            if let Some(loaded) =
                load_models_with_fallback(&resources, requested_inference, &exe_dir)
            {
                models = Some(loaded);
                log_service(&exe_dir, "INFO", "models loaded in background");
            }
        }

        // ── 摄像头预热（秒解锁）──────────────────────────────────────────────
        // 锁屏/凭据界面活跃时提前打开摄像头，使随后用户动鼠标发的 "run" 秒识别，不必再等
        // MSMF 打开摄像头的 2-3s。只【打开摄像头 + 预热帧】，绝不跑人脸识别（无 DNN 推理、
        // 不耗 CPU，不违反 #115「锁屏后风扇狂转」）。安全兜底：预热后 PREWARM_IDLE_TIMEOUT
        // 内若无 "run"（无人到场）则释放摄像头并抑制预热（关指示灯、省电），直到收到 run 或
        // release；有连续失败（可能无人）或 broker 释放冷却期内不预热。
        {
            let pending = state.run_requested.load(Ordering::SeqCst)
                || state.passkey_face_gate.pending_request_id().is_some();
            let recognizing = state.recognition_active.load(Ordering::SeqCst);
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let broker_cooldown = now_ms < state.after_release_cooldown_until.load(Ordering::SeqCst);
            if prewarm_at.is_none()
                && !prewarm_suppressed
                && has_credential_client
                && cam.is_none()
                && !pending
                && !recognizing
                && !broker_cooldown
                // UI 正用摄像头（录入/预览）时不预热，把摄像头让给 UI，修复录入采集黑屏。
                && now_ms >= state.camera_yield_until.load(Ordering::SeqCst)
                && state.consecutive_failures.load(Ordering::SeqCst) == 0
                // 有关闭/释放请求待处理时不启动预热打开（open_configured_camera 阻塞 2-3s）：
                // 让主循环尽快在下一轮响应 should_exit/release，避免关机/解锁被这次预热拖 2-3s。
                && !state.should_exit.load(Ordering::SeqCst)
                && !state.release_requested.load(Ordering::SeqCst)
            {
                if let Some((c, backend_name)) = open_configured_camera(camera_index, &exe_dir) {
                    cam = Some(c);
                    prewarm_at = Some(Instant::now());
                    log_service(
                        &exe_dir,
                        "INFO",
                        &format!("camera pre-warmed on lock via {} (秒解锁预开)", backend_name),
                    );
                } else {
                    // 预热打开失败（摄像头被占用/不存在）：抑制预热，避免每轮循环反复尝试打开、
                    // 刷屏日志、空耗 CPU（code-review 发现）。用户真正动鼠标触发 "run" 时仍会在
                    // 识别路径再尝试打开；release/成功识别会解除抑制。
                    prewarm_suppressed = true;
                }
            }
            if let Some(t) = prewarm_at {
                if !pending && !recognizing && t.elapsed() > PREWARM_IDLE_TIMEOUT {
                    cam = None;
                    prewarm_at = None;
                    prewarm_suppressed = true;
                    log_service(&exe_dir, "INFO", "camera pre-warm idle timeout, released (省电)");
                }
            }
        }

        let passkey_request_id = state.passkey_face_gate.pending_request_id();
        let normal_run_requested = if passkey_request_id.is_none() {
            state.run_requested.swap(false, Ordering::SeqCst)
        } else {
            false
        };
        if passkey_request_id.is_none() && !normal_run_requested {
            thread::sleep(Duration::from_millis(30));
            continue;
        }

        if passkey_request_id.is_none() {
            if let Some(failed_at) = last_failed_at {
            let elapsed = failed_at.elapsed();
            if elapsed < retry_delay {
                let remaining_ms = retry_delay.saturating_sub(elapsed).as_millis();
                log_service(
                    &exe_dir,
                    "INFO",
                    &format!("run ignored by retry delay, remaining {}ms", remaining_ms),
                );
                thread::sleep(Duration::from_millis(30));
                continue;
            }
            }
        }
        state.recognition_active.store(true, Ordering::SeqCst);
        // 进入识别：用户已到场——清预热标记并解除抑制。本次识别复用锁屏预开的摄像头（line
        // "if cam.is_none()" 处 cam 已 Some → 跳过 2-3s 打开 → 秒识别）；下一轮锁屏仍可预热。
        prewarm_at = None;
        prewarm_suppressed = false;

        // 定期重新加载人脸记录和配置
        if records.is_empty() || last_reload.elapsed() > Duration::from_secs(30) {
            records = load_face_records(&exe_dir, &db_path);
            camera_index = configured_camera_index(&db_path);
            camera_rotation = load_camera_rotation(&db_path);
            unlock_brightness = load_unlock_brightness(&db_path);
            retry_delay = load_retry_delay(&db_path);
            not_face_delay = load_not_face_delay(&db_path);
            if let Some((ref mut m, ref mut inf)) = models.as_mut() {
                reload_models_if_inference_changed(
                    &resources, &db_path, &exe_dir, inf, m,
                );
            }
            last_reload = Instant::now();
        }
        if records.is_empty() {
            log_service(&exe_dir, "WARN", "run requested but no enabled face records found");
            if let Some(request_id) = passkey_request_id {
                state.passkey_face_gate.reject(request_id);
            } else {
                state.run_requested.store(false, Ordering::SeqCst);
            }
            state.recognition_active.store(false, Ordering::SeqCst);
            cam = None;
            continue;
        }

        // 收到 "run" 但模型尚未加载（后台加载可能还未成功）。
        // 不放弃本次 run —— 内联重试 500ms × 20 次（10 秒），覆盖 GPU 初始化延迟。
        // 与后台加载协同：后台加载成功后此处直接跳过；若后台尚未成功则在此快速重试。
        if models.is_none() {
            'load_models: {
                for i in 0..20 {
                    match load_models_with_fallback(&resources, requested_inference, &exe_dir) {
                        Some(loaded) => {
                            models = Some(loaded);
                            log_service(&exe_dir, "INFO", &format!("models loaded on run (attempt {})", i + 1));
                            break 'load_models;
                        }
                        None => {
                            log_service(
                                &exe_dir, "WARN",
                                &format!("model loading, retry {}/20", i + 1),
                            );
                            thread::sleep(Duration::from_millis(500));
                        }
                    }
                }
                // 10 秒内仍未就绪——放弃本次 run，下次 run 会再试
                log_service(&exe_dir, "WARN", "model not ready after 20 retries, deferring run");
                if let Some(request_id) = passkey_request_id {
                    state.passkey_face_gate.reject(request_id);
                } else {
                    state.run_requested.store(false, Ordering::SeqCst);
                }
                state.recognition_active.store(false, Ordering::SeqCst);
                continue 'main;
            }
        }

        // 打开首选项中保存的摄像头索引，避免每次解锁都扫描 0-3 号设备。
        if cam.is_none() {
            if let Some((c, backend_name)) = open_configured_camera(camera_index, &exe_dir) {
                cam = Some(c);
                log_service(
                    &exe_dir,
                    "INFO",
                    &format!("camera opened at configured index {} via {}", camera_index, backend_name),
                );
            }
        }
        // 解锁前提升屏幕亮度（仅笔记本内置屏），识别结束后恢复
        let saved_brightness = if unlock_brightness > 0 {
            let orig = get_brightness();
            set_brightness(unlock_brightness);
            orig
        } else {
            None
        };

        // 识别循环：无脸时按 UI 配置超时；有人脸但不匹配时保留硬上限，避免持续占用摄像头。
        // 摄像头冷启动时首帧偏暗/传感器未就绪，首轮识别可能无人脸。
        // 允许最多 3 轮内部重试（无需 DLL 重发 "run"），消除 Chrome CREDUI 等场景的"第一次失败，第二次成功"问题。
        const MAX_NO_FACE_RETRIES: u32 = 3;
        let mut matched = false;
        let mut matched_face_id: Option<i64> = None;
        let mut saw_face = false;
        let mut no_face_retries = 0u32;

        while no_face_retries < MAX_NO_FACE_RETRIES {
            if state.should_exit.load(Ordering::SeqCst)
                || state.release_requested.load(Ordering::SeqCst)
                || (passkey_request_id.is_none()
                    && state.broker_guard_release_requested.load(Ordering::SeqCst))
            {
                break;
            }

            // 每轮重新获取 cam 引用（块结束后 borrow 自动释放，允许后续 cam = None）
            // 首轮使用已打开的 cam，重试轮从重新打开的 cam 获取
            saw_face = false;
            {
                let cap = match cam.as_mut() {
                    Some(c) => c,
                    None => {
                        log_service(&exe_dir, "ERROR", "camera not available for recognition round");
                        break;
                    }
                };

                let hard_deadline = Instant::now() + Duration::from_secs(10);
                let mut no_face_since: Option<Instant> = None;
                while Instant::now() < hard_deadline {
                    if state.should_exit.load(Ordering::SeqCst)
                        || state.release_requested.load(Ordering::SeqCst)
                        || (passkey_request_id.is_none()
                            && state.broker_guard_release_requested.load(Ordering::SeqCst))
                    {
                        break;
                    }
                    let mut frame = Mat::default();
                    if cap.read(&mut frame).is_err() || frame.empty() {
                        let since = no_face_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= not_face_delay {
                            log_service(&exe_dir, "INFO", "no usable camera frame timeout reached");
                            break;
                        }
                        thread::sleep(Duration::from_millis(30));
                        continue;
                    }
                    let frame = rotate_frame(&frame, camera_rotation).unwrap_or(frame);

                    let (ref mut m, _) = models.as_mut().expect("models loaded before run");
                    let cam_feat = match detect_and_extract(m, &frame) {
                        Some(f) => f,
                        None => {
                            let since = no_face_since.get_or_insert_with(Instant::now);
                            if since.elapsed() >= not_face_delay {
                                log_service(&exe_dir, "INFO", "no face detected timeout reached");
                                break;
                            }
                            thread::sleep(Duration::from_millis(30));
                            continue;
                        }
                    };
                    no_face_since = None;
                    saw_face = true;
                    let cam_bytes = feature_to_bytes(&cam_feat);

                    for rec in &records {
                        let score = cosine_sim(&cam_bytes, &rec.feature_bytes);
                        let threshold = rec.threshold as f64 / 100.0;
                        if score >= threshold {
                            if passkey_request_id.is_some() {
                                log_service(
                                    &exe_dir,
                                    "INFO",
                                    &format!("face matched for passkey authorization: {}", rec.user_name),
                                );
                            } else {
                                *state.matched_creds.lock().unwrap() = Some((
                                    rec.user_name.clone(),
                                    rec.user_pwd.clone(),
                                    rec.domain.clone(),
                                ));
                                log_service(&exe_dir, "INFO", &format!("face matched for {}", rec.user_name));
                            }
                            matched_face_id = Some(rec.id);
                            // 更新活跃时间：人脸识别成功说明用户在
                            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
                            state.last_user_active.store(now, Ordering::SeqCst);
                            if passkey_request_id.is_none() {
                                state.last_successful_unlock_at.store(now, Ordering::SeqCst);
                            }
                            matched = true;
                            // 仅提交密码凭据（Approach B）——所有场景统一走密码，登录/解锁秒过，
                            // CredUI 被拒时由 DLL 回退 Windows 原生 PIN。不再加载/注入存储 PIN。
                            break;
                        }
                    }
                    if matched { break; }
                    thread::sleep(Duration::from_millis(30));
                }
            } // cap 在这里释放，cam borrow 结束

            if matched || saw_face { break; }
            // 无人脸：摄像头可能尚未预热，内部重试
            no_face_retries += 1;
            if no_face_retries < MAX_NO_FACE_RETRIES {
                log_service(&exe_dir, "INFO", &format!("no face in round {}, retrying ({}/{})", no_face_retries, no_face_retries + 1, MAX_NO_FACE_RETRIES));
                // 释放当前摄像头后重开，获取新数据流（take() 取出旧值并 drop，显式释放）
                drop(cam.take());
                if let Some((c, backend_name)) = open_configured_camera(camera_index, &exe_dir) {
                    cam = Some(c);
                    log_service(&exe_dir, "INFO", &format!("camera reopened for retry via {}", backend_name));
                } else {
                    log_service(&exe_dir, "ERROR", "failed to reopen camera for retry");
                    break;
                }
            }
        }

        // 识别结束，恢复原始亮度
        if let Some(orig) = saved_brightness {
            set_brightness(orig);
        }

        let broker_guard_cancelled = passkey_request_id.is_none()
            && state
                .broker_guard_release_requested
                .swap(false, Ordering::SeqCst);

        if let Some(request_id) = passkey_request_id {
            if matched {
                if state.passkey_face_gate.authorize(request_id) {
                    log_service(&exe_dir, "INFO", "passkey face authorization granted");
                } else {
                    log_service(&exe_dir, "WARN", "passkey face authorization expired before match");
                }
            } else if state.passkey_face_gate.reject(request_id) {
                log_service(&exe_dir, "WARN", "passkey face authorization rejected");
            }
        } else if broker_guard_cancelled {
            state.run_requested.store(false, Ordering::SeqCst);
            *state.matched_creds.lock().unwrap() = None;
            log_service(
                &exe_dir,
                "INFO",
                "generic broker recognition stopped before credential submission",
            );
        } else {
            if matched {
                insert_unlock_log(&db_path, &exe_dir, matched_face_id, true, None);
                last_failed_at = None;
                state.run_requested.store(false, Ordering::SeqCst);
                state.consecutive_failures.store(0, Ordering::SeqCst);
                // 重置 delay 状态，确保下次锁屏时能重新布防。
                delayed_run_at = None;
                delay_session_armed = false;
            } else if !state.release_requested.load(Ordering::SeqCst) {
                if saw_face {
                    insert_unlock_log(&db_path, &exe_dir, None, false, None);
                }
                last_failed_at = Some(Instant::now());
                // 递增连续失败计数，用于 delay 退避。
                let fails = state.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                // 重置 delay 状态，允许下次 prepare 心跳重新布防。
                delayed_run_at = None;
                delay_session_armed = false;
                log_service(&exe_dir, "WARN", &format!(
                    "face recognition finished without a match (consecutive failures: {fails})"
                ));
            }
            state.run_requested.store(false, Ordering::SeqCst);
        }
        state.recognition_active.store(false, Ordering::SeqCst);
        cam = None;
    }
}

// ─── Auto-lock monitor ──────────────────────────────────────────────────────────

/// 从 options 表读取自动锁屏配置
fn load_auto_lock_settings(db_path: &Path) -> (bool, u64) {
    let conn = match Connection::open(db_path) { Ok(c) => c, Err(_) => return (false, 300) };
    let mut enabled = false;
    let mut timeout: u64 = 300;

    // 读取 autoLockEnabled (字符串 "true"/"false")
    if let Ok(mut stmt) = conn.prepare("SELECT val FROM options WHERE key = 'autoLockEnabled'") {
        if let Ok(val) = stmt.query_row([], |row| row.get::<_, String>(0)) {
            enabled = val == "true";
        }
    }
    // 读取 autoLockTimeout (秒，字符串数字)
    if let Ok(mut stmt) = conn.prepare("SELECT val FROM options WHERE key = 'autoLockTimeout'") {
        if let Ok(val) = stmt.query_row([], |row| row.get::<_, String>(0)) {
            timeout = val.parse().unwrap_or(300);
        }
    }

    (enabled, timeout)
}

/// 获取系统空闲时间（毫秒）
fn get_idle_millis() -> u32 {
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe { let _ = GetLastInputInfo(&mut lii); }
    let tick = unsafe { windows::Win32::System::SystemInformation::GetTickCount() };
    tick.wrapping_sub(lii.dwTime)
}

/// 自动锁屏监控线程
fn auto_lock_monitor(state: Arc<State>, exe_dir: PathBuf) {
    let db_path = exe_dir.join("database.db");
    let resources = exe_dir.join("resources");

    // 首次加载设置
    let (mut auto_lock_enabled, mut auto_lock_timeout) = load_auto_lock_settings(&db_path);
    let mut last_config_check = Instant::now();

    // 延迟加载模型（按需，避免内存浪费）
    let mut models: Option<Models> = None;
    let mut records: Vec<FaceRecord> = vec![];
    let mut last_record_reload = instant_secs_ago(60);
    let mut camera_rotation = load_camera_rotation(&db_path);
    let mut requested_inference = load_inference_backend(&db_path);
    // 授权冷却：人脸授权成功后这段时间内不再开摄像头。
    // 根因：授权只更新 state.last_user_active，但不会重置 OS 的 GetLastInputInfo；
    // 用户长时间不碰键鼠（看屏幕、读网页、盯终端）时，下一轮 OS idle 仍超时 → 又开摄像头。
    // 冷却时长取 max(60s, autoLockTimeout)：用户在场时按其设定的检测间隔周期性复查，
    // 而非固定每 60s 一次，把空闲期间摄像头亮起频率降到与 autoLockTimeout 一致（通常 5 分钟）。
    const AUTH_COOLDOWN_MIN: Duration = Duration::from_secs(60);
    let mut auth_cooldown_until: Option<Instant> = None;

    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }
        thread::sleep(Duration::from_secs(1));

        // 每 30 秒重新读取设置
        if last_config_check.elapsed() > Duration::from_secs(30) {
            let (enabled, timeout) = load_auto_lock_settings(&db_path);
            auto_lock_enabled = enabled;
            auto_lock_timeout = timeout;
            camera_rotation = load_camera_rotation(&db_path);
            if let Some(model_set) = models.as_mut() {
                reload_models_if_inference_changed(
                    &resources,
                    &db_path,
                    &exe_dir,
                    &mut requested_inference,
                    model_set,
                );
            } else {
                requested_inference = load_inference_backend(&db_path);
            }
            last_config_check = Instant::now();
        }

        if !auto_lock_enabled { continue; }

        // 屏幕已锁（凭据提供程序活跃、DLL creds 管道已连）时不再自动锁屏：既避免对已锁屏幕
        // 重复锁定，也避免与解锁端「摄像头预热」抢占摄像头（autoLockTimeout 小于预热空闲超时
        // 时二者会争用同一摄像头，导致本复查开摄像头失败）。屏幕已锁时自动锁屏本就无意义。
        if state.dll_creds_pipe.load(Ordering::SeqCst) != INVALID_HANDLE_VALUE.0 as isize {
            continue;
        }

        let idle_ms = get_idle_millis();
        if idle_ms < (auto_lock_timeout * 1000) as u32 {
            // 用户有真实键鼠输入，更新活跃时间并清空授权冷却（OS idle 已被真正重置）
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            state.last_user_active.store(now, Ordering::SeqCst);
            auth_cooldown_until = None;
            continue;
        }

        // 空闲超时，且没有正在进行的解锁请求（避免冲突）
        if state.run_requested.load(Ordering::SeqCst) { continue; }

        // UI 正用摄像头（录入/预览）时不开摄像头做在场检测，把摄像头让给 UI（防抢占黑屏）。
        {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            if now_ms < state.camera_yield_until.load(Ordering::SeqCst) { continue; }
        }

        // 加载模型（仅首次）
        if models.is_none() {
            models = load_models_with_fallback(&resources, requested_inference, &exe_dir)
                .map(|(loaded, _)| loaded);
        }
        let models = match models.as_mut() { Some(m) => m, None => continue };

        // 重新加载人脸记录
        if last_record_reload.elapsed() > Duration::from_secs(60) {
            records = load_face_records(&exe_dir, &db_path);
            last_record_reload = Instant::now();
        }
        if records.is_empty() { continue; } // 无人脸记录，不锁屏

        // 授权冷却期内不开摄像头（修闪烁）：人脸授权成功后冷却期内，即使 OS idle 仍超时
        // 也跳过——人脸识别不会重置 GetLastInputInfo，否则会反复开摄像头闪烁。
        if let Some(until) = auth_cooldown_until {
            if Instant::now() < until { continue; }
            auth_cooldown_until = None;
        }

        // broker 冷却期内不打开摄像头
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        if now_ms < state.after_release_cooldown_until.load(Ordering::SeqCst) {
            continue;
        }

        // 打开摄像头做一次验证（最多 15 帧 ≈ 2~3 秒）。
        // 关键：这里开摄像头是「自动锁屏空闲复查在场」触发的，与凭据提供程序的 "run" 无关。
        // 必须写日志，否则用户只看到摄像头亮、unlock.log 却空白，无从判断是 auto-lock 正常工作
        // 还是异常调用（排障史：曾因这里没日志，误以为「非人脸场景乱亮摄像头」是 bug）。
        log_service(
            &exe_dir,
            "INFO",
            &format!(
                "auto-lock: idle {}s >= timeout {}s, opening camera to verify presence",
                idle_ms / 1000,
                auto_lock_timeout
            ),
        );
        let mut cam: Option<VideoCapture> = None;
        let camera_index = configured_camera_index(&db_path);
        if let Some((c, backend_name)) = open_configured_camera(camera_index, &exe_dir) {
            log_service(&exe_dir, "INFO", &format!("auto-lock: camera opened via {}", backend_name));
            cam = Some(c);
        }
        let cap = match cam.as_mut() {
            Some(c) => c,
            None => {
                log_service(&exe_dir, "WARN", "auto-lock: failed to open camera, skip this check");
                continue;
            }
        };

        let mut authorized = false;
        for _ in 0..15 {
            if state.should_exit.load(Ordering::SeqCst) { break; }
            // 中途用户回来操作了
            if get_idle_millis() < 500 { authorized = true; break; }

            let mut frame = Mat::default();
            if cap.read(&mut frame).is_err() || frame.empty() {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            let frame = rotate_frame(&frame, camera_rotation).unwrap_or(frame);

            if let Some(feat) = detect_and_extract(models, &frame) {
                let cam_bytes = feature_to_bytes(&feat);
                for rec in &records {
                    let score = cosine_sim(&cam_bytes, &rec.feature_bytes);
                    let threshold = rec.threshold as f64 / 100.0;
                    if score >= threshold {
                        authorized = true;
                        break;
                    }
                }
            }
            if authorized { break; }
        }
        // 释放摄像头
        drop(cam);

        if authorized {
            // 授权用户在场，更新活跃时间并进入授权冷却：下一轮 OS idle 仍会超时
            // （人脸识别不重置 GetLastInputInfo），冷却避免反复开摄像头闪烁。
            // 冷却时长 = max(60s, autoLockTimeout)：在场时按用户设定的检测间隔周期复查，
            // 而非固定每 60s，把空闲期间摄像头亮起频率降到与检测间隔一致。
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            state.last_user_active.store(now, Ordering::SeqCst);
            let cooldown = AUTH_COOLDOWN_MIN.max(Duration::from_secs(auto_lock_timeout));
            auth_cooldown_until = Some(Instant::now() + cooldown);
            log_service(
                &exe_dir,
                "INFO",
                &format!("auto-lock: authorized user present, next presence check in {}s", cooldown.as_secs()),
            );
        } else {
            // 无人或非授权人员 → 锁屏，清空授权冷却（锁屏后下次需重新识别）
            log_service(&exe_dir, "INFO", "auto-lock: no authorized face, locking workstation");
            auth_cooldown_until = None;
            // LockWorkStation 是异步"请求"且可能静默失败（返回错误、组策略
            // DisableLockWorkstation 禁锁等）。旧实现忽略返回值也不验证结果（issue #27：
            // 日志已写 "locking workstation" 但电脑没锁），失败后 5s 一轮的复查循环
            // 每 7-8 秒开一次摄像头死循环。现在：检查返回值 + 轮询输入桌面确认真锁上，
            // 最多重试 3 次；仍失败写 ERROR 日志并退避 60s。
            let mut locked = false;
            for attempt in 1..=3u32 {
                if let Err(e) = unsafe { LockWorkStation() } {
                    log_service(&exe_dir, "WARN", &format!(
                        "auto-lock: LockWorkStation failed (attempt {attempt}): {e:?}"
                    ));
                }
                // 锁定请求异步生效：轮询输入桌面最多 2s 确认已切到 secure desktop
                for _ in 0..10 {
                    thread::sleep(Duration::from_millis(200));
                    if is_workstation_locked() { locked = true; break; }
                }
                if locked { break; }
                log_service(&exe_dir, "WARN", &format!(
                    "auto-lock: workstation still unlocked after attempt {attempt}"
                ));
            }
            if locked {
                log_service(&exe_dir, "INFO", "auto-lock: workstation locked");
                // 锁屏后等 5 秒再继续检查
                thread::sleep(Duration::from_secs(5));
            } else {
                let hint = if lock_workstation_disabled_by_policy() {
                    "; DisableLockWorkstation policy is set — Windows forbids locking on this system"
                } else {
                    ""
                };
                log_service(&exe_dir, "ERROR", &format!(
                    "auto-lock: failed to lock workstation after 3 attempts{hint}; next attempt in 60s"
                ));
                // 复用授权冷却做失败退避，避免每 7-8s 开摄像头复查的死循环
                auth_cooldown_until = Some(Instant::now() + Duration::from_secs(60));
            }
        }
    }
}

/// 当前输入桌面是否已切离 "Default"（锁定后为 Winlogon secure desktop）。
/// 打不开输入桌面（锁定状态下常见 ACCESS_DENIED）也视为已锁定。
fn is_workstation_locked() -> bool {
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, UOI_NAME,
        DESKTOP_READOBJECTS, DESKTOP_CONTROL_FLAGS,
    };
    unsafe {
        let desk = match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) {
            Ok(d) => d,
            Err(_) => return true,
        };
        let mut name = [0u16; 64];
        let mut needed = 0u32;
        let ok = GetUserObjectInformationW(
            HANDLE(desk.0),
            UOI_NAME,
            Some(name.as_mut_ptr() as *mut _),
            (name.len() * 2) as u32,
            Some(&mut needed),
        )
        .is_ok();
        let _ = CloseDesktop(desk);
        if !ok {
            return true;
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        !String::from_utf16_lossy(&name[..end]).eq_ignore_ascii_case("default")
    }
}

/// 组策略是否禁用了工作站锁定（HKCU/HKLM ...\Policies\System\DisableLockWorkstation=1）。
/// 优化工具/精简系统常设此策略，是 LockWorkStation 静默失败的常见原因（issue #27 诊断提示）。
fn lock_workstation_disabled_by_policy() -> bool {
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
    };
    let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\0"
        .encode_utf16()
        .collect();
    let value: Vec<u16> = "DisableLockWorkstation\0".encode_utf16().collect();
    for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let mut data: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                root,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut data as *mut u32 as *mut std::ffi::c_void),
                Some(&mut size),
            )
        };
        if status.is_ok() && data == 1 {
            return true;
        }
    }
    false
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/// 诊断：捕获本进程任意线程的 panic，把确切位置与原因写入 unlock.log。
/// 用于定位 worker 在开机早期反复崩溃（exit 101）的根因。
fn install_panic_logger(exe_dir: PathBuf) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic>".to_string());
        let thread = std::thread::current().name().unwrap_or("<unnamed>").to_string();
        log_service(
            &exe_dir,
            "ERROR",
            &format!("WORKER PANIC @ {location} [thread {thread}]: {payload}"),
        );
        previous(info);
    }));
}

fn run_service_worker(exe_dir: PathBuf) -> i32 {
    install_panic_logger(exe_dir.clone());

    let _single_instance = match acquire_single_instance_mutex(&exe_dir) {
        Some(handle) => handle,
        None => return 0,
    };

    let state = State::new(exe_dir.clone());
    log_service(&exe_dir, "INFO", "FaceWinUnlock service worker started");

    let s1 = state.clone();
    thread::spawn(move || run_control_server(s1));

    let s2 = state.clone();
    thread::spawn(move || run_unlock_server(s2));

    let s3 = state.clone();
    let dir2 = exe_dir.clone();
    thread::spawn(move || auto_lock_monitor(s3, dir2));

    let s4 = state.clone();
    thread::spawn(move || run_passkey_face_server(s4));

    let s5 = state.clone();
    let dir3 = exe_dir.clone();
    thread::spawn(move || webauthn_activity::run(s5, dir3));

    face_recognition_loop(state, exe_dir);
    0
}

fn run_service_supervisor(exe_dir: PathBuf) {
    let _single_instance = match acquire_named_mutex(
        &exe_dir,
        "Global\\FaceWinUnlockTauriSupervisor",
        "another FaceWinUnlock supervisor instance is already running; exiting",
    ) {
        Some(handle) => handle,
        None => return,
    };

    log_service(&exe_dir, "INFO", "FaceWinUnlock supervisor started");
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            log_service(&exe_dir, "ERROR", &format!("unable to resolve current exe for supervisor: {e}"));
            return;
        }
    };

    // 重启退避：worker 若存活 >= STABLE_RUN 视为已稳定，崩溃后用最小间隔快速拉起；
    // 若开机早期/配置错误导致"启动即崩"，则指数退避至上限，避免疯狂重启刷爆日志、
    // 空耗 CPU、磨损磁盘（本次 Instant 下溢曾在 30s 内崩溃约 120 次、日志暴涨 4 倍）。
    const MIN_BACKOFF: Duration = Duration::from_millis(250);
    const MAX_BACKOFF: Duration = Duration::from_secs(10);
    const STABLE_RUN: Duration = Duration::from_secs(30);
    let mut backoff = MIN_BACKOFF;

    loop {
        let started = Instant::now();
        match ProcessCommand::new(&exe).arg(WORKER_ARG).spawn() {
            Ok(mut child) => match child.wait() {
                Ok(status) if status.success() => {
                    log_service(&exe_dir, "INFO", "service worker exited normally; supervisor stopping");
                    break;
                }
                Ok(status) => {
                    log_service(&exe_dir, "WARN", &format!("service worker exited with {status}"));
                }
                Err(e) => {
                    log_service(&exe_dir, "WARN", &format!("failed waiting for service worker: {e}"));
                }
            },
            Err(e) => {
                log_service(&exe_dir, "ERROR", &format!("failed to spawn service worker: {e}"));
            }
        }
        // 存活够久 => 偶发崩溃，重置退避；否则（启动即崩）指数增长，封顶 MAX_BACKOFF。
        if started.elapsed() >= STABLE_RUN {
            backoff = MIN_BACKOFF;
        }
        log_service(
            &exe_dir,
            "WARN",
            &format!("restarting service worker in {:.1}s", backoff.as_secs_f64()),
        );
        thread::sleep(backoff);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn main() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    // OpenCL kernel tuning 缓存目录（issue #3）：不设此目录，OpenCV 的 ocl4dnn 每次 forward
    // 都会对卷积层重新做 OpenCL kernel 编译 + auto-tuning —— OpenCL/FP16 后端首次推理可达
    // ~90s，且因结果不持久化，**每次解锁都重复**（用户反馈锁屏转圈 90 秒不解锁）。指向一个
    // 已存在、可写、持久的目录后，只有首次 tuning 慢，后续从缓存秒加载。必须在任何 OpenCV
    // OpenCL 调用前设置。SYSTEM 服务用 ProgramData（SYSTEM 可写且重启后保留）。
    {
        let ocl_cache = PathBuf::from(
            std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()),
        )
        .join("facewinunlock-tauri")
        .join("ocl_cache");
        if std::fs::create_dir_all(&ocl_cache).is_ok() {
            std::env::set_var("OPENCV_OCL4DNN_CONFIG_PATH", &ocl_cache);
        }
    }

    // MSMF 摄像头后端在部分 Win10 上打开极慢（issue #3：ViCrack 日志实测 MSMF open 41011ms /
    // 39756ms ≈ 40 秒摄像头才亮）。根因是 OpenCV MSMF 默认启用的硬件帧变换（HW transforms）在这些
    // 机器上初始化挂起。关掉它让 MSMF 打开恢复正常速度，同时**保留 MSMF 后端**——录入端也走 MSMF，
    // 特征空间一致，不必退回 DShow（会造成"检测到脸但匹配不上"）。必须在任何 VideoCapture 打开前设置。
    std::env::set_var("OPENCV_VIDEOIO_MSMF_ENABLE_HW_TRANSFORMS", "0");

    // ── NGC 解密链 Smoke Test（CLI 模式）────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let is_cli_mode = args.iter().any(|a| a == "--ngc-smoke-test" || a == "--ngc-probe" || a == "--ngc-dump" || a == "--ngc-keys" || a == "--ngc-enum-cng" || a == "--ngc-sign-probe" || a == "--ngc-container-dump" || a == "--ngc-srk" || a == "--ngc-ncrypt" || a == "--ngc-ncrypt-vault" || a == "--ngc-ncrypt-export" || a == "--ngc-dump-enc" || a == "--ngc-cbor-deep-dump" || a == "--ngc-phase1" || a == "--ngc-phase1-path-a" || a == "--ngc-probe-derive" || a == "--pin-save");

    // windows_subsystem="windows" → 无控制台。CLI 结果全量写入文件。
    let cli_out_path: Option<std::path::PathBuf> = if is_cli_mode {
        let p = exe_dir.join("ngc_test_result.txt");
        // 清空旧结果 + 写入 UTF-8 BOM（记事本自动识别）
        let _ = std::fs::write(&p, "\u{FEFF}");
        Some(p)
    } else {
        None
    };

    // CLI 输出：仅写文件（GUI 程序无控制台 stdout）
    fn cli_write(file: &Option<std::path::PathBuf>, text: &str) {
        if let Some(ref p) = file {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(text.as_bytes());
            }
        }
    }
    macro_rules! cli_println {
        ($file:expr) => { cli_write($file, "\n") };
        ($file:expr, $($arg:tt)*) => { cli_write($file, &format!("{}\n", format!($($arg)*))) };
    }

    // PsExec SYSTEM 环境下无控制台 → 弹窗告知用户结果文件路径
    fn cli_done(path: &std::path::Path, passed: bool) -> ! {
        // 不弹 MessageBox——PsExec SYSTEM 会话 (Session 0) 里弹窗不可见，
        // 会卡死进程。直接写文件退出，用户自行查看。
        let summary = if passed { "PASS" } else { "FAIL" };
        cli_write(&Some(path.to_path_buf()), &format!("\n[{}] 测试结束，结果见本文件。\n", summary));
        let _ = std::fs::write(path.join("..").join("ngc_test_done.txt"), summary);
        std::process::exit(if passed { 0 } else { 1 });
    }

    if args.iter().any(|a| a == "--ngc-enum-cng") {
        // CNG/KSP 密钥枚举诊断：确认 FIDO/passkey 私钥能否经 CNG 直接访问。
        // 若 FIDO 密钥出现在 Passport/Platform KSP 中，签名应走 NCrypt 原地签名，
        // 而非逆向解密文件格式。
        cli_println!(&cli_out_path, "=== CNG/KSP 密钥枚举诊断 ===");
        cli_println!(&cli_out_path, "（以当前进程身份枚举；NGC 密钥属 LocalService，");
        cli_println!(&cli_out_path, " 若此处为空，可能需要模拟 LocalService 令牌）");
        for provider in [
            "Microsoft Passport Key Storage Provider",
            "Microsoft Platform Crypto Provider",
            "Microsoft Software Key Storage Provider",
        ] {
            cli_println!(&cli_out_path);
            cli_println!(&cli_out_path, "--- Provider: {} ---", provider);
            match ngc::dpapi::enum_cng_keys(provider) {
                Ok(keys) => {
                    cli_println!(&cli_out_path, "  共 {} 个密钥:", keys.len());
                    for (name, alg) in &keys {
                        cli_println!(&cli_out_path, "    [{}] {}", if alg.is_empty() { "?" } else { alg }, name);
                    }
                }
                Err(e) => cli_println!(&cli_out_path, "  枚举失败: {}", e),
            }
        }
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    if args.iter().any(|a| a == "--ngc-container-dump") {
        // PIN-free：递归 dump NGC 容器真实磁盘结构，用于把现代格式逆向写对。
        // 仅读结构与已加密 blob（不解密、不碰 PIN）。
        cli_println!(&cli_out_path, "=== NGC 容器结构 Dump (PIN-free) ===");
        let ngc_root = std::path::Path::new(r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc");
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        let mut stack: Vec<std::path::PathBuf> = vec![ngc_root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() { stack.push(p); } else { files.push(p); }
                }
            }
        }
        files.sort();
        cli_println!(&cli_out_path, "共 {} 个文件\n", files.len());
        for p in &files {
            let rel = p.strip_prefix(ngc_root).unwrap_or(p);
            let data = match std::fs::read(p) { Ok(d) => d, Err(_) => { cli_println!(&cli_out_path, "■ {}  (读取失败)", rel.display()); continue; } };
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            cli_println!(&cli_out_path, "■ {}  ({} bytes)", rel.display(), data.len());
            if name.ends_with(".json") {
                let txt = String::from_utf8_lossy(&data);
                let shown: String = txt.chars().take(6000).collect();
                cli_println!(&cli_out_path, "{}", shown);
            } else {
                let n = data.len().min(192);
                let hex: String = data[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                cli_println!(&cli_out_path, "  hex[{}/{}]: {}", n, data.len(), hex);
                if data.len() >= 2 && data.len() % 2 == 0 {
                    let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let s = String::from_utf16_lossy(&u16s);
                    let printable = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').count();
                    if printable > s.chars().count() / 2 {
                        cli_println!(&cli_out_path, "  utf16: {}", s.trim_end_matches('\0'));
                    }
                }
            }
            cli_println!(&cli_out_path);
        }
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    if args.iter().any(|a| a == "--ngc-sign-probe") {
        // FIDO 签名探针：测多种 PIN 供给策略对 Passport KSP 密钥签名是否成功。
        // 用法: --ngc-sign-probe <rpId> <PIN>   例: --ngc-sign-probe google.com 1234
        let idx = args.iter().position(|a| a == "--ngc-sign-probe").unwrap_or(0) + 1;
        let rp_id = args.get(idx).map(|s| s.as_str()).unwrap_or("");
        let pin = args.get(idx + 1).map(|s| s.as_str()).unwrap_or("");
        cli_println!(&cli_out_path, "=== FIDO 签名探针 ===");
        if rp_id.is_empty() || pin.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-sign-probe <rpId> <PIN>");
            cli_println!(&cli_out_path, "示例: --ngc-sign-probe google.com 1234");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        let mut any_ok = false;
        for line in ngc::dpapi::ncrypt_sign_probe(rp_id, pin) {
            if line.contains("签名成功") { any_ok = true; }
            cli_println!(&cli_out_path, "{}", line);
        }
        cli_done(cli_out_path.as_ref().unwrap(), any_ok);
    }

    if args.iter().any(|a| a == "--ngc-dump") {
        // NGC 加密原始数据 dump（调试用）
        let ngc_root = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
        cli_println!(&cli_out_path, "=== NGC encryptedCbor Raw Dump ===");
        cli_println!(&cli_out_path);
        if let Ok(entries) = std::fs::read_dir(ngc_root) {
            for e in entries.flatten() {
                let p = e.path();
                if !p.is_dir() || p.file_name().and_then(|n| n.to_str()).map_or(true, |n| !n.starts_with('{')) { continue; }
                let pj = p.join("Protectors.json");
                if !pj.is_file() { continue; }
                if let Ok(json_str) = std::fs::read_to_string(&pj) {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(cbor_b64) = root.get("pin").and_then(|p| p.get("secretStore")).and_then(|s| s.get("encryptedCbor")).and_then(|v| v.as_str()) {
                            use base64::Engine;
                            if let Ok(cbor_bytes) = base64::engine::general_purpose::STANDARD.decode(cbor_b64) {
                                cli_println!(&cli_out_path, "encryptedCbor size: {} bytes", cbor_bytes.len());
                                // Hex dump of first 128 bytes
                                cli_println!(&cli_out_path, "--- hex dump (first 128 bytes) ---");
                                let dump_len = cbor_bytes.len().min(128);
                                for chunk in cbor_bytes[..dump_len].chunks(16) {
                                    let hex: String = chunk.iter().map(|b| format!("{:02X} ", b)).collect();
                                    let ascii: String = chunk.iter().map(|&b| if b >= 32 && b < 127 { b as char } else { '.' }).collect();
                                    cli_println!(&cli_out_path, "  {:45} {}", hex, ascii);
                                }
                                cli_println!(&cli_out_path);

                                // 尝试解析 NgcIsoHeader
                                if let Ok(hdr) = ngc::container::parse_ngciso_header(&cbor_bytes) {
                                    cli_println!(&cli_out_path, "--- NgcIsoHeader ---");
                                    cli_println!(&cli_out_path, "salt (first 8 bytes): {:02X?}", &hdr.salt[..8.min(hdr.salt.len())]);
                                    cli_println!(&cli_out_path, "rounds: {}", hdr.rounds);
                                    cli_println!(&cli_out_path, "iv (len {}): {:02X?}", hdr.iv.len(), &hdr.iv);
                                    cli_println!(&cli_out_path, "payload_offset: {} (0x{:X})", hdr.payload_offset, hdr.payload_offset);
                                    cli_println!(&cli_out_path, "ciphertext size after header: {} bytes", cbor_bytes.len() - hdr.payload_offset);
                                } else {
                                    cli_println!(&cli_out_path, "parse_ngciso_header FAILED");
                                }
                            }
                        }
                    }
                }
            }
        }
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    if args.iter().any(|a| a == "--ngc-srk") {
        let uidx = args.iter().position(|a| a == "--ngc-srk").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() { cli_println!(&cli_out_path, "用法: --ngc-srk <用户名> <PIN>"); cli_done(cli_out_path.as_ref().unwrap(), false); }
        cli_println!(&cli_out_path, "=== Protector GCM 解密 SRK 提取 ===");
        let sid = match ngc::lookup_sid_by_username(u) { Ok(s) => s, Err(e) => { cli_println!(&cli_out_path, "SID: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); } };
        let ci = match ngc::container::find_ngc_container(&sid) { Ok(c) => c, Err(e) => { cli_println!(&cli_out_path, "容器: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); } };
        if let Ok(entropy) = ngc::pin::derive_entropy(p, &ci.salt, ci.rounds) {
            // 诊断: DPAPI unwrap SRK
            let cj = ci.container_path.join("Container.json");
            if let Ok(cj_js) = std::fs::read_to_string(&cj) {
                if let Ok(cj_v) = serde_json::from_str::<serde_json::Value>(&cj_js) {
                    if let Some(srk_b64) = cj_v.get("srk").and_then(|s| s.as_str()) {
                        use base64::Engine;
                        cli_println!(&cli_out_path, "SRK base64: {}", srk_b64);
                        if let Ok(srk_blob) = base64::engine::general_purpose::STANDARD.decode(srk_b64) {
                            cli_println!(&cli_out_path, "SRK decoded: {} bytes", srk_blob.len());
                            cli_println!(&cli_out_path, "SRK hex: {:02X?}", &srk_blob);
                            // Try DPAPI
                            match ngc::dpapi::dpapi_unprotect(&srk_blob, &entropy) {
                                Ok(key) => {
                                    cli_println!(&cli_out_path, "DPAPI unwrap OK: {} bytes", key.len());
                                    cli_println!(&cli_out_path, "key[..32]: {:02X?}", &key.iter().take(32).collect::<Vec<_>>());
                                }
                                Err(e) => { cli_println!(&cli_out_path, "DPAPI unwrap FAILED: {}", e); }
                            }
                            // Try without entropy
                            match ngc::dpapi::dpapi_unprotect(&srk_blob, &[]) {
                                Ok(key) => {
                                    cli_println!(&cli_out_path, "DPAPI(no entropy) OK: {} bytes", key.len());
                                }
                                Err(e) => { cli_println!(&cli_out_path, "DPAPI(no entropy): {}", e); }
                            }
                        }
                    }
                }
            }
            let pj = ci.container_path.join("Protectors.json");
            if let Ok(js) = std::fs::read_to_string(&pj) {
                if let Ok(r) = serde_json::from_str::<serde_json::Value>(&js) {
                    if let Some(cbor_b64) = r.get("pin").and_then(|p| p.get("secretStore")).and_then(|s| s.get("encryptedCbor")).and_then(|v| v.as_str()) {
                        use base64::Engine;
                        if let Ok(cb) = base64::engine::general_purpose::STANDARD.decode(cbor_b64) {
                            if let Ok(hdr) = ngc::container::parse_ngciso_header(&cb) {
                                let ct = &cb[hdr.payload_offset..];
                                cli_println!(&cli_out_path, "ct_len={} ct%16={}", ct.len(), ct.len()%16);
                                if let Some((desc, pt)) = ngc::try_multiple_key_derivations(&entropy, &hdr.iv, ct) {
                                    cli_println!(&cli_out_path, "成功: {}", desc);
                                    cli_println!(&cli_out_path, "payload长度: {} bytes", pt.len());
                                    // Hex dump first 128 bytes
                                    for chunk in pt.iter().take(128).collect::<Vec<_>>().chunks(16) {
                                        cli_println!(&cli_out_path, "  {}", chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
                                    }
                                    // 如果 payload 看起来像 CBOR，尝试提取 32 字节密钥段
                                    if pt.len() >= 32 {
                                        cli_println!(&cli_out_path, "first 32B (candidate SRK):");
                                        for chunk in pt[..32].chunks(16) {
                                            cli_println!(&cli_out_path, "  {}", chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
                                        }
                                    }
                                } else {
                                    cli_println!(&cli_out_path, "所有派生方式均失败");
                                }
                            }
                        }
                    }
                }
            }
        }
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    // ── Path A: NCrypt KSP 签名验证（新路线）───────────────────────────
    if args.iter().any(|a| a == "--ngc-ncrypt") {
        let uidx = args.iter().position(|a| a == "--ngc-ncrypt").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-ncrypt <用户名> <PIN>");
            cli_println!(&cli_out_path, "示例: --ngc-ncrypt \"星记\" \"<PIN>\"");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        cli_println!(&cli_out_path, "=== Path A: NCrypt KSP PIN 验证 ===");
        use sha2::{Sha256, Digest};
        let test_hash = Sha256::digest(b"FaceWinUnlock NCrypt test data 2026").to_vec();
        cli_println!(&cli_out_path, "用户: {}", u);
        cli_println!(&cli_out_path, "测试数据: SHA256(...)= {} bytes", test_hash.len());

        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID lookup 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };

        match ngc::ncrypt::verify_pin_and_sign(&sid, p, &test_hash) {
            Ok((result, log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "✅✅✅ NCrypt KSP 签名成功！PIN 正确！ ✅✅✅");
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "密钥名称:   {}", result.key_name);
                cli_println!(&cli_out_path, "算法:       {}", result.algorithm);
                cli_println!(&cli_out_path, "密钥长度:   {} bits", result.key_length);
                cli_println!(&cli_out_path, "签名长度:   {} bytes", result.signature.len());
                cli_println!(&cli_out_path, "签名前16B:  {:02X?}", &result.signature[..result.signature.len().min(16)]);
                cli_println!(&cli_out_path, "");
                let _ = &log; // 成功时 log 为空，真实日志在 result.log
                cli_println!(&cli_out_path, "--- 完整诊断日志 ---");
                for line in &result.log {
                    cli_println!(&cli_out_path, "{}", line);
                }
                cli_done(cli_out_path.as_ref().unwrap(), true);
            }
            Err((e, log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "❌ NCrypt KSP 验证失败: {}", e);
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "--- 诊断日志 ---");
                for line in &log {
                    cli_println!(&cli_out_path, "{}", line);
                }
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "可能原因:");
                cli_println!(&cli_out_path, "  1. PIN 错误");
                cli_println!(&cli_out_path, "  2. Passport KSP 中无该用户的密钥");
                cli_println!(&cli_out_path, "  3. 进程非 SYSTEM 身份（需要 PsExec -s 运行）");
                cli_println!(&cli_out_path, "  4. Windows Hello 未设置或已损坏");
                cli_done(cli_out_path.as_ref().unwrap(), false);
            }
        }
    }

    // ── Phase 1 完整链路: NCrypt PIN 验证 + Vault 解密 ───────────────
    if args.iter().any(|a| a == "--ngc-ncrypt-vault") {
        let uidx = args.iter().position(|a| a == "--ngc-ncrypt-vault").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-ncrypt-vault <用户名> <PIN>");
            cli_println!(&cli_out_path, "示例: --ngc-ncrypt-vault \"星记\" \"<PIN>\"");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "Phase 1 完整链路: NCrypt PIN 验证 + Vault 解密");
        cli_println!(&cli_out_path, "========================================");
        use sha2::{Sha256, Digest};
        let test_hash = Sha256::digest(b"FaceWinUnlock NCrypt-Vault chain test 2026").to_vec();
        cli_println!(&cli_out_path, "");
        cli_println!(&cli_out_path, "[Step 1] NCrypt KSP PIN 验证...");
        cli_println!(&cli_out_path, "  用户: {}", u);

        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "  SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "  SID lookup 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };

        // Step 1: PIN 验证
        let sign_result = match ngc::ncrypt::verify_pin_and_sign(&sid, p, &test_hash) {
            Ok((sr, log)) => {
                cli_println!(&cli_out_path, "  ✅ Step 1 完成: PIN 验证通过！");
                cli_println!(&cli_out_path, "     密钥: {} ({}, {} bits)", sr.key_name, sr.algorithm, sr.key_length);
                cli_println!(&cli_out_path, "     签名长度: {} bytes", sr.signature.len());
                for line in &log { cli_println!(&cli_out_path, "     | {}", line); }
                Some(sr)
            }
            Err((e, diag_log)) => {
                cli_println!(&cli_out_path, "  ❌ Step 1 失败: {}", e);
                for line in &diag_log { cli_println!(&cli_out_path, "    | {}", line); }
                None
            }
        };

        // Step 2: 尝试用 RSA 私钥解密 vault / KSP 内部解封
        cli_println!(&cli_out_path, "");
        cli_println!(&cli_out_path, "[Step 2] NCryptDecrypt 尝试解密 EncData...");
        
        match ngc::ncrypt::try_ncrypt_decrypt_vault(&sid, p) {
            Ok((pt, dec_log)) => {
                cli_println!(&cli_out_path, "  ✅✅✅ NCryptDecrypt 解封成功!");
                cli_println!(&cli_out_path, "     数据长度: {} bytes", pt.len());
                cli_println!(&cli_out_path, "     前64B hex: {:02X?}", &pt[..pt.len().min(64)]);
                for line in &dec_log { cli_println!(&cli_out_path, "    | {}", line); }
                // UTF-16LE 解码尝试
                if pt.len() >= 2 {
                    let decoded = String::from_utf16_lossy(
                        &pt[..pt.len() & !1]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>()
                    ).trim_matches('\0').to_string();
                    if !decoded.is_empty() {
                        cli_println!(&cli_out_path, "     🎉 明文内容: [{} chars] {:?}", decoded.chars().count(), decoded);
                    } else {
                        cli_println!(&cli_out_path, "     UTF-16 解码为空或非文本数据");
                    }
                }
                cli_done(cli_out_path.as_ref().unwrap(), true);
            }
            Err((e, dec_log)) => {
                cli_println!(&cli_out_path, "  ❌ NCryptDecrypt 解封失败: {}", e);
                for line in &dec_log { cli_println!(&cli_out_path, "    | {}", line); }
                
                // 即使解封失败，Step 1 成功也说明 PIN 正确
                if sign_result.is_some() {
                    cli_println!(&cli_out_path, "");
                    cli_println!(&cli_out_path, "📋 总结:");
                    cli_println!(&cli_out_path, "  ✅ PIN 验证 — 通过 (NCryptSignHash 成功)");
                    cli_println!(&cli_out_path, "  ❌ Vault 解密 — 失败 (KSP 可能不允许导出明文)");
                    cli_println!(&cli_out_path, "");
                    cli_println!(&cli_out_path, "下一步方向:");
                    cli_println!(&cli_out_path, "  A) 用 SYSTEM 身份运行 (PsExec -s)，KSP 行为可能不同");
                    cli_println!(&cli_out_path, "  B) 研究 NCryptExportKey 导出 PLAINTEXTKEY_BLOB");
                    cli_println!(&cli_out_path, "  C) 走 WebAuthn/Passkey 路线绕过密码获取");
                }
                cli_done(cli_out_path.as_ref().unwrap(), sign_result.is_some());
            }
        }
    }

    // ── 导出 encryptedCbor 供 CyberChef 分析 ────────────────────
    if args.iter().any(|a| a == "--ngc-dump-enc") {
        let uidx = args.iter().position(|a| a == "--ngc-dump-enc").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        cli_println!(&cli_out_path, "=== 导出 EncData (encryptedCbor) ===");
        cli_println!(&cli_out_path, "用户: {}", u);
        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        let ci = match ngc::container::find_ngc_container(&sid) {
            Ok(c) => c,
            Err(e) => { cli_println!(&cli_out_path, "容器未找到: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        cli_println!(&cli_out_path, "容器: {}", ci.container_path.display());
        let pj = ci.container_path.join("Protectors.json");
        let ps_str = match std::fs::read_to_string(&pj) {
            Ok(s) => s,
            Err(_) => { cli_println!(&cli_out_path, "无法读 Protectors.json"); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        let pv: serde_json::Value = match serde_json::from_str(&ps_str) {
            Ok(v) => v,
            Err(_) => { cli_println!(&cli_out_path, "JSON 解析失败"); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        let ec_b64 = pv.get("pin").and_then(|p| p.get("secretStore")).and_then(|s| s.get("encryptedCbor")).and_then(|e| e.as_str()).unwrap_or("");
        if ec_b64.is_empty() {
            cli_println!(&cli_out_path, "无 encryptedCbor"); cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(ec_b64) {
            Ok(ec_bytes) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "========== CyberChef Base64 ==========");
                for chunk in ec_b64.as_bytes().chunks(100) { cli_println!(&cli_out_path, "{}", std::str::from_utf8(chunk).unwrap_or("?")); }
                cli_println!(&cli_out_path, "[Info] {} B, Head32: {:02X?}", ec_bytes.len(), &ec_bytes[..ec_bytes.len().min(32)]);
            }
            Err(e) => { cli_println!(&cli_out_path, "b64 失败: {}", e); }
        }
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    // ── CBOR 深度 dump: 解析所有加密Cbor 的 CBOR 结构 (路B 诊断) ────────
    if args.iter().any(|a| a == "--ngc-cbor-deep-dump") {
        use base64::Engine;
        let uidx = args.iter().position(|a| a == "--ngc-cbor-deep-dump").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "  CBOR 深度 dump (路B 诊断)");
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "用户: {}", u);
        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        let ci = match ngc::container::find_ngc_container(&sid) {
            Ok(c) => c,
            Err(e) => { cli_println!(&cli_out_path, "容器未找到: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        cli_println!(&cli_out_path, "容器: {}", ci.container_path.display());

        // 1. Protectors.json -> pin.secretStore.encryptedCbor
        let pj = ci.container_path.join("Protectors.json");
        if pj.exists() {
            cli_println!(&cli_out_path, "");
            cli_println!(&cli_out_path, "─── 1. Protectors.json → pin.secretStore.encryptedCbor ───");
            if let Ok(ps) = std::fs::read_to_string(&pj) {
                if let Ok(pv) = serde_json::from_str::<serde_json::Value>(&ps) {
                    let ec = pv.get("pin").and_then(|p| p.get("secretStore")).and_then(|s| s.get("encryptedCbor")).and_then(|v| v.as_str());
                    if let Some(ec_b64) = ec {
                        if let Ok(ec_bytes) = base64::engine::general_purpose::STANDARD.decode(ec_b64) {
                            cli_println!(&cli_out_path, "{}", ngc::cbor::deep_dump_cbor("Protectors.encryptedCbor", &ec_bytes));
                        }
                    } else {
                        cli_println!(&cli_out_path, "(无 pin.secretStore.encryptedCbor 字段)");
                    }
                }
            }
        } else {
            cli_println!(&cli_out_path, "(Protectors.json 不存在)");
        }

        // 2. Container.json -> encryptedCbor
        let cj = ci.container_path.join("Container.json");
        if cj.exists() {
            cli_println!(&cli_out_path, "");
            cli_println!(&cli_out_path, "─── 2. Container.json → encryptedCbor ───");
            if let Ok(cs) = std::fs::read_to_string(&cj) {
                if let Ok(cv) = serde_json::from_str::<serde_json::Value>(&cs) {
                    let ec = cv.get("encryptedCbor").and_then(|v| v.as_str());
                    if let Some(ec_b64) = ec {
                        if let Ok(ec_bytes) = base64::engine::general_purpose::STANDARD.decode(ec_b64) {
                            cli_println!(&cli_out_path, "{}", ngc::cbor::deep_dump_cbor("Container.encryptedCbor", &ec_bytes));
                        }
                    } else {
                        cli_println!(&cli_out_path, "(无 encryptedCbor 字段)");
                    }
                    // 同时打印 srk 字段 (如果存在)
                    if let Some(srk) = cv.get("srk").and_then(|v| v.as_str()) {
                        cli_println!(&cli_out_path, "");
                        cli_println!(&cli_out_path, "[Container.srk 存在] {} chars(base64)", srk.len());
                        if let Ok(srk_bytes) = base64::engine::general_purpose::STANDARD.decode(srk) {
                            cli_println!(&cli_out_path, "  decoded {}B, head32: {:02X?}", srk_bytes.len(), &srk_bytes[..srk_bytes.len().min(32)]);
                        }
                    }
                }
            }
        }

        // 3. Keys/*.json -> encrypted.encryptedCbor (每个 key 文件)
        let keys_dir = ci.container_path.join("Keys");
        if keys_dir.is_dir() {
            cli_println!(&cli_out_path, "");
            cli_println!(&cli_out_path, "─── 3. Keys/*.json → encrypted.encryptedCbor ───");
            if let Ok(entries) = std::fs::read_dir(&keys_dir) {
                for entry in entries.flatten() {
                    let kf = entry.path();
                    if !kf.is_file() || kf.extension().map_or(true, |e| e != "json") { continue; }
                    let fname = kf.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                    if let Ok(ks) = std::fs::read_to_string(&kf) {
                        if let Ok(kv) = serde_json::from_str::<serde_json::Value>(&ks) {
                            let ec = kv.get("encrypted").and_then(|e| e.get("encryptedCbor")).and_then(|v| v.as_str())
                                .or_else(|| kv.get("encryptedCbor").and_then(|v| v.as_str()));
                            if let Some(ec_b64) = ec {
                                if let Ok(ec_bytes) = base64::engine::general_purpose::STANDARD.decode(ec_b64) {
                                    cli_println!(&cli_out_path, "─── Keys/{} ({}B) ───", fname, ec_bytes.len());
                                    cli_println!(&cli_out_path, "{}", ngc::cbor::deep_dump_cbor(&format!("Keys/{fname}"), &ec_bytes));
                                }
                            }
                        }
                    }
                }
            }
        } else {
            cli_println!(&cli_out_path, "(Keys 目录不存在)");
        }

        cli_println!(&cli_out_path, "");
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "  CBOR 深度 dump 完成");
        cli_println!(&cli_out_path, "========================================");
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    // ── NCryptExportKey: 尝试导出 uvkey RSA 私钥 ──────────────────
    if args.iter().any(|a| a == "--ngc-ncrypt-export") {
        let uidx = args.iter().position(|a| a == "--ngc-ncrypt-export").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-ncrypt-export <用户名> <PIN>");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        cli_println!(&cli_out_path, "=== NCryptExportKey: 导出 RSA 私钥 ===");
        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };

        match ngc::ncrypt::export_rsa_key_and_decrypt(&sid, p) {
            Ok((key_blob, dec_log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "✅✅✅ ExportKey 成功!");
                cli_println!(&cli_out_path, "私钥 blob: {} bytes", key_blob.len());
                cli_println!(&cli_out_path, "前64B hex: {:02X?}", &key_blob[..key_blob.len().min(64)]);
                for line in &dec_log { cli_println!(&cli_out_path, "| {}", line); }
                
                // 用导出的私钥尝试解密 encryptedCbor
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "--- 用导出的私钥解密 EncData ---");
                match ngc::ncrypt::decrypt_with_exported_key(&sid, &key_blob, p) {
                    Ok((pt, dec2_log)) => {
                        cli_println!(&cli_out_path, "🎉🎉🎉 解密成功! {} bytes", pt.len());
                        let s = ngc::ncrypt::utf16_le_to_string(&pt);
                        if !s.is_empty() { cli_println!(&cli_out_path, "明文: [{} chars] {:?}", s.chars().count(), s); }
                        else { cli_println!(&cli_out_path, "hex: {:02X?}", &pt[..pt.len().min(64)]); }
                        for line in &dec2_log { cli_println!(&cli_out_path, "| {}", line); }
                    }
                    Err((e, dec2_log)) => {
                        cli_println!(&cli_out_path, "❌ 解密失败: {}", e);
                        for line in &dec2_log { cli_println!(&cli_out_path, "| {}", line); }
                    }
                }
                cli_done(cli_out_path.as_ref().unwrap(), true);
            }
            Err((e, exp_log)) => {
                cli_println!(&cli_out_path, "❌ ExportKey 失败: {}", e);
                for line in &exp_log { cli_println!(&cli_out_path, "| {}", line); }
                cli_done(cli_out_path.as_ref().unwrap(), false);
            }
        }
    }

    // ═══ Phase 1 完整链路: NCryptExportKey → RSA私钥 → 解密vault → 明文密码 ═══
    if args.iter().any(|a| a == "--ngc-phase1") {
        let uidx = args.iter().position(|a| a == "--ngc-phase1").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-phase1 <用户名> <PIN>");
            cli_println!(&cli_out_path, "示例: --ngc-phase1 \"星记\" \"<PIN>\"");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "  Phase 1: NCrypt → RSA → Vault → 密码");
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "用户: {}", u);

        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };

        match ngc::ncrypt::phase1_ncrypt_full_chain(&sid, p) {
            Ok((password, chain_log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "╔══════════════════════════════════════╗");
                cli_println!(&cli_out_path, "║  ✅✅✅  PHASE 1 解密成功!  ✅✅✅     ║");
                cli_println!(&cli_out_path, "╚══════════════════════════════════════╝");
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "明文密码: [{} chars] '{}'", password.chars().count(), password);
                cli_println!(&cli_out_path, "");
                for line in &chain_log { cli_println!(&cli_out_path, "| {}", line); }
                cli_done(cli_out_path.as_ref().unwrap(), true);
            }
            Err((e, chain_log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "❌ Phase 1 失败: {}", e);
                cli_println!(&cli_out_path, "");
                for line in &chain_log { cli_println!(&cli_out_path, "| {}", line); }
                cli_done(cli_out_path.as_ref().unwrap(), false);
            }
        }
    }

    // ═══ 路A phase1 专用入口: NCryptDecrypt 多点尝试 ═══
    if args.iter().any(|a| a == "--ngc-phase1-path-a") {
        let uidx = args.iter().position(|a| a == "--ngc-phase1-path-a").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-phase1-path-a <用户名> <PIN>");
            cli_println!(&cli_out_path, "示例: --ngc-phase1-path-a \"星记\" \"<PIN>\"");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "  路A Phase 1: NCryptDecrypt 原地解密");
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "用户: {}", u);

        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };

        match ngc::ncrypt::phase1_ncrypt_path_a(&sid, p) {
            Ok((password, chain_log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "╔══════════════════════════════════════╗");
                cli_println!(&cli_out_path, "║  ✅✅✅  路A PHASE 1 解密成功!  ✅✅✅   ║");
                cli_println!(&cli_out_path, "╚══════════════════════════════════════╝");
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "明文密码: [{} chars] '{}'", password.chars().count(), password);
                cli_println!(&cli_out_path, "");
                for line in &chain_log { cli_println!(&cli_out_path, "| {}", line); }
                cli_done(cli_out_path.as_ref().unwrap(), true);
            }
            Err((e, chain_log)) => {
                cli_println!(&cli_out_path, "");
                cli_println!(&cli_out_path, "❌ 路A Phase 1 失败: {}", e);
                cli_println!(&cli_out_path, "");
                for line in &chain_log { cli_println!(&cli_out_path, "| {}", line); }
                cli_done(cli_out_path.as_ref().unwrap(), false);
            }
        }
    }

    // ═══ 路B-4 探针: NCryptSecretAgreement / NCryptDeriveKey ═══
    if args.iter().any(|a| a == "--ngc-probe-derive") {
        let uidx = args.iter().position(|a| a == "--ngc-probe-derive").unwrap_or(0) + 1;
        let u = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let p = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        if u.is_empty() || p.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-probe-derive <用户名> <PIN>");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "  路B-4 探针: KSP SecretAgreement 派生");
        cli_println!(&cli_out_path, "========================================");
        cli_println!(&cli_out_path, "用户: {}", u);
        let sid = match ngc::lookup_sid_by_username(u) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID 失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };
        let log = ngc::ncrypt::probe_secret_agreement(&sid, p);
        for line in &log { cli_println!(&cli_out_path, "{}", line); }
        cli_println!(&cli_out_path, "");
        cli_println!(&cli_out_path, "[下一步] 若 NCryptSecretAgreement 成功 + NCryptDeriveKey 也能工作,");
        cli_println!(&cli_out_path, "  我们就能拿到 KSP 派生的中间 secret —— 这就是路B 想要的结果。");
        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    if args.iter().any(|a| a == "--ngc-keys") {
        let username = args.iter().position(|a| a == "--ngc-keys")
            .and_then(|i| args.get(i + 1)).map(|s| s.as_str()).unwrap_or("");
        let pin = args.iter().position(|a| a == "--ngc-keys")
            .and_then(|i| args.get(i + 2)).map(|s| s.as_str()).unwrap_or("");

        if username.is_empty() || pin.is_empty() {
            cli_println!(&cli_out_path, "用法: --ngc-keys <用户名> <PIN>");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }

        cli_println!(&cli_out_path, "=== NGC 密钥解密 ===");
        cli_println!(&cli_out_path, "用户: {}", username);

        let sid = match ngc::lookup_sid_by_username(username) {
            Ok(s) => { cli_println!(&cli_out_path, "SID: {}", s); s }
            Err(e) => { cli_println!(&cli_out_path, "SID 查找失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
        };

        match ngc::decrypt_ngc_keys(&sid, pin) {
            Ok(keys) => {
                cli_println!(&cli_out_path, "共 {} 个密钥:", keys.len());
                cli_println!(&cli_out_path);
                let mut decrypted_count = 0;
                for k in &keys {
                    let status = if k.decrypted { "✅" } else { "❌" };
                    let cache_desc = match k.cache_type {
                        1 => "NGC 登录密钥",
                        2 => "RSA 认证密钥",
                        4 => "FIDO2 (ECDSA_P256)",
                        _ => "未知类型",
                    };
                    cli_println!(&cli_out_path, "  {} {} {}bit cacheType:{} ({}) [{}]",
                        status, k.alg, k.bits, k.cache_type, cache_desc,
                        if k.method.is_empty() { "—" } else { k.method.as_str() });
                    cli_println!(&cli_out_path, "    {}", k.filename);
                    if k.decrypted { decrypted_count += 1; }
                }
                cli_println!(&cli_out_path);
                cli_println!(&cli_out_path, "解密成功: {}/{}", decrypted_count, keys.len());
                if decrypted_count > 0 {
                    let fido_gcm = keys.iter().any(|k| k.cache_type == 4 && k.decrypted && k.method.starts_with("GCM"));
                    let fido_cbc = keys.iter().any(|k| k.cache_type == 4 && k.decrypted && k.method.starts_with("CBC"));
                    let has_login = keys.iter().any(|k| k.cache_type == 1 && k.decrypted);
                    cli_println!(&cli_out_path);
                    if has_login {
                        cli_println!(&cli_out_path, "💡 NGC 登录密钥已解密 → Phase 2 passkey 可用");
                    }
                    if fido_gcm {
                        cli_println!(&cli_out_path, "🔑 FIDO2 密钥已解密【GCM 认证·铁证】→ Phase 2 passkey 签名可用，可放心推进");
                    } else if fido_cbc {
                        cli_println!(&cli_out_path, "⚠ FIDO2 仅 CBC 解出【无认证·疑似假阳性】→ 推进前需用「公钥比对」二次验证");
                    }
                }
                cli_done(cli_out_path.as_ref().unwrap(), decrypted_count > 0);
            }
            Err(e) => {
                cli_println!(&cli_out_path, "密钥解密失败: {}", e);
                cli_done(cli_out_path.as_ref().unwrap(), false);
            }
        }
    }

    if args.iter().any(|a| a == "--pin-save") {
        let uidx = args.iter().position(|a| a == "--pin-save").unwrap_or(0) + 1;
        let user = args.get(uidx).map(|s| s.as_str()).unwrap_or("");
        let pin  = args.get(uidx+1).map(|s| s.as_str()).unwrap_or("");
        let sid_arg = args.get(uidx+2).map(|s| s.as_str());
        if user.is_empty() || pin.is_empty() {
            cli_println!(&cli_out_path, "用法: --pin-save <用户名> <PIN> [SID]");
            cli_println!(&cli_out_path, "示例: --pin-save \"星记\" <PIN> S-1-5-21-...");
            cli_done(cli_out_path.as_ref().unwrap(), false);
        }
        // 如果提供了 SID 参数，直接用它；否则自动查找
        let sid = if let Some(s) = sid_arg.filter(|s| s.starts_with("S-1-")) {
            Ok(s.to_string())
        } else {
            ngc::find_sid_by_username(user)
        };
        match sid {
            Ok(sid) => {
                cli_println!(&cli_out_path, "SID: {}", sid);
                // 直接用 load_pin_with_sid 的方式手动保存（绕过 get_current_sid）
                // save_pin 内部也调 get_current_sid —— 写一个直接保存的版本
                cli_println!(&cli_out_path, "正在保存 PIN (用户: {}) ...", user);
                match ngc::pin_store::save_pin_with_sid(user, pin, &sid, None) {
                    Ok(()) => { cli_println!(&cli_out_path, "✅ PIN 已加密存储"); cli_done(cli_out_path.as_ref().unwrap(), true); }
                    Err(e) => { cli_println!(&cli_out_path, "❌ 保存失败: {}", e); cli_done(cli_out_path.as_ref().unwrap(), false); }
                }
            }
            Err(e) => {
                cli_println!(&cli_out_path, "❌ 找不到 SID: {}", e);
                cli_println!(&cli_out_path, "请手动指定: --pin-save \"星记\" <PIN> S-1-5-21-xxx");
                cli_done(cli_out_path.as_ref().unwrap(), false);
            }
        }
    }

    // 诊断探针：直接测试 Passport KSP 能否对真实 FIDO 密钥静默签名。
    // 用法: --probe-ksp-sign <rpId> <PIN文件路径>
    // PIN 从文件读取，避免出现在进程参数 / 命令行回显里。
    if args.iter().any(|a| a == "--probe-ksp-sign") {
        let idx = args.iter().position(|a| a == "--probe-ksp-sign").unwrap() + 1;
        let rp_id = args.get(idx).map(|s| s.as_str()).unwrap_or("webauthn.io");
        let pin_file = args.get(idx + 1).map(|s| s.as_str()).unwrap_or("");
        let pin = if pin_file.is_empty() {
            String::new()
        } else {
            std::fs::read_to_string(pin_file)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        println!("=== Passport KSP 签名探针 ===");
        println!("rpId : {}", rp_id);
        println!(
            "PIN  : {} ({} 位)",
            if pin.is_empty() { "<空>" } else { "<已从文件读取>" },
            pin.chars().count()
        );
        let digest = [0x42u8; 32];
        let start = std::time::Instant::now();
        match ngc::ncrypt::sign_fido_assertion_hash(rp_id, &pin, &digest) {
            Ok((sig, key_name)) => {
                println!("✅ 签名成功: {} 字节 DER (耗时 {:.2?})", sig.len(), start.elapsed());
                println!("   密钥名: {}", key_name);
                println!("   → Passport KSP 允许静默签名，Approach B 对现有密钥可行。");
                std::process::exit(0);
            }
            Err(e) => {
                println!("❌ 签名失败 (耗时 {:.2?}): {}", start.elapsed(), e);
                println!("   → 若错误指向拒绝/需交互式 UI，则 KSP 禁止静默签名，须走官方插件。");
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|a| a == "--ngc-smoke-test") {
        let username_idx = args.iter().position(|a| a == "--ngc-smoke-test").unwrap_or(0) + 1;
        let username = args.get(username_idx).map(|s| s.as_str()).unwrap_or("");
        let pin = args.get(username_idx + 1).map(|s| s.as_str()).unwrap_or("");

        if username.is_empty() || pin.is_empty() {
            cli_println!(&cli_out_path, "用法: FaceWinUnlock-Server.exe --ngc-smoke-test <用户名> <PIN>");
            cli_println!(&cli_out_path, "示例: FaceWinUnlock-Server.exe --ngc-smoke-test John 123456");
            std::process::exit(1);
        }

        cli_println!(&cli_out_path, "╔══════════════════════════════════════════════════════════╗");
        cli_println!(&cli_out_path, "║       NGC 解密链 Smoke Test                              ║");
        cli_println!(&cli_out_path, "╠══════════════════════════════════════════════════════════╣");
        cli_println!(&cli_out_path, "║ 用户名 : {:<48}║", username);
        cli_println!(&cli_out_path, "║ PIN    : {:<48}║", "*".repeat(pin.len()));
        cli_println!(&cli_out_path, "╚══════════════════════════════════════════════════════════╝");
        cli_println!(&cli_out_path);

        // Step 0: 检查运行权限
        cli_println!(&cli_out_path, "[Step 0/3] 检查运行权限...");
        let ngc_root = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
        match std::fs::read_dir(ngc_root) {
            Ok(entries) => {
                let count = entries.filter_map(|e| e.ok()).count();
                cli_println!(&cli_out_path, "  ✓ NGC 目录可读 ({} 个容器)", count);
                if count == 0 {
                    cli_println!(&cli_out_path, "  ⚠ 警告: 未找到任何 NGC 容器！请确认已设置 Windows Hello PIN");
                }
            }
            Err(e) => {
                cli_println!(&cli_out_path, "  ✗ 无法读取 NGC 目录: {}", e);
                cli_println!(&cli_out_path);
                cli_println!(&cli_out_path, "  🔴 权限不足！NGC 解密需要 SYSTEM 权限。");
                cli_println!(&cli_out_path, "     请用 PsExec 以 SYSTEM 身份运行:");
                cli_println!(&cli_out_path, "     PsExec.exe -s -i \"{}\" --ngc-smoke-test \"{}\" \"****\"",
                         std::env::current_exe().unwrap_or_default().display(), username);
                std::process::exit(2);
            }
        }
        cli_println!(&cli_out_path);

        // Step 1: 用户名 → SID
        cli_println!(&cli_out_path, "[Step 1/3] 查找用户 SID...");
        let sid = match ngc::find_sid_by_username(username) {
            Ok(s) => {
                cli_println!(&cli_out_path, "  ✓ SID: {}", s);
                s
            }
            Err(e) => {
                cli_println!(&cli_out_path, "  ✗ 查找 SID 失败: {}", e);
                cli_println!(&cli_out_path);
                cli_println!(&cli_out_path, "  🔴 请确认:");
                cli_println!(&cli_out_path, "     1. 用户名拼写正确（区分大小写）");
                cli_println!(&cli_out_path, "     2. 该用户是本地账户（非 Microsoft 在线账户）");
                cli_println!(&cli_out_path, "     3. 该用户已设置 Windows Hello PIN");
                std::process::exit(3);
            }
        };
        cli_println!(&cli_out_path);

        // Step 2: NGC 解密
        cli_println!(&cli_out_path, "[Step 2/3] 执行 NGC 解密链...");
        cli_println!(&cli_out_path, "  → PIN entropy 派生 (PBKDF2+SHA512)...");
        cli_println!(&cli_out_path, "  → DPAPI 解密 RSA 私钥...");
        cli_println!(&cli_out_path, "  → Vault Policy 密钥提取...");
        cli_println!(&cli_out_path, "  → .vcrd 解密...");
        cli_println!(&cli_out_path, "  → RSA OAEP 解密对称密钥...");
        cli_println!(&cli_out_path, "  → AES-256-CBC 解密密码...");
        cli_println!(&cli_out_path);

        let start = std::time::Instant::now();
        match ngc::recover_password(&sid, pin) {
            Ok((ngc_user, password, domain)) => {
                let elapsed = start.elapsed();
                cli_println!(&cli_out_path, "╔══════════════════════════════════════════════════════════╗");
                cli_println!(&cli_out_path, "║  ✅ NGC 解密成功！                                      ║");
                cli_println!(&cli_out_path, "╠══════════════════════════════════════════════════════════╣");
                cli_println!(&cli_out_path, "║ NGC 用户名 : {:<44}║", ngc_user);
                cli_println!(&cli_out_path, "║ 域         : {:<44}║", domain);
                cli_println!(&cli_out_path, "║ 密码长度   : {:<44}║", password.len());
                cli_println!(&cli_out_path, "║ 耗时       : {:<43.1?}║", elapsed);
                cli_println!(&cli_out_path, "╚══════════════════════════════════════════════════════════╝");

                // 安全：不打印明文密码，但确认非空
                if password.is_empty() {
                    cli_println!(&cli_out_path);
                    cli_println!(&cli_out_path, "  ⚠ 警告: 密码为空——NGC 解密成功但凭据可能无效");
                } else {
                    cli_println!(&cli_out_path);
                    cli_println!(&cli_out_path, "  💡 NGC 解密链工作正常！PIN → 明文密码 全链路验证通过。");
                }
                std::process::exit(0);
            }
            Err(e) => {
                let elapsed = start.elapsed();
                cli_println!(&cli_out_path, "╔══════════════════════════════════════════════════════════╗");
                cli_println!(&cli_out_path, "║  ❌ NGC 解密失败                                         ║");
                cli_println!(&cli_out_path, "╠══════════════════════════════════════════════════════════╣");
                cli_println!(&cli_out_path, "║ 错误 : {:<48}║", e.to_string().chars().take(48).collect::<String>());
                cli_println!(&cli_out_path, "║ 耗时 : {:<43.1?}║", elapsed);
                cli_println!(&cli_out_path, "╚══════════════════════════════════════════════════════════╝");

                match &e {
                    ngc::NgcError::InvalidPin => {
                        cli_println!(&cli_out_path);
                        cli_println!(&cli_out_path, "  🔴 PIN 错误。请确认输入的 PIN 正确。");
                    }
                    ngc::NgcError::ContainerNotFound => {
                        cli_println!(&cli_out_path);
                        cli_println!(&cli_out_path, "  🔴 未找到 NGC 容器。请确认该用户已设置 Windows Hello PIN。");
                    }
                    ngc::NgcError::DecryptionFailed(msg) if msg.contains("暂未实现") => {
                        cli_println!(&cli_out_path);
                        cli_println!(&cli_out_path, "  🟡 功能尚未实现: {}", msg);
                    }
                    _ => {
                        cli_println!(&cli_out_path);
                        cli_println!(&cli_out_path, "  🔴 解密链在某个环节失败。详细信息见上方。");
                        cli_println!(&cli_out_path, "     可能原因: protector 格式/偏移不匹配当前 Windows 版本。");
                    }
                }
                std::process::exit(4);
            }
        }
    }

    // ── NGC 环境探测（不执行解密，仅检查容器和文件）──────────────
    if args.iter().any(|a| a == "--ngc-probe") {
        cli_println!(&cli_out_path, "=== NGC 环境探测 ===");
        cli_println!(&cli_out_path);

        // 1. NGC 目录
        let ngc_root = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
        match std::fs::read_dir(ngc_root) {
            Ok(entries) => {
                cli_println!(&cli_out_path, "NGC 容器目录: ✓ 可读");
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        cli_println!(&cli_out_path, "  容器: {}", p.file_name().and_then(|n| n.to_str()).unwrap_or("?"));
                        let prot = p.join("protectors");
                        if prot.is_dir() {
                            if let Ok(pe) = std::fs::read_dir(&prot) {
                                for pp in pe.flatten() {
                                    cli_println!(&cli_out_path, "    protector: {}", pp.file_name().to_string_lossy());
	                                let pd = pp.path();
	                                let pname = pp.file_name().to_string_lossy().to_string();
	                                if pd.is_dir() {
	                                    if let Ok(pf) = std::fs::read_dir(&pd) {
	                                        for pf_entry in pf.flatten() {
	                                            let fpath = pf_entry.path();
	                                            let size = fpath.metadata().map(|m| m.len()).unwrap_or(0);
	                                            cli_println!(&cli_out_path, "      {}/{} ({} bytes)", pname, fpath.file_name().and_then(|n| n.to_str()).unwrap_or("?"), size);
	                                        }
	                                    }
	                                } else {
	                                    let size = pd.metadata().map(|m| m.len()).unwrap_or(0);
	                                    cli_println!(&cli_out_path, "      {} ({} bytes)", pname, size);
	                                }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => cli_println!(&cli_out_path, "NGC 目录: ✗ 无法访问 ({})", e),
        }
        cli_println!(&cli_out_path);

        
        // 1b. 读取微软账户 NGC 容器的 JSON 元数据
        if let Ok(ce) = std::fs::read_dir(ngc_root) {
            for e in ce.flatten() {
                let p = e.path();
                if p.is_dir() && p.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.starts_with('{')) {
                    let cj = p.join("Container.json");
                    if cj.is_file() {
                        if let Ok(data) = std::fs::read_to_string(&cj) {
                            cli_println!(&cli_out_path, "--- Container.json ---");
                            cli_println!(&cli_out_path, "{}", &data[..data.len().min(4000)]);
                            cli_println!(&cli_out_path);
                        }
                    }
                    let pj = p.join("Protectors.json");
                    if pj.is_file() {
                        if let Ok(data) = std::fs::read_to_string(&pj) {
                            cli_println!(&cli_out_path, "--- Protectors.json ({} bytes) ---", data.len());
                            cli_println!(&cli_out_path, "{}", &data[..data.len().min(5000)]);
                            cli_println!(&cli_out_path);
                        }
                    }
                    let kd = p.join("Keys");
                    if kd.is_dir() {
                        if let Ok(kf) = std::fs::read_dir(&kd) {
                            for key_file in kf.flatten() {
                                let kp = key_file.path();
                                let size = kp.metadata().map(|m| m.len()).unwrap_or(0);
                                let fname = kp.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                                cli_println!(&cli_out_path, "  Key: {} ({} bytes)", fname, size);
                                // 读取小文件内容
                                if size < 5000 {
                                    if let Ok(kdata) = std::fs::read_to_string(&kp) {
                                        cli_println!(&cli_out_path, "    {}", &kdata[..kdata.len().min(2000)]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        cli_println!(&cli_out_path);

        // 2. Crypto Keys
        let keys_dir = r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys";
        match std::fs::read_dir(keys_dir) {
            Ok(entries) => {
                let count = entries.filter_map(|e| e.ok()).count();
                cli_println!(&cli_out_path, "Crypto Keys 目录: ✓ ({} 个文件)", count);
            }
            Err(e) => cli_println!(&cli_out_path, "Crypto Keys 目录: ✗ ({})", e),
        }
        cli_println!(&cli_out_path);

        // 3. Vault
        let vault_root = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault";
        let ngc_schema = "1d4350a3-330d-4af9-b3ff-a927a45998ac";
        let schema_dir = std::path::Path::new(vault_root).join(ngc_schema);
        if schema_dir.is_dir() {
            cli_println!(&cli_out_path, "Vault NGC schema: ✓");
            if let Ok(entries) = std::fs::read_dir(&schema_dir) {
                for e in entries.flatten() {
                    let p = e.path();
                    cli_println!(&cli_out_path, "  {} ({} bytes)", p.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                        p.metadata().map(|m| m.len()).unwrap_or(0));
                }
            }
        } else {
            cli_println!(&cli_out_path, "Vault NGC schema: ✗ 目录不存在 ({})", schema_dir.display());
        }
        cli_println!(&cli_out_path);

        // 4. ProfileList SID 扫描
        cli_println!(&cli_out_path, "ProfileList 本地账户:");
        let profile_list = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        if let Ok(sids) = list_profile_sids(profile_list) {
            for (sid_str, profile_path) in &sids {
                if let Some(name) = profile_path.rsplit('\\').next() {
                    let marker = if sid_str.ends_with("-500") { " (Administrator)" }
                        else if sid_str.ends_with("-501") { " (Guest)" }
                        else { "" };
                    cli_println!(&cli_out_path, "  {} → {}{}", sid_str, name, marker);
                }
            }
            if sids.is_empty() {
                cli_println!(&cli_out_path, "  (无本地账户)");
            }
        } else {
            cli_println!(&cli_out_path, "  ✗ 无法读取注册表");
        }

        cli_done(cli_out_path.as_ref().unwrap(), true);
    }

    if std::env::args().any(|arg| arg == WORKER_ARG) {
        std::process::exit(run_service_worker(exe_dir));
    }

    run_service_supervisor(exe_dir);
}

/// 列出 ProfileList 中所有本地账户 SID 和配置文件路径
fn list_profile_sids(key_path: &str) -> Result<Vec<(String, String)>, String> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, RegCloseKey, RegEnumKeyExW,
        HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };
    use windows_core::{PCWSTR, PWSTR};

    let key_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let val_name: Vec<u16> = "ProfileImagePath".encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut hkey = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(key_wide.as_ptr()), None, KEY_READ, &mut hkey).is_err() {
            return Err("无法打开 ProfileList".to_string());
        }

        let mut results = Vec::new();
        for idx in 0u32.. {
            let mut sid_buf = vec![0u16; 128];
            let mut sid_len = (sid_buf.len() * 2) as u32;
            if RegEnumKeyExW(hkey, idx, Some(PWSTR(sid_buf.as_mut_ptr())), &mut sid_len, None, None, None, None).is_err() {
                break;
            }
            let char_len = (sid_len as usize) / 2;
            let sid_str = String::from_utf16_lossy(&sid_buf[..char_len.min(sid_buf.len())]);
            if !sid_str.starts_with("S-1-5-21") && !sid_str.starts_with("S-1-5-32") {
                continue;
            }

            let sub_path: Vec<u16> = format!("{}\\{}", key_path, sid_str).encode_utf16().chain(std::iter::once(0)).collect();
            let mut sub_hkey = std::mem::zeroed();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(sub_path.as_ptr()), None, KEY_READ, &mut sub_hkey).is_err() {
                continue;
            }

            let mut data_len = 0u32;
            let mut data_type = REG_SZ;
            let _ = RegQueryValueExW(sub_hkey, PCWSTR::from_raw(val_name.as_ptr()), None, Some(&mut data_type), None, Some(&mut data_len));
            if data_len > 0 {
                let mut buf = vec![0u16; (data_len / 2) as usize];
                if RegQueryValueExW(sub_hkey, PCWSTR::from_raw(val_name.as_ptr()), None, None, Some(buf.as_mut_ptr() as *mut u8), Some(&mut data_len)).is_ok() {
                    let path = String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string();
                    if !path.is_empty() {
                        results.push((sid_str, path));
                    }
                }
            }
            let _ = RegCloseKey(sub_hkey);
        }
        let _ = RegCloseKey(hkey);
        Ok(results)
    }
}
