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

mod liveness;
mod passkey;
mod power_events;
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
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use liveness::{LivenessDecision, LivenessStatus, PassiveLiveness};
use opencv::{
    core::{Mat, Ptr, Rect, Size},
    objdetect::{FaceDetectorYN, FaceRecognizerSF},
    prelude::*,
    videoio::{self, VideoCapture},
};
use rusqlite::{params, types::ValueRef, Connection};
use serde::Deserialize;
use windows::Win32::{
    Foundation::{
        CloseHandle, GetLastError, BOOL, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
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
        RemoteDesktop::{
            ProcessIdToSessionId, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
            WTSQuerySessionInformationW, WTSQueryUserToken, WTSActive, WTSINFOEXW,
            WTSSessionInfoEx, WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK,
        },
        Shutdown::LockWorkStation,
        Threading::{
            CreateMutexW, CreateProcessAsUserW, ExitProcess, GetCurrentProcessId,
            GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
            STARTUPINFOW,
        },
    },
    UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
};
use windows_core::{PCWSTR, PWSTR};

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
const LOCK_WORKSTATION_ARG: &str = "--lock-workstation-once";
const QUERY_IDLE_ARG: &str = "--query-interactive-idle-once";
const IDLE_QUERY_ERROR_EXIT_CODE: u32 = u32::MAX;
/// UI（录入 / 一致性校验 / 预览）请求让位摄像头后，抑制预热 + 自动开摄像头的兜底时长（毫秒）。
/// UI 发 "ui_release" 时把 `camera_yield_until` 设为 now+此值，发 "ui_done"(stop_camera) 时清零。
/// 修复「录入采集黑屏」——后台预热(prewarm)占着摄像头时 UI open_camera 抢不到、只出黑帧；
/// 兜底超时应对 UI 崩溃未发 ui_done（超时后自动恢复预热，不影响秒解锁）。
const UI_CAMERA_YIELD_FALLBACK_MS: i64 = 60_000;

// ─── Shared state ─────────────────────────────────────────────────────────────

struct State {
    exe_dir:           PathBuf,
    should_exit:      AtomicBool,
    /// Condvar：退出时 notify_all() 唤醒所有等待线程，消除轮询。
    exit_cv:          Condvar,
    prepare_requested: AtomicBool,
    run_requested:    AtomicBool,
    /// `run_requested` 所属的电源代际。恢复后的新 run 可保留；挂起前遗留的 run 必须丢弃。
    run_power_generation: AtomicU64,
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
    /// 写入后通过 matched_creds_cv 唤醒等待凭据的 DLL 连接线程。
    matched_creds:    Mutex<Option<(String, String, String)>>,
    /// Condvar：face_recognition_loop 写入凭据后通知等待线程，消除 30ms 轮询。
    matched_creds_cv: Condvar,
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
    /// Windows 挂起/恢复状态。挂起期间所有摄像头路径必须保持关闭；generation 用于
    /// 中断跨越 Modern Standby 的旧捕获对象，并让恢复后的自动锁重新进入冷却。
    power: Arc<power_events::PowerLifecycle>,
    /// 浏览器 passkey assertion 的一次性人脸授权门。
    passkey_face_gate: Arc<passkey::FaceAuthorizationGate>,
    /// broker_guard_release 设置的预热抑制——必须在 release 或成功识别时清除，
    /// 不能由非 gate 路径自动清除（否则 passkey 场景下摄像头会被错误打开）。
    broker_guard_prewarm_blocked: AtomicBool,
}

impl State {
    fn new(exe_dir: PathBuf) -> Arc<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        Arc::new(Self {
            exe_dir,
            should_exit:     AtomicBool::new(false),
            exit_cv:         Condvar::new(),
            prepare_requested: AtomicBool::new(false),
            run_requested:   AtomicBool::new(false),
            run_power_generation: AtomicU64::new(0),
            recognition_active: AtomicBool::new(false),
            release_requested: AtomicBool::new(false),
            broker_guard_release_requested: AtomicBool::new(false),
            broker_guard_release_generation: AtomicU64::new(0),
            dll_creds_pipe:  AtomicIsize::new(INVALID_HANDLE_VALUE.0 as isize),
            matched_creds:   Mutex::new(None),
            matched_creds_cv: Condvar::new(),
            last_user_active: AtomicI64::new(now),
            active_pipe_handlers: AtomicUsize::new(0),
            dll_run_received: AtomicBool::new(false),
            last_successful_unlock_at: AtomicI64::new(0),
            consecutive_failures: AtomicU32::new(0),
            after_release_cooldown_until: AtomicI64::new(0),
            camera_yield_until: AtomicI64::new(0),
            power: Arc::new(power_events::PowerLifecycle::default()),
            passkey_face_gate: Arc::new(passkey::FaceAuthorizationGate::default()),
            broker_guard_prewarm_blocked: AtomicBool::new(false),
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

/// 日志文件最大大小 (5 MB)，超出后截断保留最近 ~2.5 MB。
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
/// 截断保留比例。
const LOG_KEEP_DIVISOR: u64 = 2;
/// 截断防重入：多线程并发写日志时只允许一个线程执行截断，其余线程跳过。
static LOG_TRUNCATING: AtomicBool = AtomicBool::new(false);

pub(crate) fn log_service(exe_dir: &Path, level: &str, message: &str) {
    let logs_dir = exe_dir.join("logs");
    let _ = create_dir_all(&logs_dir);
    let log_path = logs_dir.join("unlock.log");
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
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
        // 截断检查：多线程安全——用原子 CAS 确保只有一个线程执行截断。
        // 不检查 metadata 的线程直接跳过，零开销。
        if let Ok(meta) = file.metadata() {
            if meta.len() > MAX_LOG_BYTES
                && LOG_TRUNCATING
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                drop(file);
                // 后台线程执行截断，不阻塞当前调用者。
                let path = log_path.clone();
                let old_size = meta.len();
                thread::spawn(move || {
                    let _guard = TruncationGuard;
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let keep_bytes = MAX_LOG_BYTES as usize / LOG_KEEP_DIVISOR as usize;
                        let start = content.len().saturating_sub(keep_bytes);
                        // 对齐到 UTF-8 字符边界，避免截断产生乱码。
                        let mut boundary = start;
                        while boundary < content.len()
                            && !content.is_char_boundary(boundary)
                        {
                            boundary += 1;
                        }
                        let truncated = &content[boundary..];
                        let _ = std::fs::write(
                            &path,
                            format!(
                                "…[log truncated at {old_size} bytes, keeping last ~{keep_bytes} bytes]…\n{truncated}",
                            ),
                        );
                    }
                });
            }
        }
    }
}

/// 确保截断完成后重置原子标志——即使后台线程 panic 也不会永久阻塞后续截断。
struct TruncationGuard;
impl Drop for TruncationGuard {
    fn drop(&mut self) {
        LOG_TRUNCATING.store(false, Ordering::Release);
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
                if state.power.is_camera_blocked() {
                    control_buf.clear();
                    continue;
                }
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
                        state
                            .run_power_generation
                            .store(state.power.generation(), Ordering::SeqCst);
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
                    state.exit_cv.notify_all();
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

            // Condvar 等待凭据就绪（替代 30ms 轮询）：face_recognition_loop 写入
            // matched_creds 后 notify_all()，此线程立即唤醒。超时 500ms 仅用于探测
            // DLL 断连（PeekNamedPipe），避免凭据未就绪时永远阻塞。
            // ★ 关键：超时也检查 guard.take()——修复 Condvar 竞态：wait_timeout 到期
            // → 本线程解锁重入 → 解锁间隙 notify_all() 到达 → 信号丢失（#144）。
            // 解锁-重锁之间凭据可能已被写入，必须主动 take 而不是直接 continue。
            let guard = state.matched_creds.lock().unwrap();
            let (mut guard, timeout_result) = state
                .matched_creds_cv
                .wait_timeout(guard, Duration::from_millis(500))
                .unwrap();
            // 无论超时还是被唤醒，先检查凭据是否已就绪
            if let Some((username, password, domain)) = guard.take() {
                let payload = format!("{}\0{}\0{}\0", username, password, domain);
                let _ = pipe_write(pipe, payload.as_bytes());
                break;
            }
            if timeout_result.timed_out() {
                // 超时且无凭据：探测 DLL 是否仍连接
                let mut available = 0u32;
                if unsafe {
                    PeekNamedPipe(pipe, None, 0, None, Some(&mut available), None)
                }
                .is_err()
                {
                    log_service(&state.exe_dir, "INFO", "credential client disconnected");
                    break;
                }
            }
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
    if a.len() != b.len() || !a.len().is_multiple_of(4) { return 0.0; }
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
    liveness:   PassiveLiveness,
}

struct FaceObservation {
    feature:   Mat,
    face_rect: Rect,
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
    let liveness = PassiveLiveness::load(resources, inference.backend_id, inference.target_id)?;
    Ok(Models {
        detector,
        recognizer,
        liveness,
    })
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

/// 检测+提取特征，返回 None 表示无人脸或失败。
/// 同时保留检测框，供被动活体模型裁剪同一张脸，避免识别与活体检查对象不一致。
fn detect_and_extract(models: &mut Models, frame: &Mat) -> Option<FaceObservation> {
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

    let values = [
        *face_row.at_2d::<f32>(0, 0).ok()?,
        *face_row.at_2d::<f32>(0, 1).ok()?,
        *face_row.at_2d::<f32>(0, 2).ok()?,
        *face_row.at_2d::<f32>(0, 3).ok()?,
    ];
    if values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let left = (values[0].floor() as i32).clamp(0, frame.cols());
    let top = (values[1].floor() as i32).clamp(0, frame.rows());
    let right = ((values[0] + values[2]).ceil() as i32).clamp(left, frame.cols());
    let bottom = ((values[1] + values[3]).ceil() as i32).clamp(top, frame.rows());
    if right <= left || bottom <= top {
        return None;
    }

    Some(FaceObservation {
        feature,
        face_rect: Rect::new(left, top, right - left, bottom - top),
    })
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

fn warm_up_camera(cam: &mut VideoCapture, should_cancel: &impl Fn() -> bool) -> bool {
    let mut dummy = Mat::default();
    let mut ready_frames = 0usize;

    for _ in 0..CAMERA_WARMUP_MAX_FRAMES {
        if should_cancel() {
            return false;
        }
        if cam.read(&mut dummy).is_ok() && !dummy.empty() {
            ready_frames += 1;
            if ready_frames >= CAMERA_WARMUP_READY_FRAMES {
                break;
            }
        } else {
            ready_frames = 0;
        }
    }
    !should_cancel()
}

fn open_configured_camera(
    index: i32,
    exe_dir: &Path,
    should_cancel: impl Fn() -> bool,
) -> Option<(VideoCapture, &'static str)> {
    // 后端顺序必须与 UI 录入端 open_camera(None) 一致。v0.5.3 的 DShow 优先会造成
    // Win10 部分机器录入/解锁帧管线不一致；v0.5.4 的 CAP_ANY 优先又会在 issue #3
    // 的 Win10 机器上阻塞约 40 秒才亮摄像头。这里显式采用 UI 当前顺序并记录耗时，
    // 便于继续区分"打不开"和"某个后端打开过慢"。
    for (backend_name, backend) in [
        ("MSMF", videoio::CAP_MSMF),
        ("DShow", videoio::CAP_DSHOW),
        ("Any", videoio::CAP_ANY),
    ] {
        if should_cancel() {
            return None;
        }
        let started = Instant::now();
        if let Ok(mut c) = VideoCapture::new(index, backend) {
            if should_cancel() {
                return None;
            }
            if c.is_opened().unwrap_or(false) {
                let _ = c.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0);
                let _ = c.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0);
                if !warm_up_camera(&mut c, &should_cancel) {
                    return None;
                }
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

/// Prevents the just-finished credential session from reopening the camera
/// after a manual PIN/password unlock. The gate is cleared only after the old
/// credential client disconnects and a new one connects, or after an explicit
/// run request proves that a new unlock attempt is active.
#[derive(Default)]
struct PrewarmSessionGate {
    blocked_after_release: bool,
    saw_client_disconnect: bool,
}

impl PrewarmSessionGate {
    fn on_manual_release(&mut self) {
        self.blocked_after_release = true;
        self.saw_client_disconnect = false;
    }

    fn observe_credential_client(&mut self, connected: bool) -> bool {
        if !self.blocked_after_release {
            return false;
        }
        if !connected {
            self.saw_client_disconnect = true;
            return false;
        }
        if self.saw_client_disconnect {
            self.blocked_after_release = false;
            self.saw_client_disconnect = false;
            return true;
        }
        false
    }

    fn on_run(&mut self) {
        self.blocked_after_release = false;
        self.saw_client_disconnect = false;
    }

    fn blocks_prewarm(&self) -> bool {
        self.blocked_after_release
    }
}

#[cfg(test)]
mod prewarm_session_gate_tests {
    use super::PrewarmSessionGate;

    #[test]
    fn manual_release_stays_blocked_while_old_client_is_connected() {
        let mut gate = PrewarmSessionGate::default();
        gate.on_manual_release();

        assert!(gate.blocks_prewarm());
        assert!(!gate.observe_credential_client(true));
        assert!(gate.blocks_prewarm());
    }

    #[test]
    fn prewarm_resumes_only_after_disconnect_and_new_client() {
        let mut gate = PrewarmSessionGate::default();
        gate.on_manual_release();

        assert!(!gate.observe_credential_client(false));
        assert!(gate.blocks_prewarm());
        assert!(gate.observe_credential_client(true));
        assert!(!gate.blocks_prewarm());
    }

    #[test]
    fn explicit_run_unblocks_when_client_transition_was_not_observed() {
        let mut gate = PrewarmSessionGate::default();
        gate.on_manual_release();
        gate.on_run();

        assert!(!gate.blocks_prewarm());
    }
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
    // prewarm_suppressed = 空闲超时或释放后抑制预热，直到下次 run，或旧凭据客户端断开后
    // 新客户端连接（下一次凭据会话）。
    let mut prewarm_at: Option<Instant> = None;
    let mut prewarm_suppressed = false;
    let mut prewarm_session_gate = PrewarmSessionGate::default();
    let mut power_resume_requires_run = false;
    let mut observed_power_generation = state.power.generation();

    'main: loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let power_generation = state.power.generation();
        if power_generation != observed_power_generation {
            observed_power_generation = power_generation;
            let preserve_new_run = !state.power.is_camera_blocked()
                && state.run_requested.load(Ordering::SeqCst)
                && state.run_power_generation.load(Ordering::SeqCst) == power_generation;
            state.passkey_face_gate.reject_pending();
            cam = None;
            prewarm_at = None;
            prewarm_suppressed = true;
            power_resume_requires_run = true;
            state.broker_guard_prewarm_blocked.store(false, Ordering::SeqCst);
            delayed_run_at = None;
            delay_session_armed = false;
            last_failed_at = None;
            state.prepare_requested.store(false, Ordering::SeqCst);
            if !preserve_new_run {
                state.run_requested.store(false, Ordering::SeqCst);
                state.dll_run_received.store(false, Ordering::SeqCst);
            }
            state.recognition_active.store(false, Ordering::SeqCst);
            *state.matched_creds.lock().unwrap() = None;
            log_service(
                &exe_dir,
                "INFO",
                if state.power.is_camera_blocked() {
                    if state.power.is_suspended() {
                        "power suspend detected; camera closed and recognition paused"
                    } else {
                        "console display inactive; camera closed and recognition paused"
                    }
                } else {
                    "camera power gate cleared; stale camera state discarded"
                },
            );
        }
        if state.power.is_camera_blocked() {
            thread::sleep(Duration::from_millis(20));
            continue;
        }

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
            state.broker_guard_prewarm_blocked.store(true, Ordering::SeqCst);
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
            // 手动 PIN/密码解锁后，旧凭据客户端可能还会存活数百毫秒。若这里解除抑制，
            // 下方预热块会在同一秒重新打开摄像头。保持抑制，直到观察到旧客户端断开并有
            // 新客户端连接；显式 run 也可解除，确保极端竞态下下一次解锁仍可正常识别。
            prewarm_suppressed = true;
            state.broker_guard_prewarm_blocked.store(false, Ordering::SeqCst);
            prewarm_session_gate.on_manual_release();
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
            state.matched_creds_cv.notify_all();
            // 等待 DLL 消费（最多 30s）
            for _ in 0..300 {
                thread::sleep(Duration::from_millis(100));
                if state.matched_creds.lock().unwrap().is_none()
                    || state.should_exit.load(Ordering::SeqCst)
                    || state.power.generation() != observed_power_generation { break; }
            }
            continue;
        }

        let has_credential_client =
            state.dll_creds_pipe.load(Ordering::SeqCst) != INVALID_HANDLE_VALUE.0 as isize;
        if prewarm_session_gate.observe_credential_client(has_credential_client) {
            // power_resume_requires_run 仅当摄像头实际被阻断时才保持抑制——
            // 防止 Modern Standby 恢复后锁屏界面立刻预热。若摄像头未被阻断
            // 但标志仍为 true（虚假 power 事件、初始通知等），则解除。
            if !power_resume_requires_run || !state.power.is_camera_blocked() {
                prewarm_suppressed = false;
                power_resume_requires_run = false;
            }
            log_service(
                &exe_dir,
                "INFO",
                if prewarm_suppressed {
                    "new credential session; prewarm deferred (camera blocked)"
                } else {
                    "new credential session detected; camera prewarm re-enabled"
                },
            );
        }
        // Gate 未阻断（无 prior release）但预热仍被抑制的路径：电源事件/空闲超时/
        // 预热打开失败等原因设了 prewarm_suppressed=true，但 gate 未触发（blocked_after_release=false）
        // → 新凭据客户端已连且摄像头可用时清除抑制，恢复秒解锁预热。
        // 修复 Win+L 锁屏后移动鼠标要等 1-2s 摄像头才亮（rc5 回归）。
        // ★ broker_guard_release 也设 prewarm_suppressed=true 但不经 gate——
        //   必须用专用标记排除，否则 passkey 场景下摄像头会被错误打开（CRITICAL）。
        if has_credential_client && prewarm_suppressed && !prewarm_session_gate.blocks_prewarm()
            && !state.power.is_camera_blocked()
            && !state.broker_guard_prewarm_blocked.load(Ordering::SeqCst)
        {
            prewarm_suppressed = false;
            power_resume_requires_run = false;
            log_service(
                &exe_dir,
                "INFO",
                "camera prewarm re-enabled on new credential session (non-gate path)",
            );
        }
        if !has_credential_client && !state.recognition_active.load(Ordering::SeqCst) {
            delayed_run_at = None;
            delay_session_armed = false;
            power_resume_requires_run = false;
            // ★ broker_guard_prewarm_blocked 跨会话泄漏修复（CRITICAL）：
            //   passkey CredUI 结束→DLL 断开→标记仍为 true→下一次锁屏/密码填充
            //   的预热被非 gate 路径的 `!broker_guard_prewarm_blocked` 检查挡住，
            //   直到完整识别流程跑完才解除。DLL 断开时清除，新会话可立即预热。
            if state.broker_guard_prewarm_blocked.swap(false, Ordering::SeqCst) {
                log_service(
                    &exe_dir,
                    "INFO",
                    "broker_guard prewarm block cleared on credential client disconnect",
                );
            }
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
                && !prewarm_session_gate.blocks_prewarm()
                && has_credential_client
                // 没有任何启用面容时不存在可匹配目标，不应仅因锁屏界面出现就点亮摄像头。
                && !records.is_empty()
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
                && !state.power.is_camera_blocked()
            {
                let open_power_generation = state.power.generation();
                if let Some((c, backend_name)) = open_configured_camera(
                    camera_index,
                    &exe_dir,
                    || {
                        state.power.is_camera_blocked()
                            || state.power.generation() != open_power_generation
                            || state.should_exit.load(Ordering::SeqCst)
                            || state.release_requested.load(Ordering::SeqCst)
                    },
                ) {
                    if state.power.is_camera_blocked()
                        || state.power.generation() != open_power_generation
                    {
                        drop(c);
                        continue 'main;
                    }
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
        power_resume_requires_run = false;
        state.broker_guard_prewarm_blocked.store(false, Ordering::SeqCst);
        prewarm_session_gate.on_run();

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
            if state.power.is_camera_blocked() {
                state.recognition_active.store(false, Ordering::SeqCst);
                continue 'main;
            }
            let open_power_generation = state.power.generation();
            if let Some((c, backend_name)) = open_configured_camera(
                camera_index,
                &exe_dir,
                || {
                    state.power.is_camera_blocked()
                        || state.power.generation() != open_power_generation
                        || state.should_exit.load(Ordering::SeqCst)
                        || state.release_requested.load(Ordering::SeqCst)
                        || (passkey_request_id.is_none()
                            && state.broker_guard_release_requested.load(Ordering::SeqCst))
                },
            ) {
                if state.power.is_camera_blocked()
                    || state.power.generation() != open_power_generation
                {
                    drop(c);
                    continue 'main;
                }
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
                || state.power.is_camera_blocked()
                || state.power.generation() != observed_power_generation
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
                let mut liveness_candidate_id: Option<i64> = None;
                models
                    .as_mut()
                    .expect("models loaded before run")
                    .0
                    .liveness
                    .reset();
                while Instant::now() < hard_deadline {
                    if state.should_exit.load(Ordering::SeqCst)
                        || state.release_requested.load(Ordering::SeqCst)
                        || state.power.is_camera_blocked()
                        || state.power.generation() != observed_power_generation
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
                    let observation = match detect_and_extract(m, &frame) {
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
                    let cam_bytes = feature_to_bytes(&observation.feature);

                    let candidate = records.iter().find(|rec| {
                        let score = cosine_sim(&cam_bytes, &rec.feature_bytes);
                        score >= rec.threshold as f64 / 100.0
                    });
                    let Some(rec) = candidate else {
                        if liveness_candidate_id.take().is_some() {
                            m.liveness.reset();
                        }
                        thread::sleep(Duration::from_millis(30));
                        continue;
                    };

                    // 活体窗口只能聚合同一身份的帧；候选人变化时丢弃旧窗口。
                    if liveness_candidate_id != Some(rec.id) {
                        m.liveness.reset();
                        liveness_candidate_id = Some(rec.id);
                    }
                    let liveness = match m.liveness.observe(&frame, observation.face_rect) {
                        Ok(observation) => observation,
                        Err(error) => {
                            log_service(
                                &exe_dir,
                                "ERROR",
                                &format!(
                                    "passive liveness inference failed; refusing face authorization: {:?}",
                                    error
                                ),
                            );
                            break;
                        }
                    };
                    match liveness.status {
                        LivenessStatus::Collecting => {
                            thread::sleep(Duration::from_millis(60));
                            continue;
                        }
                        LivenessStatus::Ready(LivenessDecision::Live) => {}
                        LivenessStatus::Ready(
                            LivenessDecision::Spoof | LivenessDecision::Inconclusive,
                        ) => {
                            log_service(
                                &exe_dir,
                                "WARN",
                                "passive liveness rejected face authorization",
                            );
                            break;
                        }
                    }

                    if passkey_request_id.is_some() {
                        log_service(
                            &exe_dir,
                            "INFO",
                            &format!(
                                "face and passive liveness matched for passkey authorization: {}",
                                rec.user_name
                            ),
                        );
                    } else {
                        *state.matched_creds.lock().unwrap() = Some((
                            rec.user_name.clone(),
                            rec.user_pwd.clone(),
                            rec.domain.clone(),
                        ));
                        state.matched_creds_cv.notify_all();
                        log_service(
                            &exe_dir,
                            "INFO",
                            &format!("face and passive liveness matched for {}", rec.user_name),
                        );
                    }
                    matched_face_id = Some(rec.id);
                    // 更新活跃时间：人脸识别成功且活体通过，说明用户在。
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    state.last_user_active.store(now, Ordering::SeqCst);
                    if passkey_request_id.is_none() {
                        state.last_successful_unlock_at.store(now, Ordering::SeqCst);
                    }
                    matched = true;
                    // 仅提交密码凭据（Approach B）——所有场景统一走密码，登录/解锁秒过，
                    // CredUI 被拒时由 DLL 回退 Windows 原生 PIN。不再加载/注入存储 PIN。
                    break;
                }
            } // cap 在这里释放，cam borrow 结束

            if matched || saw_face { break; }
            // 无人脸：摄像头可能尚未预热，内部重试
            no_face_retries += 1;
            if no_face_retries < MAX_NO_FACE_RETRIES {
                if state.power.is_camera_blocked()
                    || state.power.generation() != observed_power_generation
                {
                    break;
                }
                log_service(&exe_dir, "INFO", &format!("no face in round {}, retrying ({}/{})", no_face_retries, no_face_retries + 1, MAX_NO_FACE_RETRIES));
                // 释放当前摄像头后重开，获取新数据流（take() 取出旧值并 drop，显式释放）
                drop(cam.take());
                if let Some((c, backend_name)) = open_configured_camera(
                    camera_index,
                    &exe_dir,
                    || {
                        state.power.is_camera_blocked()
                            || state.power.generation() != observed_power_generation
                            || state.should_exit.load(Ordering::SeqCst)
                            || state.release_requested.load(Ordering::SeqCst)
                    },
                ) {
                    if state.power.is_camera_blocked()
                        || state.power.generation() != observed_power_generation
                    {
                        drop(c);
                        break;
                    }
                    cam = Some(c);
                    log_service(&exe_dir, "INFO", &format!("camera reopened for retry via {}", backend_name));
                } else {
                    log_service(&exe_dir, "ERROR", "failed to reopen camera for retry");
                    break;
                }
            }
        }

        if state.power.is_camera_blocked()
            || state.power.generation() != observed_power_generation
        {
            if let Some(orig) = saved_brightness {
                set_brightness(orig);
            }
            state.recognition_active.store(false, Ordering::SeqCst);
            cam = None;
            continue 'main;
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

fn request_auto_lock(exe_dir: &Path) -> bool {
    // SYSTEM worker 位于 Session 0，不能直接调用只允许交互桌面的 LockWorkStation。
    // 在活动用户会话启动一次性 helper 发起锁定，再通过 WTSSessionInfoEx 确认结果。
    for attempt in 1..=3u32 {
        let session_id = match launch_lock_helper_in_active_session() {
            Ok(session_id) => session_id,
            Err(error) => {
                log_service(exe_dir, "WARN", &format!(
                    "auto-lock: interactive lock helper failed (attempt {attempt}): {error}"
                ));
                thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        log_service(exe_dir, "INFO", &format!(
            "auto-lock: lock request sent to interactive session {session_id}"
        ));
        let mut verification_error = None;
        for _ in 0..25 {
            thread::sleep(Duration::from_millis(200));
            match query_session_lock_state(session_id) {
                Ok(SessionLockState::Locked) => {
                    log_service(exe_dir, "INFO", "auto-lock: workstation locked");
                    return true;
                }
                Ok(SessionLockState::Unlocked | SessionLockState::Unknown) => {}
                Err(error) => verification_error = Some(error),
            }
        }
        if let Some(error) = verification_error {
            log_service(exe_dir, "WARN", &format!(
                "auto-lock: unable to verify session {session_id} state: {error}"
            ));
        }
        log_service(exe_dir, "WARN", &format!(
            "auto-lock: session {session_id} is not confirmed locked after attempt {attempt}"
        ));
    }

    let hint = if lock_workstation_disabled_by_policy() {
        "; DisableLockWorkstation policy is set — Windows forbids locking on this system"
    } else {
        ""
    };
    log_service(exe_dir, "ERROR", &format!(
        "auto-lock: failed to lock workstation after 3 attempts{hint}; next attempt in 60s"
    ));
    false
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
    // 根因：授权只更新 state.last_user_active，但不会重置交互会话的输入空闲时间；
    // 用户长时间不碰键鼠（看屏幕、读网页、盯终端）时，下一轮 OS idle 仍超时 → 又开摄像头。
    // 冷却时长取 max(60s, autoLockTimeout)：用户在场时按其设定的检测间隔周期性复查，
    // 而非固定每 60s 一次，把空闲期间摄像头亮起频率降到与 autoLockTimeout 一致（通常 5 分钟）。
    const AUTH_COOLDOWN_MIN: Duration = Duration::from_secs(60);
    let mut auth_cooldown_until: Option<Instant> = None;
    let mut last_idle_query_error_log = instant_secs_ago(60);
    let mut next_idle_probe_at = Instant::now();
    let mut observed_power_generation = state.power.generation();

    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }
        thread::sleep(Duration::from_secs(1));

        // 每 30 秒重新读取设置
        if last_config_check.elapsed() > Duration::from_secs(30) {
            let (enabled, timeout) = load_auto_lock_settings(&db_path);
            let settings_changed = enabled != auto_lock_enabled || timeout != auto_lock_timeout;
            auto_lock_enabled = enabled;
            auto_lock_timeout = timeout;
            if settings_changed {
                next_idle_probe_at = Instant::now();
                auth_cooldown_until = None;
            }
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

        let power_generation = state.power.generation();
        if power_generation != observed_power_generation {
            observed_power_generation = power_generation;
            next_idle_probe_at = Instant::now();
            if state.power.is_camera_blocked() {
                auth_cooldown_until = None;
                log_service(
                    &exe_dir,
                    "INFO",
                    if state.power.is_suspended() {
                        "auto-lock: paused for system suspend"
                    } else {
                        "auto-lock: console display inactive; camera checks disabled"
                    },
                );
            } else {
                let cooldown = AUTH_COOLDOWN_MIN.max(Duration::from_secs(auto_lock_timeout));
                auth_cooldown_until = Some(Instant::now() + cooldown);
                log_service(
                    &exe_dir,
                    "INFO",
                    &format!(
                        "auto-lock: resume grace active for {}s; camera remains closed",
                        cooldown.as_secs()
                    ),
                );
            }
            continue;
        }
        if state.power.is_suspended() { continue; }

        // 屏幕已锁（凭据提供程序活跃、DLL creds 管道已连）时不再自动锁屏：既避免对已锁屏幕
        // 重复锁定，也避免与解锁端「摄像头预热」抢占摄像头（autoLockTimeout 小于预热空闲超时
        // 时二者会争用同一摄像头，导致本复查开摄像头失败）。屏幕已锁时自动锁屏本就无意义。
        if state.dll_creds_pipe.load(Ordering::SeqCst) != INVALID_HANDLE_VALUE.0 as isize {
            continue;
        }

        // 人脸确认用户仍在场后的冷却期内不需要再次查询交互会话，也不开摄像头。
        if let Some(until) = auth_cooldown_until {
            if Instant::now() < until { continue; }
            auth_cooldown_until = None;
        }

        if Instant::now() < next_idle_probe_at {
            continue;
        }

        let idle_ms = match active_interactive_idle_millis() {
            Ok(idle_ms) => idle_ms,
            Err(error) => {
                if last_idle_query_error_log.elapsed() >= Duration::from_secs(60) {
                    log_service(
                        &exe_dir,
                        "WARN",
                        &format!(
                            "auto-lock: cannot read active-session idle time; skipping lock: {error}"
                        ),
                    );
                    last_idle_query_error_log = Instant::now();
                }
                next_idle_probe_at = Instant::now() + Duration::from_secs(5);
                continue;
            }
        };
        let timeout_ms = auto_lock_timeout.saturating_mul(1000);
        if idle_ms < timeout_ms {
            next_idle_probe_at = Instant::now()
                + Duration::from_millis(timeout_ms.saturating_sub(idle_ms).max(1_000));
            // 用户有真实键鼠输入，更新活跃时间并清空授权冷却（会话空闲时间已被真正重置）
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            state.last_user_active.store(now, Ordering::SeqCst);
            auth_cooldown_until = None;
            continue;
        }
        // 已到空闲阈值；后续准备失败时短暂退避，避免每秒启动交互会话 helper。
        next_idle_probe_at = Instant::now() + Duration::from_secs(5);

        // 空闲超时，且没有正在进行的解锁请求（避免冲突）
        if state.run_requested.load(Ordering::SeqCst) { continue; }
        if state.recognition_active.load(Ordering::SeqCst) { continue; }
        if state.dll_creds_pipe.load(Ordering::SeqCst) != INVALID_HANDLE_VALUE.0 as isize { continue; }

        // 先加载人脸记录。未录入人脸时保持既有行为，不启用本项目的自动锁屏。
        if last_record_reload.elapsed() > Duration::from_secs(60) {
            records = load_face_records(&exe_dir, &db_path);
            last_record_reload = Instant::now();
        }
        if records.is_empty() { continue; }

        // Modern Standby 从控制台屏幕关闭开始，且可能没有 PBT_APMSUSPEND。此时绝不打开
        // 摄像头；真实会话已空闲则直接锁屏。远控持续输入会在上面的 idle 检查中阻止此路径。
        if state.power.is_display_inactive() {
            match active_interactive_idle_millis() {
                Ok(latest_idle_ms) if latest_idle_ms < timeout_ms => {
                    next_idle_probe_at = Instant::now()
                        + Duration::from_millis(
                            timeout_ms.saturating_sub(latest_idle_ms).max(1_000),
                        );
                    continue;
                }
                Ok(_) => {}
                Err(error) => {
                    log_service(
                        &exe_dir,
                        "WARN",
                        &format!(
                            "auto-lock: display inactive but idle query failed; lock cancelled: {error}"
                        ),
                    );
                    next_idle_probe_at = Instant::now() + Duration::from_secs(5);
                    continue;
                }
            }
            log_service(
                &exe_dir,
                "INFO",
                "auto-lock: display inactive and session idle; locking without camera",
            );
            auth_cooldown_until = None;
            if request_auto_lock(&exe_dir) {
                thread::sleep(Duration::from_secs(5));
            } else {
                auth_cooldown_until = Some(Instant::now() + Duration::from_secs(60));
            }
            continue;
        }

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
        if state.power.is_camera_blocked() {
            log_service(
                &exe_dir,
                "INFO",
                "auto-lock: camera check cancelled by display or suspend transition",
            );
            continue;
        }
        let check_power_generation = state.power.generation();
        if let Some((c, backend_name)) = open_configured_camera(
            camera_index,
            &exe_dir,
            || {
                state.power.is_camera_blocked()
                    || state.power.generation() != check_power_generation
                    || state.should_exit.load(Ordering::SeqCst)
                    || state.run_requested.load(Ordering::SeqCst)
                    || state.recognition_active.load(Ordering::SeqCst)
                    || state.dll_creds_pipe.load(Ordering::SeqCst)
                        != INVALID_HANDLE_VALUE.0 as isize
            },
        ) {
            if state.power.is_camera_blocked()
                || state.power.generation() != check_power_generation
                || state.run_requested.load(Ordering::SeqCst)
                || state.recognition_active.load(Ordering::SeqCst)
                || state.dll_creds_pipe.load(Ordering::SeqCst)
                    != INVALID_HANDLE_VALUE.0 as isize
            {
                drop(c);
                log_service(&exe_dir, "INFO", "auto-lock: camera open cancelled by power or unlock activity");
                continue;
            }
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

        // 在场检测超时与退避：与主识别循环的 not_face_delay 策略一致。
        // 之前只扫 15 帧（～0.5-1.5s），摄像头传感器的自动曝光/白平衡可能尚在
        // 稳定期，导致人脸在画面中但检测不到 → 用户端坐电脑前却被误锁。
        // 现在用 not_face_delay 做"无人脸多久放弃"判断 + hard_deadline 做硬上限。
        let check_not_face_delay = load_not_face_delay(&db_path);
        let hard_deadline = Instant::now() + Duration::from_secs(10);
        let mut authorized = false;
        let mut camera_check_cancelled = false;
        let mut no_face_since: Option<Instant> = None;
        while Instant::now() < hard_deadline {
            if state.should_exit.load(Ordering::SeqCst) { break; }
            if state.power.is_camera_blocked()
                || state.power.generation() != check_power_generation
                || state.run_requested.load(Ordering::SeqCst)
                || state.recognition_active.load(Ordering::SeqCst)
                || state.dll_creds_pipe.load(Ordering::SeqCst)
                    != INVALID_HANDLE_VALUE.0 as isize
            {
                camera_check_cancelled = true;
                break;
            }
            let mut frame = Mat::default();
            if cap.read(&mut frame).is_err() || frame.empty() {
                let since = no_face_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= check_not_face_delay {
                    log_service(&exe_dir, "INFO", "auto-lock: no usable camera frame, timing out presence check");
                    break;
                }
                thread::sleep(Duration::from_millis(30));
                continue;
            }
            let frame = rotate_frame(&frame, camera_rotation).unwrap_or(frame);

            if let Some(observation) = detect_and_extract(models, &frame) {
                no_face_since = None;
                let cam_bytes = feature_to_bytes(&observation.feature);
                for rec in &records {
                    let score = cosine_sim(&cam_bytes, &rec.feature_bytes);
                    let threshold = rec.threshold as f64 / 100.0;
                    if score >= threshold {
                        authorized = true;
                        break;
                    }
                }
            } else {
                // 无人脸：记录首次无脸时刻，超时则放弃（与主识别循环一致）
                let since = no_face_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= check_not_face_delay {
                    log_service(&exe_dir, "INFO", "auto-lock: no face detected within timeout, giving up");
                    break;
                }
            }
            if authorized { break; }
            thread::sleep(Duration::from_millis(30));
        }
        // 释放摄像头
        drop(cam);
        if camera_check_cancelled {
            log_service(&exe_dir, "INFO", "auto-lock: presence check cancelled by power or unlock activity");
            continue;
        }

        // 初次在场检测未授权、且键鼠仍空闲 → 给一次重试机会。摄像头传感器从冷启动
        // 到自动曝光稳定有时需 3-5 秒；单次检测可能在传感器尚未就绪时结束。
        // 等待几秒后重新打开摄像头做第二次检测，覆盖传感器预热窗口。
        if !authorized {
            let retry_power_gen = state.power.generation();
            log_service(&exe_dir, "INFO", &format!(
                "auto-lock: first presence check failed; retrying after sensor warm-up delay (power_gen={retry_power_gen}, baseline={check_power_generation})"
            ));
            thread::sleep(Duration::from_secs(3));
            // 重试前复查状态
            if state.power.is_camera_blocked()
                || state.power.generation() != check_power_generation
                || state.run_requested.load(Ordering::SeqCst)
                || state.recognition_active.load(Ordering::SeqCst)
                || state.dll_creds_pipe.load(Ordering::SeqCst)
                    != INVALID_HANDLE_VALUE.0 as isize
            {
                continue;
            }
            if let Some((mut c2, backend2)) = open_configured_camera(
                camera_index,
                &exe_dir,
                || {
                    state.power.is_camera_blocked()
                        || state.power.generation() != check_power_generation
                        || state.run_requested.load(Ordering::SeqCst)
                        || state.recognition_active.load(Ordering::SeqCst)
                        || state.dll_creds_pipe.load(Ordering::SeqCst)
                            != INVALID_HANDLE_VALUE.0 as isize
                },
            ) {
                log_service(&exe_dir, "INFO", &format!("auto-lock: retry camera opened via {}", backend2));
                let retry_deadline = Instant::now() + Duration::from_secs(8);
                let mut no_face_retry: Option<Instant> = None;
                while Instant::now() < retry_deadline {
                    if state.power.is_camera_blocked()
                        || state.power.generation() != check_power_generation
                        || state.run_requested.load(Ordering::SeqCst)
                        || state.recognition_active.load(Ordering::SeqCst)
                        || state.dll_creds_pipe.load(Ordering::SeqCst)
                            != INVALID_HANDLE_VALUE.0 as isize
                    {
                        camera_check_cancelled = true;
                        break;
                    }
                    let mut frame = Mat::default();
                    if c2.read(&mut frame).is_err() || frame.empty() {
                        let since = no_face_retry.get_or_insert_with(Instant::now);
                        if since.elapsed() >= check_not_face_delay { break; }
                        thread::sleep(Duration::from_millis(30));
                        continue;
                    }
                    let frame = rotate_frame(&frame, camera_rotation).unwrap_or(frame);
                    if let Some(observation) = detect_and_extract(models, &frame) {
                        no_face_retry = None;
                        let cam_bytes = feature_to_bytes(&observation.feature);
                        for rec in &records {
                            let score = cosine_sim(&cam_bytes, &rec.feature_bytes);
                            let threshold = rec.threshold as f64 / 100.0;
                            if score >= threshold {
                                authorized = true;
                                break;
                            }
                        }
                    } else {
                        let since = no_face_retry.get_or_insert_with(Instant::now);
                        if since.elapsed() >= check_not_face_delay { break; }
                    }
                    if authorized { break; }
                    thread::sleep(Duration::from_millis(30));
                }
                drop(c2);
                if authorized {
                    log_service(&exe_dir, "INFO", "auto-lock: presence confirmed on retry");
                }
            }
        }
        if camera_check_cancelled {
            log_service(&exe_dir, "INFO", "auto-lock: presence check cancelled during retry");
            continue;
        }

        if authorized {
            // 授权用户在场，更新活跃时间并进入授权冷却：下一轮 OS idle 仍会超时
            // （人脸识别不重置交互会话输入计时），冷却避免反复开摄像头闪烁。
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
            // 摄像头检查期间可能刚好收到本地或远程输入。锁屏前必须重新读取一次，
            // 查询失败也要保守取消，不能把未知状态当作用户离开。
            match active_interactive_idle_millis() {
                Ok(latest_idle_ms) if latest_idle_ms < timeout_ms => {
                    next_idle_probe_at = Instant::now()
                        + Duration::from_millis(
                            timeout_ms.saturating_sub(latest_idle_ms).max(1_000),
                        );
                    log_service(
                        &exe_dir,
                        "INFO",
                        "auto-lock: interactive input resumed during presence check; lock cancelled",
                    );
                    continue;
                }
                Ok(_) => {}
                Err(error) => {
                    log_service(
                        &exe_dir,
                        "WARN",
                        &format!(
                            "auto-lock: final active-session idle query failed; lock cancelled: {error}"
                        ),
                    );
                    next_idle_probe_at = Instant::now() + Duration::from_secs(5);
                    continue;
                }
            }
            // 无人或非授权人员 → 锁屏，清空授权冷却（锁屏后下次需重新识别）
            log_service(&exe_dir, "INFO", "auto-lock: no authorized face, locking workstation");
            auth_cooldown_until = None;
            if request_auto_lock(&exe_dir) {
                thread::sleep(Duration::from_secs(5));
            } else {
                // 复用授权冷却做失败退避，避免每 7-8s 开摄像头复查的死循环
                auth_cooldown_until = Some(Instant::now() + Duration::from_secs(60));
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionLockState {
    Locked,
    Unlocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionSnapshot {
    lock_state: SessionLockState,
    idle_millis: Option<u64>,
}

const WTS_TIME_UNITS_PER_MILLISECOND: i64 = 10_000;

fn wts_idle_millis(current_time: i64, last_input_time: i64) -> Option<u64> {
    if current_time <= 0 || last_input_time <= 0 {
        return None;
    }
    let elapsed = current_time.checked_sub(last_input_time)?;
    if elapsed < 0 {
        return None;
    }
    u64::try_from(elapsed / WTS_TIME_UNITS_PER_MILLISECOND).ok()
}

fn session_lock_state_from_flags(flags: i32) -> SessionLockState {
    match flags as u32 {
        WTS_SESSIONSTATE_LOCK => SessionLockState::Locked,
        WTS_SESSIONSTATE_UNLOCK => SessionLockState::Unlocked,
        _ => SessionLockState::Unknown,
    }
}

fn prioritize_active_sessions(mut active: Vec<u32>, console_session: Option<u32>) -> Vec<u32> {
    if let Some(console) = console_session {
        if let Some(index) = active.iter().position(|session| *session == console) {
            active.swap(0, index);
        } else if active.is_empty() {
            active.push(console);
        }
    }
    active
}

fn active_session_ids() -> Result<Vec<u32>, String> {
    let mut session_ids = Vec::new();
    let mut sessions = std::ptr::null_mut();
    let mut count = 0u32;
    let enumeration = unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut sessions, &mut count) };
    if enumeration.is_ok() && !sessions.is_null() {
        let entries = unsafe { std::slice::from_raw_parts(sessions, count as usize) };
        for entry in entries {
            if entry.State == WTSActive && !session_ids.contains(&entry.SessionId) {
                session_ids.push(entry.SessionId);
            }
        }
    }
    if !sessions.is_null() {
        unsafe { WTSFreeMemory(sessions.cast()); }
    }

    // RDP 活跃时，物理控制台可能仍有用户令牌但已断开。优先使用枚举得到的
    // WTSActive 会话；仅在枚举没有活动项时回退到当前物理控制台。
    let console_session = match unsafe { WTSGetActiveConsoleSessionId() } {
        u32::MAX => None,
        session_id => Some(session_id),
    };
    session_ids = prioritize_active_sessions(session_ids, console_session);

    if session_ids.is_empty() {
        Err("no active interactive user session".to_string())
    } else {
        Ok(session_ids)
    }
}

fn active_interactive_idle_millis() -> Result<u64, String> {
    let session_ids = active_session_ids()?;
    let mut minimum = None;
    let mut failures = Vec::new();
    for &session_id in &session_ids {
        match query_session_snapshot(session_id) {
            Ok(SessionSnapshot {
                idle_millis: Some(idle_millis),
                ..
            }) => {
                minimum = Some(minimum.map_or(idle_millis, |idle: u64| idle.min(idle_millis)));
            }
            Ok(_) => failures.push(format!("session {session_id}: invalid WTS timestamps")),
            Err(error) => failures.push(format!("session {session_id}: {error}")),
        }
    }

    if let Some(idle_millis) = minimum {
        return Ok(idle_millis);
    }

    if current_process_session_id().is_some_and(|session_id| session_ids.contains(&session_id)) {
        return current_session_idle_millis()
            .map(u64::from)
            .ok_or_else(|| "GetLastInputInfo failed in the active interactive session".to_string());
    }

    query_idle_via_interactive_helper().map_err(|helper_error| {
        format!(
            "WTS LastInputTime unavailable ({}); {helper_error}",
            failures.join(", ")
        )
    })
}

fn query_active_user_token() -> Result<(u32, OwnedHandle), String> {
    let mut failures = Vec::new();
    for session_id in active_session_ids()? {
        let mut token = HANDLE::default();
        match unsafe { WTSQueryUserToken(session_id, &mut token) } {
            Ok(()) => return Ok((session_id, OwnedHandle(token))),
            Err(error) => {
                if !token.is_invalid() {
                    unsafe { let _ = CloseHandle(token); }
                }
                failures.push(format!("session {session_id}: {error:?}"));
            }
        }
    }
    Err(format!("WTSQueryUserToken failed ({})", failures.join(", ")))
}

fn launch_helper_in_active_session(
    argument: &str,
    timeout_ms: u32,
) -> Result<(u32, u32), String> {
    let (session_id, user_token) = query_active_user_token()?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve helper executable: {error}"))?;
    let executable_text = executable
        .to_str()
        .ok_or_else(|| "helper executable path is not valid UTF-8".to_string())?;
    let current_dir = executable
        .parent()
        .ok_or_else(|| "helper executable has no parent directory".to_string())?;

    let application = to_wide(executable_text);
    let mut command_line = to_wide(&format!("\"{executable_text}\" {argument}"));
    let mut desktop = to_wide("winsta0\\default");
    let current_dir = to_wide(current_dir
        .to_str()
        .ok_or_else(|| "lock helper working directory is not valid UTF-8".to_string())?);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();

    let launch_result = unsafe {
        CreateProcessAsUserW(
            Some(user_token.0),
            PCWSTR::from_raw(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCWSTR::from_raw(current_dir.as_ptr()),
            &startup,
            &mut process,
        )
    };

    let process_handle = OwnedHandle(process.hProcess);
    let _thread_handle = OwnedHandle(process.hThread);
    launch_result
        .map_err(|error| format!("CreateProcessAsUserW failed for session {session_id}: {error:?}"))?;
    match unsafe { WaitForSingleObject(process_handle.0, timeout_ms) } {
        WAIT_OBJECT_0 => {
            let mut exit_code = 1u32;
            unsafe { GetExitCodeProcess(process_handle.0, &mut exit_code) }
                .map_err(|error| format!("GetExitCodeProcess(helper) failed: {error:?}"))?;
            Ok((session_id, exit_code))
        }
        WAIT_TIMEOUT => Err(format!("helper {argument} timed out")),
        WAIT_FAILED => Err(format!(
            "waiting for lock helper failed: {:?}", unsafe { GetLastError() }
        )),
        other => Err(format!("unexpected helper wait result: {other:?}")),
    }
}

fn launch_lock_helper_in_active_session() -> Result<u32, String> {
    let (session_id, exit_code) =
        launch_helper_in_active_session(LOCK_WORKSTATION_ARG, 3_000)?;
    if exit_code != 0 {
        return Err(format!("lock helper exited with code {exit_code}"));
    }
    Ok(session_id)
}

fn query_idle_via_interactive_helper() -> Result<u64, String> {
    let (session_id, exit_code) = launch_helper_in_active_session(QUERY_IDLE_ARG, 3_000)?;
    if exit_code == IDLE_QUERY_ERROR_EXIT_CODE {
        Err(format!("interactive idle helper failed in session {session_id}"))
    } else {
        Ok(u64::from(exit_code))
    }
}

fn query_session_snapshot(session_id: u32) -> Result<SessionSnapshot, String> {
    let mut buffer = PWSTR::null();
    let mut bytes_returned = 0u32;
    let query_result = unsafe {
        WTSQuerySessionInformationW(
            None,
            session_id,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes_returned,
        )
    };
    if let Err(error) = query_result {
        if !buffer.is_null() {
            unsafe { WTSFreeMemory(buffer.0.cast()); }
        }
        return Err(format!("WTSQuerySessionInformationW failed: {error:?}"));
    }
    if buffer.is_null() {
        return Err("WTSSessionInfoEx returned a null buffer".to_string());
    }

    let result = if bytes_returned < std::mem::size_of::<WTSINFOEXW>() as u32 {
        Err(format!("WTSSessionInfoEx returned only {bytes_returned} bytes"))
    } else {
        let info = unsafe { &*(buffer.0.cast::<WTSINFOEXW>()) };
        if info.Level != 1 {
            Err(format!("unsupported WTSSessionInfoEx level {}", info.Level))
        } else {
            let level = unsafe { info.Data.WTSInfoExLevel1 };
            Ok(SessionSnapshot {
                lock_state: session_lock_state_from_flags(level.SessionFlags),
                idle_millis: wts_idle_millis(level.CurrentTime, level.LastInputTime),
            })
        }
    };
    unsafe { WTSFreeMemory(buffer.0.cast()); }
    result
}

fn query_session_lock_state(session_id: u32) -> Result<SessionLockState, String> {
    query_session_snapshot(session_id).map(|snapshot| snapshot.lock_state)
}

fn run_lock_workstation_helper() -> i32 {
    match unsafe { LockWorkStation() } {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn elapsed_input_millis(now: u32, last_input: u32) -> u32 {
    let elapsed = now.wrapping_sub(last_input);
    // A remotely injected INPUT can carry a timestamp slightly ahead of GetTickCount.
    // Treat the resulting half-range wrap as recent activity instead of a multi-day idle.
    if elapsed > i32::MAX as u32 { 0 } else { elapsed }
}

fn current_session_idle_millis() -> Option<u32> {
    let mut input = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    if !unsafe { GetLastInputInfo(&mut input) }.as_bool() {
        return None;
    }
    let now = unsafe { windows::Win32::System::SystemInformation::GetTickCount() };
    Some(elapsed_input_millis(now, input.dwTime))
}

fn current_process_session_id() -> Option<u32> {
    let mut session_id = u32::MAX;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
        .ok()
        .map(|_| session_id)
}

fn exit_with_current_session_idle() -> ! {
    let exit_code = current_session_idle_millis().unwrap_or(IDLE_QUERY_ERROR_EXIT_CODE);
    unsafe { ExitProcess(exit_code) }
}

#[cfg(test)]
mod auto_lock_session_tests {
    use super::{
        active_interactive_idle_millis, elapsed_input_millis, prioritize_active_sessions,
        session_lock_state_from_flags, wts_idle_millis, SessionLockState,
    };

    #[test]
    fn session_flags_distinguish_locked_unlocked_and_unknown() {
        assert_eq!(session_lock_state_from_flags(0), SessionLockState::Locked);
        assert_eq!(session_lock_state_from_flags(1), SessionLockState::Unlocked);
        assert_eq!(session_lock_state_from_flags(-1), SessionLockState::Unknown);
        assert_eq!(session_lock_state_from_flags(99), SessionLockState::Unknown);
    }

    #[test]
    fn active_rdp_session_wins_over_disconnected_console() {
        assert_eq!(prioritize_active_sessions(vec![2], Some(1)), vec![2]);
        assert_eq!(prioritize_active_sessions(vec![2, 1], Some(1)), vec![1, 2]);
        assert_eq!(prioritize_active_sessions(Vec::new(), Some(1)), vec![1]);
    }

    #[test]
    fn wts_timestamps_produce_session_idle_milliseconds() {
        let current = 50_000_000i64;
        assert_eq!(wts_idle_millis(current, 20_000_000), Some(3_000));
        assert_eq!(wts_idle_millis(current, current), Some(0));
        assert_eq!(wts_idle_millis(current, current + 1), None);
        assert_eq!(wts_idle_millis(0, 0), None);
    }

    #[test]
    fn future_input_timestamp_is_treated_as_recent_activity() {
        assert_eq!(elapsed_input_millis(1_000, 900), 100);
        assert_eq!(elapsed_input_millis(1_000, 1_001), 0);
        assert_eq!(elapsed_input_millis(5, u32::MAX - 4), 10);
    }

    #[test]
    #[ignore = "requires an active interactive Windows session"]
    fn active_session_idle_query_succeeds_in_interactive_session() {
        let idle = active_interactive_idle_millis()
            .expect("active interactive session should expose an idle time");
        println!("active session idle: {idle}ms");
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

    let _power_notifications = match power_events::register(state.power.clone()) {
        Ok(registration) => {
            log_service(&exe_dir, "INFO", "suspend/resume power notifications registered");
            Some(registration)
        }
        Err(error) => {
            state.power.inhibit_camera();
            log_service(
                &exe_dir,
                "ERROR",
                &format!("{error}; all camera paths are disabled for this worker"),
            );
            None
        }
    };

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

    if std::env::args().any(|arg| arg == LOCK_WORKSTATION_ARG) {
        std::process::exit(run_lock_workstation_helper());
    }
    if std::env::args().any(|arg| arg == QUERY_IDLE_ARG) {
        exit_with_current_session_idle();
    }

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

    if std::env::args().any(|arg| arg == WORKER_ARG) {
        std::process::exit(run_service_worker(exe_dir));
    }

    run_service_supervisor(exe_dir);
}
