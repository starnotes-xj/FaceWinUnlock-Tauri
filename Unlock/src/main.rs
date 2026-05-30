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

use std::{
    ffi::OsStr,
    fs::{create_dir_all, OpenOptions},
    io::Write,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicIsize, Ordering},
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
    Foundation::{CloseHandle, BOOL, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree},
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
    },
    UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
};
use windows_core::PCWSTR;

// ─── Constants ────────────────────────────────────────────────────────────────

const PIPE_SERVER_NAME: &str = r"\\.\pipe\MansonWindowsUnlockRustServer";
const PIPE_UNLOCK_NAME: &str = r"\\.\pipe\MansonWindowsUnlockRustUnlock";
const BUF_SIZE: u32 = 4096;
const CAMERA_WARMUP_MAX_FRAMES: usize = 4;
const CAMERA_WARMUP_READY_FRAMES: usize = 1;

// ─── Shared state ─────────────────────────────────────────────────────────────

struct State {
    exe_dir:           PathBuf,
    should_exit:      AtomicBool,
    prepare_requested: AtomicBool,
    run_requested:    AtomicBool,
    recognition_active: AtomicBool,
    release_requested: AtomicBool,
    /// DLL 在 MansonWindowsUnlockRustUnlock 上等待凭据的连接句柄（raw isize）
    dll_creds_pipe:   AtomicIsize,
    /// 人脸匹配到的 (username, password, domain)
    matched_creds:    Mutex<Option<(String, String, String)>>,
    /// 上一次用户活跃的时间戳（Unix 秒），用于自动锁屏
    last_user_active: AtomicI64,
}

impl State {
    fn new(exe_dir: PathBuf) -> Arc<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        Arc::new(Self {
            exe_dir,
            should_exit:     AtomicBool::new(false),
            prepare_requested: AtomicBool::new(false),
            run_requested:   AtomicBool::new(false),
            recognition_active: AtomicBool::new(false),
            release_requested: AtomicBool::new(false),
            dll_creds_pipe:  AtomicIsize::new(INVALID_HANDLE_VALUE.0 as isize),
            matched_creds:   Mutex::new(None),
            last_user_active: AtomicI64::new(now),
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

// HANDLE wraps *mut c_void which is not Send; safe because it's just a numeric handle
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}
impl SendHandle {
    // 使用方法避免 Rust 2021 partial capture 直接捕获 .0 字段
    fn take(self) -> HANDLE { self.0 }
}

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

fn log_service(exe_dir: &Path, level: &str, message: &str) {
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
                    if state.recognition_active.load(Ordering::SeqCst) {
                        log_service(&state.exe_dir, "INFO", "run ignored while recognition is active");
                    } else {
                        state.release_requested.store(false, Ordering::SeqCst);
                        state.run_requested.store(true, Ordering::SeqCst);
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

fn run_control_server(state: Arc<State>) {
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let pipe = match create_named_pipe(PIPE_SERVER_NAME) {
            Ok(p) => p,
            Err(_) => { thread::sleep(Duration::from_secs(1)); continue; }
        };

        if wait_for_client(pipe).is_err() { close_handle(pipe); continue; }

        let state2 = state.clone();
        let sendable = SendHandle(pipe);
        thread::spawn(move || handle_control_client(sendable.take(), state2));
    }
}

// ─── Unlock pipe server（MansonWindowsUnlockRustUnlock）──────────────────────

fn run_unlock_server(state: Arc<State>) {
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let pipe = match create_named_pipe(PIPE_UNLOCK_NAME) {
            Ok(p) => p,
            Err(_) => { thread::sleep(Duration::from_secs(1)); continue; }
        };

        if wait_for_client(pipe).is_err() { close_handle(pipe); continue; }

        let state2 = state.clone();
        let sendable = SendHandle(pipe);
        thread::spawn(move || handle_unlock_client(sendable.take(), state2));
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
                _ => {}
            }
        }
    } else {
        // DLL 客户端：替换旧句柄，等待写入凭据
        let old = state.dll_creds_pipe.swap(pipe.0 as isize, Ordering::SeqCst);
        if old != INVALID_HANDLE_VALUE.0 as isize {
            close_handle(HANDLE(old as *mut _));
        }
        log_service(&state.exe_dir, "INFO", "credential client connected");

        loop {
            if state.should_exit.load(Ordering::SeqCst) { break; }
            if state.release_requested.load(Ordering::SeqCst) { break; }
            if state.dll_creds_pipe.load(Ordering::SeqCst) != pipe.0 as isize { break; }
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

fn open_configured_camera(index: i32) -> Option<(VideoCapture, &'static str)> {
    // DShow 通常比 CAP_ANY 少一次后端枚举；失败时再退到 MSMF/Any，但始终只打开用户选择的索引。
    for (backend_name, backend) in [
        ("DShow", videoio::CAP_DSHOW),
        ("MSMF", videoio::CAP_MSMF),
        ("Any", videoio::CAP_ANY),
    ] {
        if let Ok(mut c) = VideoCapture::new(index, backend) {
            if c.is_opened().unwrap_or(false) {
                let _ = c.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0);
                let _ = c.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0);
                warm_up_camera(&mut c);
                return Some((c, backend_name));
            }
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

fn face_recognition_loop(state: Arc<State>, exe_dir: PathBuf) {
    let resources = exe_dir.join("resources");
    let db_path   = exe_dir.join("database.db");

    let mut requested_inference = load_inference_backend(&db_path);
    // 快速重试模型加载（3次，间隔 3s→5s→10s，总计 18s）。
    // 冷启动时 OpenCV 依赖短暂不可用属正常现象，但若 3 次均失败则表明持久性故障，
    // 继续等待无意义——直接退出，由计划任务 TimeTrigger（每 1 分钟）重新拉起进程。
    let (mut models, _) = {
        const RETRY_DELAYS: &[u64] = &[3, 5, 10];
        let mut loaded = None;
        for (i, &delay) in RETRY_DELAYS.iter().enumerate() {
            match load_models_with_fallback(&resources, requested_inference, &exe_dir) {
                Some(m) => {
                    loaded = Some(m);
                    break;
                }
                None => {
                    log_service(
                        &exe_dir,
                        "WARN",
                        &format!(
                            "model loading failed, retry {}/{} in {}s",
                            i + 1,
                            RETRY_DELAYS.len(),
                            delay
                        ),
                    );
                    std::thread::sleep(Duration::from_secs(delay));
                }
            }
        }
        match loaded {
            Some(m) => m,
            None => {
                log_service(&exe_dir, "ERROR", "failed to load opencv models after 3 retries, exiting (will be restarted by scheduled task)");
                return;
            }
        }
    };
    let mut cam: Option<VideoCapture> = None;
    let mut records: Vec<FaceRecord> = vec![];
    let mut last_reload = Instant::now() - Duration::from_secs(60);
    let mut camera_index = configured_camera_index(&db_path);
    let mut camera_rotation = load_camera_rotation(&db_path);
    let mut unlock_brightness = load_unlock_brightness(&db_path);
    let mut retry_delay = load_retry_delay(&db_path);
    let mut not_face_delay = load_not_face_delay(&db_path);
    let mut delayed_run_at: Option<Instant> = None;
    let mut delay_session_armed = false;
    let mut last_failed_at: Option<Instant> = None;

    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        if state.release_requested.swap(false, Ordering::SeqCst) {
            cam = None;
            delayed_run_at = None;
            delay_session_armed = false;
            last_failed_at = None;
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
                reload_models_if_inference_changed(
                    &resources,
                    &db_path,
                    &exe_dir,
                    &mut requested_inference,
                    &mut models,
                );
                last_reload = Instant::now();
                log_service(&exe_dir, "INFO", &format!("prepared unlock config for camera {}", camera_index));
            }
            if face_recog_type == "delay" {
                if !delay_session_armed {
                    delayed_run_at = Some(Instant::now() + face_recog_delay);
                    delay_session_armed = true;
                    log_service(
                        &exe_dir,
                        "INFO",
                        &format!(
                            "delayed face recognition scheduled after {:.1}s",
                            face_recog_delay.as_secs_f64()
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

        if !state.run_requested.swap(false, Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(30));
            continue;
        }

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
        state.recognition_active.store(true, Ordering::SeqCst);

        // 定期重新加载人脸记录和配置
        if records.is_empty() || last_reload.elapsed() > Duration::from_secs(30) {
            records = load_face_records(&exe_dir, &db_path);
            camera_index = configured_camera_index(&db_path);
            camera_rotation = load_camera_rotation(&db_path);
            unlock_brightness = load_unlock_brightness(&db_path);
            retry_delay = load_retry_delay(&db_path);
            not_face_delay = load_not_face_delay(&db_path);
            reload_models_if_inference_changed(
                &resources,
                &db_path,
                &exe_dir,
                &mut requested_inference,
                &mut models,
            );
            last_reload = Instant::now();
        }
        if records.is_empty() {
            log_service(&exe_dir, "WARN", "run requested but no enabled face records found");
            state.run_requested.store(false, Ordering::SeqCst);
            state.recognition_active.store(false, Ordering::SeqCst);
            cam = None;
            continue;
        }

        // 打开首选项中保存的摄像头索引，避免每次解锁都扫描 0-3 号设备。
        if cam.is_none() {
            if let Some((c, backend_name)) = open_configured_camera(camera_index) {
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
                || state.release_requested.load(Ordering::SeqCst) { break; }

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
                        || state.release_requested.load(Ordering::SeqCst) { break; }
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

                    let cam_feat = match detect_and_extract(&mut models, &frame) {
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
                            *state.matched_creds.lock().unwrap() = Some((rec.user_name.clone(), rec.user_pwd.clone(), rec.domain.clone()));
                            log_service(&exe_dir, "INFO", &format!("face matched for {}", rec.user_name));
                            matched_face_id = Some(rec.id);
                            // 更新活跃时间：人脸识别成功说明用户在
                            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
                            state.last_user_active.store(now, Ordering::SeqCst);
                            matched = true;
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
                // 释放当前摄像头，重新打开获取新数据流
                cam = None;
                if let Some((c, backend_name)) = open_configured_camera(camera_index) {
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

        if matched {
            insert_unlock_log(&db_path, &exe_dir, matched_face_id, true, None);
            last_failed_at = None;
            state.run_requested.store(false, Ordering::SeqCst);
        } else if !state.release_requested.load(Ordering::SeqCst) {
            if saw_face {
                insert_unlock_log(&db_path, &exe_dir, None, false, None);
            }
            last_failed_at = Some(Instant::now());
            log_service(&exe_dir, "WARN", "face recognition finished without a match");
        }
        state.run_requested.store(false, Ordering::SeqCst);
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
    let mut last_record_reload = Instant::now() - Duration::from_secs(60);
    let mut camera_rotation = load_camera_rotation(&db_path);
    let mut requested_inference = load_inference_backend(&db_path);

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

        let idle_ms = get_idle_millis();
        if idle_ms < (auto_lock_timeout * 1000) as u32 {
            // 用户有活动，更新最后活跃时间
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            state.last_user_active.store(now, Ordering::SeqCst);
            continue;
        }

        // 空闲超时，且没有正在进行的解锁请求（避免冲突）
        if state.run_requested.load(Ordering::SeqCst) { continue; }

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

        // 打开摄像头做一次验证（最多 15 帧 ≈ 2~3 秒）
        let mut cam: Option<VideoCapture> = None;
        let camera_index = configured_camera_index(&db_path);
        if let Some((c, _)) = open_configured_camera(camera_index) {
            cam = Some(c);
        }
        let cap = match cam.as_mut() { Some(c) => c, None => continue };

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
            // 授权用户在场，更新活跃时间，继续监控
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            state.last_user_active.store(now, Ordering::SeqCst);
        } else {
            // 无人或非授权人员 → 锁屏
            let _ = unsafe { LockWorkStation() };
            // 锁屏后等 5 秒再继续检查
            thread::sleep(Duration::from_secs(5));
        }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let state = State::new(exe_dir.clone());
    log_service(&exe_dir, "INFO", "FaceWinUnlock service started");

    let s1 = state.clone();
    thread::spawn(move || run_control_server(s1));

    let s2 = state.clone();
    thread::spawn(move || run_unlock_server(s2));

    let s3 = state.clone();
    let dir2 = exe_dir.clone();
    thread::spawn(move || auto_lock_monitor(s3, dir2));

    face_recognition_loop(state, exe_dir);
}
