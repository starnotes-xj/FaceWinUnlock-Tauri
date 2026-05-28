/*!
 * FaceWinUnlock-Server — 人脸解锁后台服务
 *
 * 管道拓扑:
 *   MansonWindowsUnlockRustServer  — 本进程作 Server，DLL 作 Client
 *       DLL 发送 "prepare" (初始化) / "run" (开始识别)
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
    videoio::VideoCapture,
};
use rusqlite::{types::ValueRef, Connection};
use serde::Deserialize;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
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

// ─── Shared state ─────────────────────────────────────────────────────────────

struct State {
    exe_dir:           PathBuf,
    should_exit:      AtomicBool,
    run_requested:    AtomicBool,
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
            run_requested:   AtomicBool::new(false),
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
    user_name:  String,
    user_pwd:   String,
    feature_bytes: Vec<u8>,
    threshold:  i64,   // 0~100，对应余弦相似度
    domain:     String,
}

#[derive(Default, Deserialize)]
struct JsonData {
    threshold: Option<i64>,
    view: Option<bool>,
    lock: Option<bool>,
    domain: Option<String>,
}

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

fn create_named_pipe(name: &str) -> windows::core::Result<HANDLE> {
    let wide = to_wide(name);
    let h = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUF_SIZE, BUF_SIZE, 0, None,
        )
    };
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
        thread::sleep(Duration::from_millis(20));
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

fn run_control_server(state: Arc<State>) {
    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let pipe = match create_named_pipe(PIPE_SERVER_NAME) {
            Ok(p) => p,
            Err(_) => { thread::sleep(Duration::from_secs(1)); continue; }
        };

        if wait_for_client(pipe).is_err() { close_handle(pipe); continue; }

        loop {
            if state.should_exit.load(Ordering::SeqCst) { break; }
            match pipe_read(pipe) {
                Ok(data) if !data.is_empty() => {
                    let cmd = String::from_utf8_lossy(&data);
                    if cmd.trim() == "run" {
                        state.run_requested.store(true, Ordering::SeqCst);
                    }
                }
                _ => break,
            }
        }

        unsafe { let _ = DisconnectNamedPipe(pipe); }
        close_handle(pipe);
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
    if peek_has_data(pipe, Duration::from_millis(200)) {
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
            thread::sleep(Duration::from_millis(100));
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
        "SELECT user_name, user_pwd, account_type, face_token, json_data FROM faces",
    ) { Ok(s) => s, Err(_) => return vec![] };

    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4).unwrap_or_default(),
        ))
    })
    .ok()
    .map(|rows| {
        rows.filter_map(|r| r.ok())
            .filter_map(|(u, p, account_type, t, j)| {
                let json = serde_json::from_str::<JsonData>(&j).unwrap_or_default();
                // 过滤已禁用（view=false）或已锁定（lock=true）的面容 (#103)
                if !json.view.unwrap_or(true) || json.lock.unwrap_or(false) {
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
                Some(FaceRecord { user_name: u, user_pwd: p, feature_bytes, threshold: thr, domain: dm })
            })
            .collect()
    })
    .unwrap_or_default()
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

fn load_models(resources: &Path) -> opencv::Result<Models> {
    let detector = FaceDetectorYN::create(
        resources.join("face_detection_yunet_2023mar.onnx").to_str().unwrap_or(""),
        "", Size::new(320, 320), 0.9, 0.3, 5000, 0, 0,
    )?;
    let recognizer = FaceRecognizerSF::create(
        resources.join("face_recognition_sface_2021dec.onnx").to_str().unwrap_or(""),
        "", 0, 0,
    )?;
    Ok(Models { detector, recognizer })
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

fn camera_candidates(db_path: &Path) -> Vec<i32> {
    let mut candidates: Vec<i32> = load_camera_index(db_path).into_iter().collect();
    for idx in 0..4i32 {
        if !candidates.contains(&idx) {
            candidates.push(idx);
        }
    }
    candidates
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

    let mut models = match load_models(&resources) { Ok(m) => m, Err(_) => return };
    let mut cam: Option<VideoCapture> = None;
    let mut records: Vec<FaceRecord> = vec![];
    let mut last_reload = Instant::now() - Duration::from_secs(60);
    let mut camera_rotation = load_camera_rotation(&db_path);
    let mut unlock_brightness = load_unlock_brightness(&db_path);

    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        if state.release_requested.swap(false, Ordering::SeqCst) {
            cam = None;
            log_service(&exe_dir, "INFO", "camera released");
            state.run_requested.store(false, Ordering::SeqCst);
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

        if !state.run_requested.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        state.run_requested.store(false, Ordering::SeqCst);

        // 定期重新加载人脸记录和配置
        if records.is_empty() || last_reload.elapsed() > Duration::from_secs(30) {
            records = load_face_records(&exe_dir, &db_path);
            camera_rotation = load_camera_rotation(&db_path);
            unlock_brightness = load_unlock_brightness(&db_path);
            last_reload = Instant::now();
        }
        if records.is_empty() {
            log_service(&exe_dir, "WARN", "run requested but no enabled face records found");
            cam = None;
            continue;
        }

        // 打开摄像头（首次或重新打开）
        if cam.is_none() {
            for idx in camera_candidates(&db_path) {
                if let Ok(mut c) = VideoCapture::new(idx, opencv::videoio::CAP_ANY) {
                    if c.is_opened().unwrap_or(false) {
                        // 设置默认帧尺寸 + 多帧预热（虚拟摄像头兼容 #94）
                        let _ = c.set(opencv::videoio::CAP_PROP_FRAME_WIDTH, 640.0);
                        let _ = c.set(opencv::videoio::CAP_PROP_FRAME_HEIGHT, 480.0);
                        let mut dummy = Mat::default();
                        for _ in 0..10 { let _ = c.read(&mut dummy); }
                        cam = Some(c);
                        log_service(&exe_dir, "INFO", &format!("camera opened at index {}", idx));
                        break;
                    }
                }
            }
        }
        let cap = match cam.as_mut() {
            Some(c) => c,
            None => {
                log_service(&exe_dir, "ERROR", "failed to open camera");
                continue;
            }
        };

        // 解锁前提升屏幕亮度（仅笔记本内置屏），识别结束后恢复
        let saved_brightness = if unlock_brightness > 0 {
            let orig = get_brightness();
            set_brightness(unlock_brightness);
            orig
        } else {
            None
        };

        // 识别循环（最多 60 帧 ≈ 5~10 秒）
        let mut matched = false;
        for _ in 0..60 {
            if state.should_exit.load(Ordering::SeqCst)
                || state.release_requested.load(Ordering::SeqCst) { break; }
            let mut frame = Mat::default();
            if cap.read(&mut frame).is_err() || frame.empty() {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            let frame = rotate_frame(&frame, camera_rotation).unwrap_or(frame);

            let cam_feat = match detect_and_extract(&mut models, &frame) {
                Some(f) => f,
                None => { thread::sleep(Duration::from_millis(100)); continue; }
            };
            let cam_bytes = feature_to_bytes(&cam_feat);

            for rec in &records {
                let score = cosine_sim(&cam_bytes, &rec.feature_bytes);
                let threshold = rec.threshold as f64 / 100.0;
                if score >= threshold {
                    *state.matched_creds.lock().unwrap() = Some((rec.user_name.clone(), rec.user_pwd.clone(), rec.domain.clone()));
                    log_service(&exe_dir, "INFO", &format!("face matched for {}", rec.user_name));
                    // 更新活跃时间：人脸识别成功说明用户在
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
                    state.last_user_active.store(now, Ordering::SeqCst);
                    matched = true;
                    break;
                }
            }
            if matched { break; }
            thread::sleep(Duration::from_millis(80));
        }

        // 识别结束，恢复原始亮度
        if let Some(orig) = saved_brightness {
            set_brightness(orig);
        }

        if matched {
            state.run_requested.store(false, Ordering::SeqCst);
        } else if !state.release_requested.load(Ordering::SeqCst) {
            log_service(&exe_dir, "WARN", "face recognition finished without a match");
        }
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

fn get_last_input_tick() -> u32 {
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe { let _ = GetLastInputInfo(&mut lii); }
    lii.dwTime
}

fn user_input_trigger_loop(state: Arc<State>) {
    let mut last_seen_tick = get_last_input_tick();

    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }

        let has_waiting_dll = state.dll_creds_pipe.load(Ordering::SeqCst)
            != INVALID_HANDLE_VALUE.0 as isize;
        if has_waiting_dll {
            let tick = get_last_input_tick();
            let idle_ms = get_idle_millis();
            if tick != last_seen_tick && idle_ms <= 1_500 {
                state.release_requested.store(false, Ordering::SeqCst);
                state.run_requested.store(true, Ordering::SeqCst);
            }
            last_seen_tick = tick;
        } else {
            last_seen_tick = get_last_input_tick();
        }

        thread::sleep(Duration::from_millis(100));
    }
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

    loop {
        if state.should_exit.load(Ordering::SeqCst) { break; }
        thread::sleep(Duration::from_secs(1));

        // 每 30 秒重新读取设置
        if last_config_check.elapsed() > Duration::from_secs(30) {
            let (enabled, timeout) = load_auto_lock_settings(&db_path);
            auto_lock_enabled = enabled;
            auto_lock_timeout = timeout;
            camera_rotation = load_camera_rotation(&db_path);
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
            models = load_models(&resources).ok();
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
        for idx in camera_candidates(&db_path) {
            if let Ok(mut c) = VideoCapture::new(idx, opencv::videoio::CAP_ANY) {
                if c.is_opened().unwrap_or(false) {
                    let _ = c.set(opencv::videoio::CAP_PROP_FRAME_WIDTH, 640.0);
                    let _ = c.set(opencv::videoio::CAP_PROP_FRAME_HEIGHT, 480.0);
                    let mut dummy = Mat::default();
                    for _ in 0..10 { let _ = c.read(&mut dummy); }
                    cam = Some(c);
                    break;
                }
            }
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

    let s_input = state.clone();
    thread::spawn(move || user_input_trigger_loop(s_input));

    let s3 = state.clone();
    let dir2 = exe_dir.clone();
    thread::spawn(move || auto_lock_monitor(s3, dir2));

    face_recognition_loop(state, exe_dir);
}
