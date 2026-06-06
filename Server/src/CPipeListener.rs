use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::{
    Shell::ICredentialProviderEvents,
    WindowsAndMessaging::{
        CallNextHookEx, HHOOK, SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL,
        WH_MOUSE_LL,
    },
};

use crate::animation::{AnimState, AnimationSlot};
use crate::{read_facewinunlock_registry, SharedCredentials};
use crate::Pipe::{
    parse_credentials,
    pipe_connect_to_server_with_stop, pipe_read_raw, pipe_write_raw,
    PIPE_SERVER_NAME, PIPE_UNLOCK_NAME,
};

// ICredentialProviderEvents 是 COM 接口，默认不是 Send。
// Credential Provider 运行在 winlogon.exe 中，该接口实际上支持跨线程调用。
struct SendableEvents(ICredentialProviderEvents, usize);
unsafe impl Send for SendableEvents {}

impl SendableEvents {
    fn notify_changed(&self) -> windows::core::Result<()> {
        unsafe { self.0.CredentialsChanged(self.1) }
    }
}

/// 通过 AnimationSlot 设置动画状态（槽位为空时静默忽略）
fn set_anim_state(slot: &AnimationSlot, state: AnimState) {
    if let Ok(guard) = slot.lock() {
        if let Some(ctx) = guard.as_ref() {
            ctx.set_state(state);
        }
    }
}

/// 可中断 sleep：按 200ms 轮询 stop_flag，避免 stop_and_join 时被长 sleep 卡死。
/// 返回 true 表示因 stop_flag 提前结束，false 表示完整睡完。
fn interruptible_sleep(duration: Duration, stop_flag: &AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    let tick = Duration::from_millis(200);
    loop {
        if stop_flag.load(Ordering::SeqCst) { return true; }
        let now = Instant::now();
        if now >= deadline { return false; }
        thread::sleep(deadline.saturating_duration_since(now).min(tick));
    }
}

fn broker_fallback_timeout() -> Duration {
    let seconds = read_facewinunlock_registry("CREDUI_BROKER_FALLBACK_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(5.0)
        .clamp(1.5, 30.0);
    Duration::from_millis((seconds * 1000.0) as u64)
}

pub fn request_unlock_release(reason: &str) {
    info!("CPipeListener - 请求 Unlock EXE 释放摄像头: {}", reason);
    use crate::Pipe::{pipe_connect_to_server, pipe_write_raw, PIPE_UNLOCK_NAME};
    if let Ok(pipe) = pipe_connect_to_server(PIPE_UNLOCK_NAME, 1_000) {
        let _ = pipe_write_raw(pipe, b"release");
        unsafe { let _ = CloseHandle(pipe); }
    }
}

fn trigger_broker_pin_fallback(
    shared_creds: &Arc<Mutex<SharedCredentials>>,
    stop_flag: &AtomicBool,
    creds_pipe_raw: &AtomicIsize,
    send_events: &SendableEvents,
    animation_slot: &AnimationSlot,
    reason: &str,
) {
    let already_fallback = {
        let mut creds = shared_creds.lock().unwrap();
        if creds.broker_fallback_to_pin {
            true
        } else {
            creds.username.clear();
            creds.password.clear();
            creds.is_ready = false;
            creds.is_unlocked = false;
            creds.broker_fallback_to_pin = true;
            false
        }
    };

    if already_fallback {
        return;
    }

    warn!("CPipeListener - broker 人脸验证未完成，回退 Windows PIN: {}", reason);

    // 全局标记 + disarm 钩子（路径 A：面容识别超时）
    mark_broker_pin_fallback();

    set_anim_state(animation_slot, AnimState::Failure);
    request_unlock_release(reason);
    stop_flag.store(true, Ordering::SeqCst);

    let raw = creds_pipe_raw.swap(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
    if raw != INVALID_HANDLE_VALUE.0 as isize {
        unsafe { let _ = CloseHandle(HANDLE(raw as *mut _)); }
    }

    if let Err(e) = send_events.notify_changed() {
        error!("CPipeListener - 触发 PIN 回退重枚举失败: {:?}", e);
    }
}

// 0.3.3 的核心经验：锁屏桌面运行在 winlogon 中，Credential Provider DLL
// 直接安装低级鼠标/键盘 hook 才能稳定拿到锁屏输入事件。
static MOUSE_HOOK_RAW: AtomicIsize = AtomicIsize::new(0);
static KEYBOARD_HOOK_RAW: AtomicIsize = AtomicIsize::new(0);
static IS_MOUSE_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static IS_KEYBOARD_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static INPUT_HOOKS_ARMED: AtomicBool = AtomicBool::new(false);
static INPUT_RUN_REQUESTED: AtomicBool = AtomicBool::new(false);
static INPUT_RUN_SOURCE: AtomicU8 = AtomicU8::new(0);
static INPUT_HOOK_REF_COUNT: AtomicUsize = AtomicUsize::new(0);
const INPUT_SOURCE_MOUSE: u8 = 1;
const INPUT_SOURCE_KEYBOARD: u8 = 2;

/// 全局标记：broker CredUI 场景（credentialuibroker.exe）已永久回退 PIN。
///
/// 一旦置为 true，当前进程中所有 CPipeListener 实例的面容识别将被彻底抑制：
/// - 客户端线程停止发送 "run"，disarm 钩子后退出
/// - 新实例的钩子不会被 arm
///
/// 两条触发路径：
/// A) trigger_broker_pin_fallback — 面容识别超时
/// B) ReportResult — 凭据被 Windows 拒绝（如 passkey 场景）
static BROKER_PIN_FALLBACK_GLOBAL: AtomicBool = AtomicBool::new(false);

/// 公开函数：标记 broker PIN 回退 + 立即 disarm 全局钩子。
/// 由 CSampleCredential::ReportResult 调用（凭据被拒绝路径）。
pub fn mark_broker_pin_fallback() {
    BROKER_PIN_FALLBACK_GLOBAL.store(true, Ordering::SeqCst);
    INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
    INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
}

unsafe extern "system" fn mouse_hook_fn(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && INPUT_HOOKS_ARMED.load(Ordering::SeqCst) {
        INPUT_RUN_SOURCE.store(INPUT_SOURCE_MOUSE, Ordering::SeqCst);
        INPUT_RUN_REQUESTED.store(true, Ordering::SeqCst);
    }
    let raw = MOUSE_HOOK_RAW.load(Ordering::SeqCst);
    let hook = (raw != 0).then(|| HHOOK(raw as *mut _));
    unsafe { CallNextHookEx(hook, code, wparam, lparam) }
}

unsafe extern "system" fn keyboard_hook_fn(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && INPUT_HOOKS_ARMED.load(Ordering::SeqCst) {
        INPUT_RUN_SOURCE.store(INPUT_SOURCE_KEYBOARD, Ordering::SeqCst);
        INPUT_RUN_REQUESTED.store(true, Ordering::SeqCst);
    }
    let raw = KEYBOARD_HOOK_RAW.load(Ordering::SeqCst);
    let hook = (raw != 0).then(|| HHOOK(raw as *mut _));
    unsafe { CallNextHookEx(hook, code, wparam, lparam) }
}

fn install_input_hooks() {
    let previous_refs = INPUT_HOOK_REF_COUNT.fetch_add(1, Ordering::SeqCst);
    if previous_refs == 0 {
        INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
        INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
        INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
    }

    if IS_MOUSE_HOOK_INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        match unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook_fn), None, 0) } {
            Ok(hook) => {
                MOUSE_HOOK_RAW.store(hook.0 as isize, Ordering::SeqCst);
                info!("锁屏鼠标输入 Hook 已安装");
            }
            Err(e) => {
                IS_MOUSE_HOOK_INSTALLED.store(false, Ordering::SeqCst);
                error!("设置鼠标 Hook 失败: {:?}", e);
            }
        }
    }

    if IS_KEYBOARD_HOOK_INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        match unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook_fn), None, 0) } {
            Ok(hook) => {
                KEYBOARD_HOOK_RAW.store(hook.0 as isize, Ordering::SeqCst);
                info!("锁屏键盘输入 Hook 已安装");
            }
            Err(e) => {
                IS_KEYBOARD_HOOK_INSTALLED.store(false, Ordering::SeqCst);
                error!("设置键盘 Hook 失败: {:?}", e);
            }
        }
    }
}

fn uninstall_input_hooks() {
    let Ok(previous_refs) = INPUT_HOOK_REF_COUNT.fetch_update(
        Ordering::SeqCst,
        Ordering::SeqCst,
        |count| (count > 0).then_some(count - 1),
    ) else {
        return;
    };

    if previous_refs > 1 {
        return;
    }

    INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
    INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
    INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);

    if IS_MOUSE_HOOK_INSTALLED
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let raw = MOUSE_HOOK_RAW.swap(0, Ordering::SeqCst);
        if raw != 0 {
            let _ = unsafe { UnhookWindowsHookEx(HHOOK(raw as *mut _)) };
        }
    }

    if IS_KEYBOARD_HOOK_INSTALLED
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let raw = KEYBOARD_HOOK_RAW.swap(0, Ordering::SeqCst);
        if raw != 0 {
            let _ = unsafe { UnhookWindowsHookEx(HHOOK(raw as *mut _)) };
        }
    }
}

pub struct CPipeListener {
    pub is_unlocked: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    client_thread: Option<JoinHandle<()>>,
    creds_thread: Option<JoinHandle<()>>,
    /// 保存凭据线程当前持有的管道句柄原始值（isize），用于 stop_and_join 时关闭句柄打断 ReadFile
    creds_pipe_raw: Arc<AtomicIsize>,
    /// 是否安装了鼠标/键盘 Hook。所有已启用场景都可用 Hook 触发 run，CREDUI 额外保留自动 run 兜底。
    use_input_hooks: bool,
}

impl CPipeListener {
    /// 启动管道监听：
    ///   - Client 线程：连接到 Unlock EXE 的 Server 管道，先发送 "prepare"；
    ///     所有已启用场景都可由 DLL 低级输入 Hook 捕获鼠标/键盘事件后发送 "run"
    ///   - Creds 线程：阻塞等待凭据推送，收到后设置动画为 Success
    pub fn start(
        events: ICredentialProviderEvents,
        advise_context: usize,
        shared_creds: Arc<Mutex<SharedCredentials>>,
        is_primary_scenario: bool,
        broker_fallback_to_pin: bool,
        animation_slot: AnimationSlot,
    ) -> Arc<Mutex<Self>> {
        let is_unlocked    = Arc::new(AtomicBool::new(false));
        let stop_flag      = Arc::new(AtomicBool::new(false));
        // 存储当前凭据管道句柄原始值（INVALID_HANDLE_VALUE.0 as isize 表示无效）
        let creds_pipe_raw = Arc::new(AtomicIsize::new(INVALID_HANDLE_VALUE.0 as isize));
        let use_input_hooks = true;
        // 所有场景（登录/解锁/CREDUI）统一由鼠标/键盘输入 Hook 触发 "run"，不自动开始识别。
        // 不启用 auto_run 的原因：① 锁屏后人未走开即被自动解锁，削弱锁屏安全意义（且
        //   UNLOCK_GRACE_PERIOD 常为 0，锁了立刻就识别）；② 开机时可能在 explorer/系统就绪
        //   前就提交凭据登录，导致转圈卡死；③ 摄像头常开耗电。用户走到机前本就会动一下
        //   鼠标/键盘，这一下正好表达解锁意图、再秒级识别——成本极低且更安全稳定。
        let auto_run_on_connect = false;
        if use_input_hooks {
            install_input_hooks();
        }
        let scenario_label = if is_primary_scenario { "登录/解锁" } else { "CREDUI/UAC" };

        // ── Client 线程（发送 prepare；输入 Hook 触发后发送 run）────────────────────
        let client_thread = {
            let stop_flag = stop_flag.clone();
            let anim_slot = animation_slot.clone();
            let is_unlocked_for_client = is_unlocked.clone();
            let shared_creds_for_client = shared_creds.clone();
            let creds_pipe_raw_for_client = creds_pipe_raw.clone();
            let send_events_for_client = SendableEvents(events.clone(), advise_context);
            let broker_timeout = broker_fallback_timeout();
            thread::spawn(move || {
                let connect_enabled = read_facewinunlock_registry("CONNECT_TO_PIPE")
                    .unwrap_or_else(|_| "1".to_string());
                if connect_enabled != "1" {
                    info!("CPipeListener - CONNECT_TO_PIPE 未启用，跳过管道连接");
                    return;
                }

                // Broker CredUI 场景（credentialuibroker.exe）：
                // 先尝试面容识别，超时后回退 Windows PIN。
                // 无法精准区分 passkey vs 密码（需 UIA COM 跨进程调用，在
                // 凭据提供程序沙箱中极易死锁），统一走面容→超时→PIN 路径。
                // Passkey 场景会因无人脸匹配超时自动回退 PIN。
                if broker_fallback_to_pin {
                    info!("CPipeListener - broker CredUI 场景：先面容，超时回退 PIN");
                }

                info!("CPipeListener::start - 进入管道Client线程");

                let mut first_connect = true;

                // 外层重连循环 — 处理 Unlock EXE 崩溃重启 (#113)
                // Client 线程持续运行直到 stop_flag，不依赖 is_unlocked 退出
                loop {
                    if stop_flag.load(Ordering::SeqCst) { break; }

                    let is_first = first_connect;
                    let timeout: u64 = if is_first { 30_000 } else { 10_000 };
                    let pipe = match pipe_connect_to_server_with_stop(PIPE_SERVER_NAME, timeout, Some(&stop_flag)) {
                        Ok(p)  => p,
                        Err(e) => {
                            if stop_flag.load(Ordering::SeqCst) {
                                info!("连接管道服务器被取消");
                                break;
                            }
                            if is_first {
                                warn!("首次连接管道服务器失败（Unlock EXE 可能尚未启动），继续重试: {:?}", e);
                                first_connect = false;
                            } else {
                                warn!("重连管道服务器失败: {:?}，1秒后重试", e);
                            }
                            if interruptible_sleep(Duration::from_secs(1), &stop_flag) { break; }
                            continue;
                        }
                    };
                    first_connect = false;

                    if let Err(e) = pipe_write_raw(pipe, b"prepare") {
                        error!("写入 prepare 失败: {:?}", e);
                        unsafe { let _ = CloseHandle(pipe); }
                        if interruptible_sleep(Duration::from_secs(5), &stop_flag) { break; }
                        continue;
                    }
                    info!("向管道写入数据成功：prepare");

                    let mut hooks_armed = !use_input_hooks;
                    let arm_after = Instant::now() + Duration::from_millis(250);
                    let min_run_interval = if auto_run_on_connect {
                        Duration::from_millis(2500)
                    } else {
                        Duration::from_millis(1500)
                    };
                    let mut last_run_at = Instant::now() - min_run_interval;
                    let mut last_prepare_at = Instant::now();
                    let mut auto_run_sent = false;
                    let mut broker_first_run_at: Option<Instant> = None;
                    if use_input_hooks {
                        INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
                        INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
                        INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
                    }

                    loop {
                        if stop_flag.load(Ordering::SeqCst)
                            || BROKER_PIN_FALLBACK_GLOBAL.load(Ordering::SeqCst)
                        {
                            if use_input_hooks {
                                INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
                                INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
                                INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
                            }
                            unsafe { let _ = CloseHandle(pipe); }
                            info!("面容识别已停止（stop={}, broker_fallback={}）",
                                stop_flag.load(Ordering::SeqCst),
                                BROKER_PIN_FALLBACK_GLOBAL.load(Ordering::SeqCst));
                            return;
                        }
                        if is_unlocked_for_client.load(Ordering::SeqCst) {
                            if use_input_hooks {
                                INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
                                INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
                                INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
                            }
                            unsafe { let _ = CloseHandle(pipe); }
                            info!("面容识别已成功，停止发送 run");
                            return;
                        }

                        if use_input_hooks && !hooks_armed && Instant::now() >= arm_after
                            && !BROKER_PIN_FALLBACK_GLOBAL.load(Ordering::SeqCst)
                        {
                            INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
                            INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
                            INPUT_HOOKS_ARMED.store(true, Ordering::SeqCst);
                            hooks_armed = true;
                            info!("{} 输入 Hook 已就绪，等待鼠标/键盘触发识别", scenario_label);
                        }

                        let input_requested = use_input_hooks
                            && INPUT_RUN_REQUESTED.swap(false, Ordering::SeqCst);
                        let input_source = if input_requested {
                            INPUT_RUN_SOURCE.swap(0, Ordering::SeqCst)
                        } else {
                            0
                        };
                        let auto_requested = auto_run_on_connect && !auto_run_sent;
                        let should_send_run = hooks_armed
                            && last_run_at.elapsed() >= min_run_interval
                            && (input_requested || auto_requested);

                        if should_send_run {
                            if let Err(e) = pipe_write_raw(pipe, b"run") {
                                warn!("发送 run 失败: {:?}，Unlock EXE 可能已崩溃，尝试重连...", e);
                                unsafe { let _ = CloseHandle(pipe); }
                                break;
                            }
                            last_run_at = Instant::now();
                            if broker_fallback_to_pin && broker_first_run_at.is_none() {
                                broker_first_run_at = Some(last_run_at);
                                info!(
                                    "broker 场景已开始人脸识别，{} ms 后未完成则回退 Windows PIN",
                                    broker_timeout.as_millis()
                                );
                            }
                            set_anim_state(&anim_slot, AnimState::Scanning);
                            if auto_run_on_connect {
                                auto_run_sent = true;
                            }
                            if input_requested {
                                let source_name = match input_source {
                                    INPUT_SOURCE_MOUSE => "鼠标",
                                    INPUT_SOURCE_KEYBOARD => "键盘",
                                    _ => "鼠标/键盘",
                                };
                                info!("检测到{}{}输入，已发送 run", scenario_label, source_name);
                            } else {
                                info!("登录/解锁主场景已自动发送 run");
                            }
                        }

                        if broker_fallback_to_pin {
                            if let Some(first_run_at) = broker_first_run_at {
                                if first_run_at.elapsed() >= broker_timeout
                                    && !is_unlocked_for_client.load(Ordering::SeqCst)
                                {
                                    trigger_broker_pin_fallback(
                                        &shared_creds_for_client,
                                        &stop_flag,
                                        &creds_pipe_raw_for_client,
                                        &send_events_for_client,
                                        &anim_slot,
                                        "face timeout",
                                    );
                                    unsafe { let _ = CloseHandle(pipe); }
                                    return;
                                }
                            }
                        }

                        if interruptible_sleep(Duration::from_millis(20), &stop_flag) {
                            unsafe { let _ = CloseHandle(pipe); }
                            return;
                        }

                        if last_prepare_at.elapsed() >= Duration::from_secs(1) {
                            if let Err(e) = pipe_write_raw(pipe, b"prepare") {
                                warn!("prepare 心跳失败: {:?}，Unlock EXE 可能已崩溃，尝试重连...", e);
                                unsafe { let _ = CloseHandle(pipe); }
                                break;
                            }
                            last_prepare_at = Instant::now();
                        }
                    }
                }
            })
        };

        // ── Creds 线程（接收凭据 + 驱动 Success 动画）────────────────────
        let creds_thread = {
            let is_unlocked    = is_unlocked.clone();
            let stop_flag      = stop_flag.clone();
            let creds_pipe_raw = creds_pipe_raw.clone();
            let send_events    = SendableEvents(events, advise_context);
            let anim_slot      = animation_slot.clone();
            thread::spawn(move || {
                info!("CPipeListener::start - 进入凭据Client线程");

                loop {
                    if stop_flag.load(Ordering::SeqCst) { break; }

                    // 尝试连接到 Unlock EXE 的 MansonWindowsUnlockRustUnlock 管道
                    // 使用 5 秒超时 + stop_flag 监听，避免关闭对话框时被 connect 卡住
                    let pipe = match pipe_connect_to_server_with_stop(PIPE_UNLOCK_NAME, 5_000, Some(&stop_flag)) {
                        Ok(p)  => p,
                        Err(_) => {
                            // Unlock EXE 可能尚未运行，继续等待
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    };

                    if stop_flag.load(Ordering::SeqCst) {
                        unsafe { let _ = CloseHandle(pipe); }
                        break;
                    }

                    info!("凭据线程：已连接到 MansonWindowsUnlockRustUnlock");
                    // 存储句柄以便 stop_and_join 可以关闭它来打断 ReadFile
                    creds_pipe_raw.store(pipe.0 as isize, Ordering::SeqCst);

                    // 阻塞等待 Unlock EXE 推送凭据
                    match pipe_read_raw(pipe) {
                        Ok(data) if !data.is_empty() => {
                            // 先清除句柄存储
                            creds_pipe_raw.store(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);

                            match parse_credentials(&data) {
                                Some((user, pwd, domain)) => {
                                    // 拒绝空用户名的凭据，防止"虚空登录" (#103)
                                    if user.is_empty() {
                                        warn!("凭据线程：收到空用户名凭据，已拒绝");
                                    } else {
                                        {
                                            let mut creds = shared_creds.lock().unwrap();
                                            if creds.broker_fallback_to_pin {
                                                warn!("凭据线程：broker 已回退 PIN，丢弃迟到的人脸凭据");
                                                continue;
                                            }
                                            info!("凭据线程：收到凭据，用户: {}", user);
                                            creds.username = user;
                                            creds.password = pwd;
                                            creds.domain   = domain;
                                            creds.is_ready = true;
                                            creds.is_unlocked = true;
                                        }
                                        is_unlocked.store(true, Ordering::SeqCst);

                                        // 动画：面容识别成功
                                        set_anim_state(&anim_slot, AnimState::Success);

                                        if let Err(e) = send_events.notify_changed() {
                                            error!("CredentialsChanged 失败: {:?}", e);
                                        } else {
                                            info!("已通知 Windows 凭据已就绪");
                                        }

                                        // 启动独立线程：让 Success 动画短暂显示后再销毁
                                        // 延迟 500ms 后通过 animation_slot 销毁 AnimationContext
                                        {
                                            let anim_slot = anim_slot.clone();
                                            thread::spawn(move || {
                                                thread::sleep(Duration::from_millis(500));
                                                if let Ok(mut guard) = anim_slot.lock() {
                                                    if guard.is_some() {
                                                        info!("CPipeListener - 销毁动画（凭据已提交）");
                                                        *guard = None;
                                                    }
                                                }
                                            });
                                        }
                                    }
                                }
                                None => warn!("凭据线程：收到无法解析的凭据数据"),
                            }
                        }
                        Ok(_) => {
                            // 空数据或 stop_and_join 关闭句柄导致的返回，忽略
                            creds_pipe_raw.store(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
                        }
                        Err(e) => {
                            creds_pipe_raw.store(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
                            if !stop_flag.load(Ordering::SeqCst) {
                                warn!("凭据线程：读取失败（Unlock EXE 断开？）: {:?}", e);
                            }
                        }
                    }

                    unsafe { let _ = CloseHandle(pipe); }

                    // 已解锁则不再重连
                    if is_unlocked.load(Ordering::SeqCst) { break; }
                }

                info!("凭据线程退出");
            })
        };

        Arc::new(Mutex::new(Self {
            is_unlocked,
            stop_flag,
            client_thread: Some(client_thread),
            creds_thread:  Some(creds_thread),
            creds_pipe_raw,
            use_input_hooks,
        }))
    }

    /// 停止两个后台线程并等待其退出
    pub fn stop_and_join(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if self.use_input_hooks {
            uninstall_input_hooks();
            self.use_input_hooks = false;
        }

        // 关闭凭据管道句柄，打断凭据线程中正在阻塞的 ReadFile
        let raw = self.creds_pipe_raw.swap(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
        if raw != INVALID_HANDLE_VALUE.0 as isize {
            let h = HANDLE(raw as *mut _);
            unsafe { let _ = CloseHandle(h); }
        }

        if let Some(t) = self.client_thread.take() { let _ = t.join(); }
        if let Some(t) = self.creds_thread.take()  { let _ = t.join(); }

        // 对话框关闭且不是面容识别成功时，通知 Unlock EXE 释放摄像头。
        if !self.is_unlocked.load(Ordering::SeqCst) {
            request_unlock_release("manual verification or dialog cancel");
        }
    }
}

impl Drop for CPipeListener {
    fn drop(&mut self) {
        if self.use_input_hooks {
            uninstall_input_hooks();
        }
    }
}
