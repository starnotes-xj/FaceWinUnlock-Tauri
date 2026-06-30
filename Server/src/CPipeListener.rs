use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::{
    Shell::ICredentialProviderEvents,
    WindowsAndMessaging::{
        CallNextHookEx, DispatchMessageW, GetMessageW, HHOOK, MSG, PM_NOREMOVE, PeekMessageW,
        PostThreadMessageW, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx,
        WH_KEYBOARD_LL, WH_MOUSE_LL, WM_QUIT,
    },
};

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

/// 后台线程 DLL 引用计数守护：线程存活期间保持 DLL 加载，退出时 dll_release。
/// 使 stop_and_join 可安全「分离不 join」——DllCanUnloadNow 会等线程退出后才卸载，
/// 既不在宿主 UI 线程 join 阻塞（broker 不冻死），又不会因 DLL 提前卸载导致分离线程崩溃。
struct DllRefGuard;
impl Drop for DllRefGuard {
    fn drop(&mut self) {
        crate::dll_release();
    }
}

pub fn request_unlock_release(reason: &str) {
    info!("CPipeListener - 请求 Unlock EXE 释放摄像头: {}", reason);
    use crate::Pipe::{pipe_connect_to_server, pipe_write_raw, PIPE_UNLOCK_NAME};
    if let Ok(pipe) = pipe_connect_to_server(PIPE_UNLOCK_NAME, 1_000) {
        let _ = pipe_write_raw(pipe, b"release");
        unsafe { let _ = CloseHandle(pipe); }
    }
}

/// broker 场景专用释放命令。除释放摄像头外，还会设置 35s 冷却期，
/// 在此期间 Unlock EXE 拒绝新 "run" 命令，防止 credentialuibroker.exe
/// 新建进程后 DLL static 归零导致面容识别被重新激活。
/// 正常锁屏/解锁使用 request_unlock_release（不设冷却）。
pub fn request_broker_release(reason: &str) {
    info!("CPipeListener - 请求 broker release（含冷却期）: {}", reason);
    use crate::Pipe::{pipe_connect_to_server, pipe_write_raw, PIPE_UNLOCK_NAME};
    if let Ok(pipe) = pipe_connect_to_server(PIPE_UNLOCK_NAME, 1_000) {
        let _ = pipe_write_raw(pipe, b"broker_release");
        unsafe { let _ = CloseHandle(pipe); }
    }
}

fn trigger_broker_pin_fallback(
    shared_creds: &Arc<Mutex<SharedCredentials>>,
    stop_flag: &AtomicBool,
    creds_pipe_raw: &AtomicIsize,
    send_events: &SendableEvents,
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

    request_broker_release(reason);
    stop_flag.store(true, Ordering::SeqCst);

    let raw = creds_pipe_raw.swap(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
    if raw != INVALID_HANDLE_VALUE.0 as isize {
        unsafe { let _ = CloseHandle(HANDLE(raw as *mut _)); }
    }

    if let Err(e) = send_events.notify_changed() {
        error!("CPipeListener - 触发 PIN 回退重枚举失败: {:?}", e);
    }
}

fn close_pipe_if_owned(owner: &AtomicIsize, pipe: HANDLE) {
    if owner
        .compare_exchange(
            pipe.0 as isize,
            INVALID_HANDLE_VALUE.0 as isize,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
    {
        unsafe {
            let _ = CloseHandle(pipe);
        }
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
/// 专用输入钩子线程的线程 ID（0 = 未运行）。uninstall 用它 PostThreadMessage(WM_QUIT)。
static HOOK_THREAD_ID: AtomicU32 = AtomicU32::new(0);
const INPUT_SOURCE_MOUSE: u8 = 1;
const INPUT_SOURCE_KEYBOARD: u8 = 2;

/// 当前 broker CredUI 会话已回退 PIN。
///
/// 一旦置为 true，当前会话中的 CPipeListener 会停止识别。下一次
/// SetUsageScenario 会显式 reset，避免 credentialuibroker.exe 进程缓存把状态
/// 泄漏到下一次查看密码 / passkey 弹窗。
/// - 客户端线程停止发送 "run"，disarm 钩子后退出
/// - 新实例的钩子不会被 arm
///
/// 两条触发路径：
/// A) trigger_broker_pin_fallback — 面容识别超时
/// B) ReportResult — 凭据被 Windows 拒绝（如 passkey 场景）
static BROKER_PIN_FALLBACK_GLOBAL: AtomicBool = AtomicBool::new(false);

/// 公开函数：标记 broker PIN 回退 + 立即 disarm 全局钩子。
///
/// 由 trigger_broker_pin_fallback（路径 A：超时）和
/// CSampleCredential::ReportResult（路径 B：凭据被拒绝）调用。
///
pub fn mark_broker_pin_fallback() {
    // swap(true) 返回旧值。旧值为 true 说明已设置过，跳过。
    if BROKER_PIN_FALLBACK_GLOBAL.swap(true, Ordering::SeqCst) {
        return;
    }
    // 阻止 DLL 被卸载 → static 变量不会因重载而重置
    crate::dll_add_ref();
    INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
    INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
}

pub fn reset_broker_pin_fallback() {
    if BROKER_PIN_FALLBACK_GLOBAL.swap(false, Ordering::SeqCst) {
        info!("CPipeListener - 新 broker 会话已清除上一次 PIN fallback 状态");
    }
    INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
    INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
    INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
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
    if previous_refs > 0 {
        return; // 已有专用钩子线程在运行，复用之
    }
    INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
    INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
    INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);

    // 低级钩子（WH_MOUSE_LL/WH_KEYBOARD_LL）必须在「安装它的线程」上跑消息泵、并在
    // 「同一线程」卸载。此前在 broker 的 Advise/UnAdvise 线程装/卸——跨线程、或该线程
    // teardown 时不泵消息，会让 UnhookWindowsHookEx 永久阻塞 → CredentialUIBroker.exe
    // 卡死（实测根因）。改为专用线程：本线程装钩子 → GetMessage 泵消息（驱动 LL 回调）
    // → 收到 WM_QUIT 在本线程卸钩子退出。uninstall 仅 PostThreadMessage(WM_QUIT)，非阻塞。
    crate::dll_add_ref(); // 钩子线程生命周期内保持 DLL 加载（卸钩子前 DLL 不卸载）
    thread::spawn(|| {
        let _dll_ref = DllRefGuard;

        // 先建立本线程的消息队列，确保后续 uninstall 的 PostThreadMessage 不会丢失。
        let mut msg = MSG::default();
        unsafe { let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE); }
        HOOK_THREAD_ID.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);

        match unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook_fn), None, 0) } {
            Ok(hook) => {
                MOUSE_HOOK_RAW.store(hook.0 as isize, Ordering::SeqCst);
                IS_MOUSE_HOOK_INSTALLED.store(true, Ordering::SeqCst);
                info!("锁屏鼠标输入 Hook 已安装");
            }
            Err(e) => error!("设置鼠标 Hook 失败: {:?}", e),
        }
        match unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook_fn), None, 0) } {
            Ok(hook) => {
                KEYBOARD_HOOK_RAW.store(hook.0 as isize, Ordering::SeqCst);
                IS_KEYBOARD_HOOK_INSTALLED.store(true, Ordering::SeqCst);
                info!("锁屏键盘输入 Hook 已安装");
            }
            Err(e) => error!("设置键盘 Hook 失败: {:?}", e),
        }

        // 消息泵：LL 钩子回调经本线程消息队列派发。GetMessage 阻塞至 WM_QUIT(返回0)/错误(-1)。
        loop {
            let r = unsafe { GetMessageW(&mut msg, None, 0, 0) };
            if r.0 == 0 || r.0 == -1 {
                break;
            }
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // 在「同一线程」卸钩子——绝不跨线程，从根上消除 UnhookWindowsHookEx 阻塞。
        let raw_m = MOUSE_HOOK_RAW.swap(0, Ordering::SeqCst);
        if raw_m != 0 {
            unsafe { let _ = UnhookWindowsHookEx(HHOOK(raw_m as *mut _)); }
        }
        IS_MOUSE_HOOK_INSTALLED.store(false, Ordering::SeqCst);
        let raw_k = KEYBOARD_HOOK_RAW.swap(0, Ordering::SeqCst);
        if raw_k != 0 {
            unsafe { let _ = UnhookWindowsHookEx(HHOOK(raw_k as *mut _)); }
        }
        IS_KEYBOARD_HOOK_INSTALLED.store(false, Ordering::SeqCst);
        HOOK_THREAD_ID.store(0, Ordering::SeqCst);
        info!("输入 Hook 线程已退出（钩子已在本线程安全卸载）");
    });
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
        return; // 还有其它实例在用钩子线程，不关
    }

    INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
    INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
    INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);

    // 只给专用钩子线程发 WM_QUIT，让它在「自己线程」上卸钩子退出——绝不在调用方
    // （broker/winlogon 的 UI 线程）上 UnhookWindowsHookEx，从根上消除 teardown 卡死。
    // 非阻塞：本函数立即返回；钩子线程收到 WM_QUIT 后卸钩子、释放 DLL 引用、退出。
    let tid = HOOK_THREAD_ID.load(Ordering::SeqCst);
    if tid != 0 {
        unsafe { let _ = PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0)); }
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
    /// 是否主场景（登录/解锁）。仅主场景在 stop_and_join 中向 Unlock EXE 发 release 释放摄像头；
    /// CREDUI/broker 场景不发——既符合文档约定（锁屏可能仍需 Unlock EXE），也避免在
    /// CredentialUIBroker.exe 的 UI 线程 teardown 路径上执行阻塞管道连接而拖慢/冻结关闭。
    is_primary_scenario: bool,
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
        crate::dll_add_ref(); // client 线程生命周期内保持 DLL 加载（stop_and_join 分离不 join）
        let client_thread = {
            let stop_flag = stop_flag.clone();
            let is_unlocked_for_client = is_unlocked.clone();
            let shared_creds_for_client = shared_creds.clone();
            let creds_pipe_raw_for_client = creds_pipe_raw.clone();
            let send_events_for_client = SendableEvents(events.clone(), advise_context);
            let broker_timeout = broker_fallback_timeout();
            thread::spawn(move || {
                let _dll_ref = DllRefGuard; // 退出（含下方 return）时 dll_release，分离安全
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
                        let session_fallback = shared_creds_for_client
                            .lock()
                            .map(|creds| creds.broker_fallback_to_pin)
                            .unwrap_or(true);
                        if stop_flag.load(Ordering::SeqCst)
                            || BROKER_PIN_FALLBACK_GLOBAL.load(Ordering::SeqCst)
                            || session_fallback
                        {
                            if use_input_hooks {
                                INPUT_HOOKS_ARMED.store(false, Ordering::SeqCst);
                                INPUT_RUN_REQUESTED.store(false, Ordering::SeqCst);
                                INPUT_RUN_SOURCE.store(0, Ordering::SeqCst);
                            }
                            unsafe { let _ = CloseHandle(pipe); }
                            info!("面容识别已停止（stop={}, broker_fallback={}, session_fallback={}）",
                                stop_flag.load(Ordering::SeqCst),
                                BROKER_PIN_FALLBACK_GLOBAL.load(Ordering::SeqCst),
                                session_fallback);
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

        // ── Creds 线程（接收凭据）────────────────────
        crate::dll_add_ref(); // creds 线程生命周期内保持 DLL 加载（stop_and_join 分离不 join）
        let creds_thread = {
            let is_unlocked    = is_unlocked.clone();
            let stop_flag      = stop_flag.clone();
            let creds_pipe_raw = creds_pipe_raw.clone();
            let send_events    = SendableEvents(events, advise_context);
            thread::spawn(move || {
                let _dll_ref = DllRefGuard; // 退出时 dll_release，分离安全

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

                    // store 后立即复查 stop：避免 stop_and_join 的句柄关闭恰好发生在本 store
                    // 之前、漏掉本句柄，导致下面 ReadFile 永久阻塞、冻死宿主 UI 线程
                    //（passkey 取消时 CredentialUIBroker.exe 卡死的竞态根因）。
                    if stop_flag.load(Ordering::SeqCst) {
                        close_pipe_if_owned(&creds_pipe_raw, pipe);
                        break;
                    }

                    // 阻塞等待 Unlock EXE 推送凭据
                    let read_result = pipe_read_raw(pipe);
                    // 只有仍持有原子句柄所有权的一方负责 CloseHandle。若 stop/fallback
                    // 已 swap 并关闭句柄，这里 CAS 失败，避免关闭已复用的 Windows HANDLE。
                    close_pipe_if_owned(&creds_pipe_raw, pipe);

                    match read_result {
                        Ok(data) if !data.is_empty() => {
                            // ── 检测 inject_pin 命令（KSP 增强版：DLL 端 SendInput）──
                            let data_str = String::from_utf8_lossy(&data);
                            if data_str.starts_with("inject_pin:") {
                                let pin = data_str["inject_pin:".len()..].trim_end_matches('\0').to_string();
                                if !pin.is_empty() {
                                    info!("CPipeListener - 收到 PIN 注入命令，执行 SendInput...");
                                    inject_pin_sendinput(&pin);
                                    info!("CPipeListener - PIN 已注入到前台窗口");
                                }
                                continue;
                            }

                            match parse_credentials(&data) {
                                Some((user, pwd, domain)) => {
                                    // 拒绝空用户名的凭据，防止"虚空登录" (#103)
                                    if user.is_empty() {
                                        warn!("凭据线程：收到空用户名凭据，已拒绝");
                                    } else {
                                        {
                                            let mut creds = shared_creds.lock().unwrap();
                                            if creds.broker_fallback_to_pin {
                                                // ── Approach B：面容已过，覆盖 broker PIN 回退 ──
                                                // 即使 broker 已超时进入 PIN 模式，面容凭据到达后
                                                // 仍然提交——人脸识别比 PIN 输入更可靠。
                                                info!("凭据线程：面容凭据到达，覆盖 broker PIN 回退");
                                                creds.broker_fallback_to_pin = false;
                                                // 同时通知全局标记（其他管道实例也会检查）
                                                BROKER_PIN_FALLBACK_GLOBAL.store(false, Ordering::SeqCst);
                                                // 也要释放 pin_buffer，让 GetSerialization 走密码路径
                                            }
                                            info!("凭据线程：收到凭据，用户: {}", user);
                                            creds.username = user;
                                            creds.password = pwd;
                                            creds.domain   = domain;
                                            creds.is_ready = true;
                                            creds.is_unlocked = true;
                                        }
                                        is_unlocked.store(true, Ordering::SeqCst);

                                        if let Err(e) = send_events.notify_changed() {
                                            error!("CredentialsChanged 失败: {:?}", e);
                                        } else {
                                            info!("已通知 Windows 凭据已就绪");
                                        }
                                    }
                                }
                                None => warn!("凭据线程：收到无法解析的凭据数据"),
                            }
                        }
                        Ok(_) => {
                            // 空数据或 stop_and_join 关闭句柄导致的返回，忽略
                        }
                        Err(e) => {
                            if !stop_flag.load(Ordering::SeqCst) {
                                warn!("凭据线程：读取失败（Unlock EXE 断开？）: {:?}", e);
                            }
                        }
                    }

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
            is_primary_scenario,
        }))
    }

    /// 停止两个后台线程：发 stop + 关句柄解阻塞，随后**分离**（绝不在宿主 UI 线程 join）。
    /// 两线程已用 dll_add_ref/dll_release 守护 DLL 生命周期，DllCanUnloadNow 会等它们
    /// 退出后才卸载——故可安全分离，UI 线程立即返回，CredentialUIBroker.exe 永不因
    /// teardown 的线程 join 而冻结（passkey / 查看密码取消卡死的根治）。
    pub fn stop_and_join(&mut self) {
        info!("CPipeListener::stop_and_join - 开始（信号 stop + 关句柄 + 分离）");
        self.stop_flag.store(true, Ordering::SeqCst);
        if self.use_input_hooks {
            uninstall_input_hooks();
            self.use_input_hooks = false;
        }

        // 单次 swap 足够：若 creds 线程尚未发布句柄，它会在 store 后立刻复查 stop
        // 并自行关闭；若已发布，则由这里取得唯一关闭所有权并打断 ReadFile。
        let raw = self
            .creds_pipe_raw
            .swap(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
        if raw != INVALID_HANDLE_VALUE.0 as isize {
            unsafe {
                let _ = CloseHandle(HANDLE(raw as *mut _));
            }
        }

        // 关键：绝不在宿主 UI 线程 join 后台线程——drop JoinHandle 即分离。
        // DLL 引用计数保证 DLL 在两线程退出前不卸载，分离安全；UI 线程立即返回。
        let _ = self.client_thread.take();
        let _ = self.creds_thread.take();
        info!("CPipeListener::stop_and_join - 已分离后台线程（DLL 引用计数守护其生命周期）");

        // 仅主场景（登录/解锁）在此向 Unlock EXE 发 release 释放摄像头。
        // CREDUI/broker 不发：① 文档约定 CREDUI 不发 exit/release（锁屏可能仍需 Unlock EXE）；
        // ② request_unlock_release 是阻塞管道连接，绝不能在 broker 的 UI 线程 teardown 上执行。
        if self.is_primary_scenario && !self.is_unlocked.load(Ordering::SeqCst) {
            request_unlock_release("manual verification or dialog cancel");
        }
        info!("CPipeListener::stop_and_join - 完成");
    }
}

/// KSP 增强版：DLL 端 SendInput PIN 注入。
///
/// 在全系统中精确定位 PIN 输入框，设焦点后用 SendInput 注入。
/// 优先通过 EnumWindows 找 Chrome CredUI 对话框中的 Edit/PasswordBox，
/// 设焦点后 SendInput 自然进入该控件（不依赖前台窗口）。
/// 定位失败回退盲打。
fn inject_pin_sendinput(pin: &str) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VIRTUAL_KEY, VK_RETURN, SetFocus,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, GetClassNameW,
        GetWindow, GW_CHILD,
    };
    use windows::Win32::Foundation::{HWND, BOOL, LPARAM};

    let our_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };

    // ── 枚举所有顶层窗口，找同进程 CredUI/PIN 对话框 + 其 Edit 子控件 ──
    struct FindCtx { pid: u32, found_hwnd: HWND }
    let mut ctx = FindCtx { pid: our_pid, found_hwnd: HWND(std::ptr::null_mut()) };

    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut FindCtx);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid != ctx.pid { return BOOL(1); }
        // 只看 CredUI/PIN 相关窗口类
        let mut cls = [0u16; 64];
        GetClassNameW(hwnd, &mut cls);
        let cls_str = String::from_utf16_lossy(&cls);
        // Chrome PIN 框可能是 Credential Dialog Xaml Host 或 Windows.UI.Core.CoreWindow
        let is_credui = cls_str.contains("Credential") || cls_str.contains("CoreWindow")
            || cls_str.contains("WindowsSecurity") || cls_str.contains("AADCredential");
        if !is_credui { return BOOL(1); }
        // 找子 Edit
        let child = GetWindow(hwnd, GW_CHILD).unwrap_or(HWND(std::ptr::null_mut()));
        ctx.found_hwnd = find_edit_recursive(child);
        if ctx.found_hwnd.0.is_null() { BOOL(1) } else { BOOL(0) }
    }
    unsafe fn find_edit_recursive(hwnd: HWND) -> HWND {
        if hwnd.0.is_null() { return hwnd; }
        let mut cls = [0u16; 64];
        GetClassNameW(hwnd, &mut cls);
        let s = String::from_utf16_lossy(&cls);
        if s.contains("Edit") || s.contains("PasswordBox") || s.contains("TextBox") { return hwnd; }
        let mut child = GetWindow(hwnd, GW_CHILD).unwrap_or(HWND(std::ptr::null_mut()));
        while !child.0.is_null() {
            let r = find_edit_recursive(child);
            if !r.0.is_null() { return r; }
            child = GetWindow(child, windows::Win32::UI::WindowsAndMessaging::GW_HWNDNEXT).unwrap_or(HWND(std::ptr::null_mut()));
        }
        HWND(std::ptr::null_mut())
    }

    unsafe { let _ = EnumWindows(Some(callback), LPARAM(&mut ctx as *mut _ as isize)); }

    if !ctx.found_hwnd.0.is_null() {
        info!("inject_pin: 找到 PIN Edit HWND=0x{:X}", ctx.found_hwnd.0 as usize);
        unsafe { let _ = SetFocus(Some(ctx.found_hwnd)); }
        std::thread::sleep(std::time::Duration::from_millis(80));
    } else {
        warn!("inject_pin: 未找到 PIN Edit，回退盲打");
    }

    // ── SendInput 注入 PIN ──
    for ch in pin.encode_utf16() {
        unsafe {
            let down = INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: ch, dwFlags: KEYEVENTF_UNICODE, time: 0, dwExtraInfo: 0 } } };
            let up   = INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: ch, dwFlags: KEYBD_EVENT_FLAGS(KEYEVENTF_UNICODE.0 | KEYEVENTF_KEYUP.0), time: 0, dwExtraInfo: 0 } } };
            SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32);
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    unsafe {
        let down = INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VK_RETURN, wScan: 0, dwFlags: KEYBD_EVENT_FLAGS(0), time: 0, dwExtraInfo: 0 } } };
        let up   = INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VK_RETURN, wScan: 0, dwFlags: KEYEVENTF_KEYUP, time: 0, dwExtraInfo: 0 } } };
        SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32);
    }
    info!("inject_pin: PIN + Enter 已发送");
}

impl Drop for CPipeListener {
    fn drop(&mut self) {
        if self.use_input_hooks {
            uninstall_input_hooks();
        }
    }
}
