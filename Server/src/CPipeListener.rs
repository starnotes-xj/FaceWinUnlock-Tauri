use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::UI::Shell::ICredentialProviderEvents;

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

pub struct CPipeListener {
    pub is_unlocked: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    client_thread: Option<JoinHandle<()>>,
    creds_thread: Option<JoinHandle<()>>,
    /// 保存凭据线程当前持有的管道句柄原始值（isize），用于 stop_and_join 时关闭句柄打断 ReadFile
    creds_pipe_raw: Arc<AtomicIsize>,
    /// 登录/解锁场景（非 CREDUI），用于 stop_and_join 中决定是否通知 Unlock EXE 释放资源 (#117)
    is_primary_scenario: bool,
}

impl CPipeListener {
    /// 启动管道监听：
    ///   - Client 线程：连接到 Unlock EXE 的 Server 管道，发送 "prepare" / "run"，
    ///     同时通过 animation_slot 驱动动画状态 (Scanning/Failure)
    ///   - Creds 线程：阻塞等待凭据推送，收到后设置动画为 Success
    pub fn start(
        events: ICredentialProviderEvents,
        advise_context: usize,
        shared_creds: Arc<Mutex<SharedCredentials>>,
        is_primary_scenario: bool,
        animation_slot: AnimationSlot,
    ) -> Arc<Mutex<Self>> {
        let is_unlocked    = Arc::new(AtomicBool::new(false));
        let stop_flag      = Arc::new(AtomicBool::new(false));
        // 存储当前凭据管道句柄原始值（INVALID_HANDLE_VALUE.0 as isize 表示无效）
        let creds_pipe_raw = Arc::new(AtomicIsize::new(INVALID_HANDLE_VALUE.0 as isize));

        // ── Client 线程（发送 prepare / run + 驱动动画状态）────────────
        let client_thread = {
            let stop_flag = stop_flag.clone();
            let anim_slot = animation_slot.clone();
            thread::spawn(move || {
                let connect_enabled = read_facewinunlock_registry("CONNECT_TO_PIPE")
                    .unwrap_or_else(|_| "1".to_string());
                if connect_enabled != "1" {
                    info!("CPipeListener - CONNECT_TO_PIPE 未启用，跳过管道连接");
                    return;
                }

                info!("CPipeListener::start - 进入管道Client线程");

                let retry_secs: f64 = read_facewinunlock_registry("RETRY_DELAY")
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(10.0);
                let retry_delay = Duration::from_secs_f64(retry_secs.max(1.0));

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
                            if is_first {
                                error!("首次连接管道服务器失败（Unlock EXE 未启动？）: {:?}", e);
                                return;
                            }
                            warn!("重连管道服务器失败: {:?}，5秒后重试", e);
                            if interruptible_sleep(Duration::from_secs(5), &stop_flag) { break; }
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

                    // 首次连接给予宽限期，避免用户锁屏后刚走开就被面容解锁（#116 动态锁兼容）
                    let grace = if is_first {
                        let secs: f64 = read_facewinunlock_registry("UNLOCK_GRACE_PERIOD")
                            .ok()
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(5.0);
                        let d = Duration::from_secs_f64(secs.max(0.0));
                        info!("首次连接，宽限期 {} 秒后开始面容识别", d.as_secs());
                        d
                    } else {
                        Duration::from_secs(1)
                    };
                    // 可中断 sleep，避免 CredUI 场景下用户提前关闭对话框时 stop_and_join 卡死
                    if interruptible_sleep(grace, &stop_flag) {
                        unsafe { let _ = CloseHandle(pipe); }
                        return;
                    }

                    // 内层重试循环 — 定期发送 "run"，含指数退避策略 (#115)
                    let mut retry_count: u32 = 0;

                    loop {
                        if stop_flag.load(Ordering::SeqCst) {
                            unsafe { let _ = CloseHandle(pipe); }
                            return;
                        }

                        if let Err(e) = pipe_write_raw(pipe, b"run") {
                            warn!("写入 run 失败: {:?}，Unlock EXE 可能已崩溃，尝试重连...", e);
                            unsafe { let _ = CloseHandle(pipe); }
                            break;
                        }
                        info!("向管道写入数据成功：run");

                        // 动画：进入扫描状态
                        set_anim_state(&anim_slot, AnimState::Scanning);

                        retry_count += 1;

                        // 动画：连续 3 次未匹配 → 短暂 Failure，随后回 Scanning
                        if retry_count == 3 {
                            set_anim_state(&anim_slot, AnimState::Failure);
                        }

                        // 退避策略: 逐步降低人脸识别频率，减少无人锁屏时的CPU消耗 (#115)
                        let delay = if retry_count <= 10 {
                            retry_delay
                        } else if retry_count <= 30 {
                            if retry_count == 11 {
                                info!("Client线程已重试10次未解锁，进入低频模式（{}秒间隔）", retry_delay.as_secs() * 5);
                            }
                            retry_delay * 5
                        } else {
                            if retry_count == 31 {
                                info!("Client线程已重试30次未解锁，进入极低频模式（{}秒间隔）", retry_delay.as_secs() * 20);
                            }
                            retry_delay * 20
                        };

                        let deadline = Instant::now() + delay;
                        loop {
                            if stop_flag.load(Ordering::SeqCst) {
                                unsafe { let _ = CloseHandle(pipe); }
                                return;
                            }
                            if Instant::now() >= deadline { break; }
                            thread::sleep(Duration::from_millis(200));
                        }
                        info!("管道重试: 再次发送 run（第{}次）", retry_count);
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
                            thread::sleep(Duration::from_millis(500));
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
            is_primary_scenario,
        }))
    }

    /// 停止两个后台线程并等待其退出
    pub fn stop_and_join(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);

        // 关闭凭据管道句柄，打断凭据线程中正在阻塞的 ReadFile
        let raw = self.creds_pipe_raw.swap(INVALID_HANDLE_VALUE.0 as isize, Ordering::SeqCst);
        if raw != INVALID_HANDLE_VALUE.0 as isize {
            let h = HANDLE(raw as *mut _);
            unsafe { let _ = CloseHandle(h); }
        }

        if let Some(t) = self.client_thread.take() { let _ = t.join(); }
        if let Some(t) = self.creds_thread.take()  { let _ = t.join(); }

        // 主场景（登录/解锁）且用户手动解锁（非面容识别）时，通知 Unlock EXE 释放摄像头 (#117)
        if self.is_primary_scenario && !self.is_unlocked.load(Ordering::SeqCst) {
            info!("CPipeListener - 手动解锁检测到，通知 Unlock EXE 释放资源");
            use crate::Pipe::{pipe_connect_to_server, pipe_write_raw, PIPE_UNLOCK_NAME};
            if let Ok(pipe) = pipe_connect_to_server(PIPE_UNLOCK_NAME, 3_000) {
                let _ = pipe_write_raw(pipe, b"exit");
                unsafe { let _ = CloseHandle(pipe); }
            }
        }
    }
}
