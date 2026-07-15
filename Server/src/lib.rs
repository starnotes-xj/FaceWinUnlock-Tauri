// 引入日志宏和日志库
// 模块/常量沿用原 C++ 项目与 COM 约定的大驼峰命名（CSampleProvider 等），crate 名
// FaceWinUnlock_Tauri 同时是 DLL 导出名——均为有意命名，统一抑制风格 lint（非代码问题）。
#![allow(non_snake_case, non_upper_case_globals)]
#[macro_use] extern crate log;
extern crate simplelog;
use simplelog::*;
use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, REG_VALUE_TYPE};
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

// 引入必要的系统类型和Win32 API绑定
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering};

// Windows基础类型和COM接口
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_INVALIDARG, HINSTANCE, S_FALSE, S_OK};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::UI::Shell::ICredentialProvider;
use windows_core::{implement, Ref, GUID, PCWSTR};
use windows::Win32::Foundation::BOOL;
use windows::core::{Interface, HRESULT};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

// 导入凭据提供程序和凭据的实现模块
pub mod CSampleProvider;
pub mod CSampleCredential;
pub mod CPipeListener;
pub mod Pipe;

use CSampleProvider::SampleProvider;

// 全局引用计数器，用于管理DLL的生命周期
// 当引用计数为0时，系统可以安全卸载DLL
static G_REF_COUNT: AtomicI32 = AtomicI32::new(0);
/// 增加DLL的引用计数
pub fn dll_add_ref() {
    let new_count = G_REF_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    info!("DLL引用计数增加，当前计数: {}", new_count);
}

/// 减少DLL的引用计数
pub fn dll_release() {
    let new_count = G_REF_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
    info!("DLL引用计数减少，当前计数: {}", new_count);
}

/// 读取注册表数据
pub fn read_facewinunlock_registry(key_name: &str) -> windows::core::Result<String> {
    let reg_path = "SOFTWARE\\facewinunlock-tauri";
    // 打开HKLM下的注册表项
    let mut hkey: HKEY = HKEY::default();

    let os_str = OsStr::new(reg_path);
    let reg_path_ptr: Vec<u16> = os_str.encode_wide().chain(std::iter::once(0)).collect();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(reg_path_ptr.as_ptr()), // 子路径
            None, // 保留参数
            KEY_READ, // 只读
            &mut hkey, // 输出打开的注册表句柄
        )
    };

    if status.is_err() {
        return Err(windows_core::Error::new(HRESULT(0), format!("打开注册表失败: {}", status.0)));
    }

    // 查询值的长度
    let mut value_type = REG_VALUE_TYPE::default();
    let mut value_len = 0u32;

    let os_str = OsStr::new(key_name);
    let key_name_ptr: Vec<u16> = os_str.encode_wide().chain(std::iter::once(0)).collect();
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(key_name_ptr.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut value_len),
        )
    };

    if status.is_err() {
        // 关闭注册表
        unsafe { let _ = RegCloseKey(hkey); };
        return Err(windows_core::Error::new(HRESULT(0), format!("查询注册表长度失败: {}", status.0)));
    }

    if value_type != REG_SZ {
        // 关闭注册表
        unsafe { let _ = RegCloseKey(hkey); };
        return Err(windows_core::Error::new(HRESULT(0), "值类型不是 REG_SZ"));
    }

    // 读取值内容
    let mut buffer = vec![0u16; (value_len / 2) as usize];
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(key_name_ptr.as_ptr()),
            None,
            None,
            Some(buffer.as_mut_ptr() as *mut u8), // 转换为 *mut u8
            Some(&mut value_len),
        )
    };

    if status.is_err() {
        // 关闭注册表
        unsafe { let _ = RegCloseKey(hkey); };
        return Err(windows_core::Error::new(HRESULT(0), format!("读取注册表值失败: {}", status.0)));
    }

    unsafe { let _ = RegCloseKey(hkey); };

    // 将 UTF-16 数组转换回 Rust String
    let value = String::from_utf16(&buffer)?.trim_end_matches('\0').to_string();
    Ok(value)
}

/// 返回当前宿主进程可执行文件名（小写，不含路径），失败时返回空串。
///
/// Credential Provider DLL 会被不同宿主加载；CREDUI 场景尤其需要区分：
/// - consent.exe: UAC 系统提权，保留人脸解锁
/// - credentialuibroker.exe: 应用层/浏览器 PIN/WebAuthn passkey，先人脸，失败后回退 PIN
///
/// `std::env::current_exe()` 在 Windows 上返回宿主进程主模块路径（不是本 DLL），
/// 正好可作为 CREDUI 调用来源判据。
pub fn current_process_exe_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default()
}

const WEBAUTHN_READY_EVENT: &str = "Global\\FaceWinUnlockTauriWebAuthnReady";
const WEBAUTHN_ACTIVE_EVENT: &str = "Global\\FaceWinUnlockTauriWebAuthnActive";

/// Conservative classification of broker-hosted CredUI. `dwFlags` is retained
/// for diagnostics, but password fill and WebAuthn have been observed with the
/// same value and therefore cannot be classified from flags alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerScene {
    Password,
    BrowserPasswordFill,
    Passkey,
    PinOrSettings,
    PrivateBrowser,
    MonitorUnavailable,
    Unknown,
}

impl BrokerScene {
    pub fn uses_face(self) -> bool {
        matches!(self, Self::Password | Self::BrowserPasswordFill)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerContext {
    pub titles: String,
    pub owner_processes: Vec<String>,
    pub dwflags: u32,
    pub webauthn_ready: bool,
    pub webauthn_active: bool,
    pub private_browser: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebAuthnMonitorState {
    pub ready: bool,
    pub active: bool,
}

fn registry_bool(key_name: &str, default: bool) -> bool {
    read_facewinunlock_registry(key_name)
        .map(|value| value.trim() == "1")
        .unwrap_or(default)
}

fn broker_context(dwflags: u32) -> BrokerContext {
    use std::path::Path;
    use windows::Win32::Foundation::{CloseHandle, HWND};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetAncestor, GetForegroundWindow, GetWindow, GetWindowTextW,
        GetWindowThreadProcessId, GET_ANCESTOR_FLAGS, GW_OWNER,
    };

    fn title_of(hwnd: HWND) -> String {
        if hwnd.0.is_null() {
            return String::new();
        }
        let mut buffer = [0u16; 512];
        let length = unsafe { GetWindowTextW(hwnd, &mut buffer) };
        if length <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buffer[..length as usize])
    }

    fn process_name_of(hwnd: HWND) -> String {
        if hwnd.0.is_null() {
            return String::new();
        }
        let mut process_id = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)); }
        if process_id == 0 {
            return String::new();
        }
        let process = match unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
        } {
            Ok(process) => process,
            Err(_) => return String::new(),
        };
        let mut path = [0u16; 1024];
        let mut size = path.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                windows_core::PWSTR(path.as_mut_ptr()),
                &mut size,
            )
        };
        unsafe { let _ = CloseHandle(process); }
        if result.is_err() {
            return String::new();
        }
        let full_path = String::from_utf16_lossy(&path[..size as usize]);
        Path::new(&full_path)
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
    }

    let foreground = unsafe { GetForegroundWindow() };
    let owner = unsafe { GetWindow(foreground, GW_OWNER) }.unwrap_or_default();
    let root_owner = unsafe { GetAncestor(foreground, GET_ANCESTOR_FLAGS(3)) };
    let windows = [foreground, owner, root_owner];
    let titles = windows
        .iter()
        .map(|hwnd| title_of(*hwnd))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut owner_processes = Vec::new();
    for hwnd in windows {
        let process = process_name_of(hwnd);
        if !process.is_empty() && !owner_processes.contains(&process) {
            owner_processes.push(process);
        }
    }

    const PRIVATE_KEYWORDS: &[&str] = &["incognito", "inprivate", "无痕", "隐身", "隐私浏览"];
    let monitor = webauthn_monitor_state();
    BrokerContext {
        private_browser: PRIVATE_KEYWORDS
            .iter()
            .any(|keyword| titles.contains(keyword)),
        titles,
        owner_processes,
        dwflags,
        webauthn_ready: monitor.ready,
        webauthn_active: monitor.active,
    }
}

fn named_event_signaled(name: &str) -> bool {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenEventW, WaitForSingleObject, SYNCHRONIZATION_ACCESS_RIGHTS,
    };

    let name = OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let event = match unsafe {
        OpenEventW(
            SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000),
            false,
            PCWSTR::from_raw(name.as_ptr()),
        )
    } {
        Ok(event) => event,
        Err(_) => return false,
    };
    let signaled = unsafe { WaitForSingleObject(event, 0) } == WAIT_OBJECT_0;
    unsafe { let _ = CloseHandle(event); }
    signaled
}

pub fn webauthn_monitor_state() -> WebAuthnMonitorState {
    let ready = named_event_signaled(WEBAUTHN_READY_EVENT);
    WebAuthnMonitorState {
        ready,
        active: ready && named_event_signaled(WEBAUTHN_ACTIVE_EVENT),
    }
}

pub fn is_webauthn_guard_active() -> bool {
    let state = webauthn_monitor_state();
    state.ready && state.active
}

pub fn classify_broker_scene(dwflags: u32) -> BrokerScene {
    let context = broker_context(dwflags);
    let scene = classify_broker_context(
        &context,
        registry_bool("CREDUI_BROWSER_PASSWORD_FILL", true),
    );
    info!(
        "classify_broker_scene - scene={:?}, flags=0x{:X}, titles={:?}, owners={:?}, webauthn_ready={}, webauthn_active={}, private={}",
        scene,
        context.dwflags,
        context.titles,
        context.owner_processes,
        context.webauthn_ready,
        context.webauthn_active,
        context.private_browser,
    );
    scene
}

pub fn classify_broker_context(
    context: &BrokerContext,
    browser_password_fill_enabled: bool,
) -> BrokerScene {
    let titles = context.titles.to_lowercase();
    let has_process = |names: &[&str]| {
        context.owner_processes.iter().any(|process| {
            names
                .iter()
                .any(|name| process.eq_ignore_ascii_case(name))
        })
    };
    let title_has = |kws: &[&str]| kws.iter().any(|k| titles.contains(k));

    // 触发弹窗的应用进程（结构信号，非本地化文本）。
    const BROWSER_PROCESSES: &[&str] = &[
        "chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe",
        "opera.exe", "opera_gx.exe", "chromium.exe", "360se.exe", "360chrome.exe",
    ];
    const SETTINGS_PROCESSES: &[&str] = &["systemsettings.exe", "bioenrollmenthost.exe"];

    // 标题关键词仅在「WebAuthn 监视器不可用」的兜底路径使用；监视器 Ready 的正常路径
    // 完全不依赖它们，改由 webauthn_active（进行中的 CTAP 事务）+ owner 进程判定。
    const PASSKEY_KEYWORDS: &[&str] = &[
        "通行密钥", "passkey", "安全密钥", "security key", "保存通行密钥",
        "创建通行密钥", "save passkey", "save a passkey", "create passkey",
        "create a passkey", "webauthn", "fido2",
    ];
    const PIN_KEYWORDS: &[&str] = &[
        "windows hello pin", "pin (windows hello)", "设置 pin", "设置pin",
        "更改 pin", "更改pin", "set up a pin", "setup pin", "change your pin",
        "security key pin", "安全密钥 pin",
    ];
    const PASSWORD_KEYWORDS: &[&str] = &[
        "密码管理工具", "password manager", "保存的密码", "已保存密码",
        "saved password", "saved passwords", "查看密码", "显示密码",
        "view password", "show password", "reveal password",
    ];
    const PASSWORD_FILL_KEYWORDS: &[&str] = &[
        "填充密码", "填充您的密码", "填充你的密码", "fill password",
        "fill your password", "filling passwords", "autofill password",
    ];

    // ① 设置 / PIN / 指纹录入：靠触发进程识别（结构信号）。任何情况都不在此走人脸。
    if has_process(SETTINGS_PROCESSES) {
        return BrokerScene::PinOrSettings;
    }

    // ② 核心非名单信号：WebAuthn 监视器报告有「进行中的 CTAP 事务」
    //    （MakeCredential/GetAssertion/SendCommand started 未 completed）——这正是
    //    真 passkey/security-key 的 UV 操作。broker 弹窗发生在事务进行中 → 跳过人脸，
    //    交还 Windows 原生。填充密码不会产生进行中的 CTAP 事务（枚举类
    //    GetAllPlatformCredentials 不计入 active），故此处只拦真 passkey。
    if context.webauthn_ready && context.webauthn_active {
        return BrokerScene::Passkey;
    }

    // ③ 标题明确是 passkey/安全密钥 UI：即使此刻 active 尚未置起（事件投递有毫秒级
    //    延迟），也保守跳过；始终压过下面的 password 关键词。CPipeListener 还会在
    //    prepare/run 前多点复查 active 兜底订阅时序竞态。
    if title_has(PASSKEY_KEYWORDS) {
        return BrokerScene::Passkey;
    }

    // ④ 无痕 / 隐私窗口：保守 fail-closed，绝不自动填。
    if context.private_browser {
        return BrokerScene::PrivateBrowser;
    }

    // ⑤ 非浏览器进程但标题是 PIN 设置：兜底跳过。
    if title_has(PIN_KEYWORDS) {
        return BrokerScene::PinOrSettings;
    }

    // ⑥ 触发进程是浏览器：到此 active=false（passkey 已在 ②③ 排除）。
    if has_process(BROWSER_PROCESSES) {
        // 查看已保存密码 / 密码管理器重新验证：明确的凭据查看，始终走人脸。
        if title_has(PASSWORD_KEYWORDS) {
            return BrokerScene::Password;
        }
        // 其余浏览器 CredUI = 密码填充。受 CREDUI_BROWSER_PASSWORD_FILL 开关控制。
        if !browser_password_fill_enabled {
            return BrokerScene::Unknown;
        }
        // ★ 监视器 Ready 且无 active（CTAP + 枚举均无）：枚举事件 2250 已为
        //   passkey 弹窗提供 5s 早期 active 窗口。到此 active=false → 必为密码填充。
        if context.webauthn_ready {
            return BrokerScene::BrowserPasswordFill;
        }
        // 监视器不可用：纯关键词兜底。
        if title_has(PASSWORD_FILL_KEYWORDS) {
            return BrokerScene::BrowserPasswordFill;
        }
        return BrokerScene::MonitorUnavailable;
    }

    // ⑦ 非浏览器 App 的查看密码兜底。
    if title_has(PASSWORD_KEYWORDS) {
        return BrokerScene::Password;
    }
    BrokerScene::Unknown
}

// 定义凭据提供程序的GUID，用于系统识别
// 8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c
pub const CLSID_SampleProvider: GUID = GUID::from_u128(0x8a7b9c6d_4e5f_89a0_8b7c_6d5e4f3e2d1c);

// 共享的凭据信息
pub struct SharedCredentials {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub is_ready: bool,
    pub is_unlocked: bool, // 面容已识别，触发自动登录；由 GetSerialization 消费后重置
    pub broker_fallback_to_pin: bool, // credentialuibroker 场景已放弃本 Provider，交还 Windows Hello PIN
}

impl SharedCredentials {
    pub fn reset_for_new_usage(&mut self) {
        self.username.clear();
        self.password.clear();
        self.domain.clear();
        self.domain.push('.');
        self.is_ready = false;
        self.is_unlocked = false;
        self.broker_fallback_to_pin = false;
    }
}

/// 类工厂实现，用于创建凭据提供程序实例
/// COM规范要求通过类工厂来实例化组件
#[implement(IClassFactory)]
struct SampleClassFactory;

impl IClassFactory_Impl for SampleClassFactory_Impl {
    /// 创建组件实例
    /// punkouter: 聚合对象的外部IUnknown接口，通常为null
    /// riid: 要获取的接口ID
    /// ppv_object: 输出参数，接收创建的接口实例
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, windows::core::IUnknown>,
        riid: *const GUID,
        ppv_object: *mut *mut std::ffi::c_void,
    ) -> windows::core::Result<()> {
        info!("SampleClassFactory::CreateInstance 被调用 - 开始创建凭据提供程序实例");

        // 不支持聚合，若提供了外部对象则返回错误
        if punkouter.is_some() {
            error!("不支持聚合，返回CLASS_E_NOAGGREGATION");
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        unsafe {
            // 检查输出指针是否有效
            if ppv_object.is_null() {
                error!("输出指针为空，返回E_INVALIDARG");
                return Err(E_INVALIDARG.into());
            }

            // 实例化凭据提供程序并转换为ICredentialProvider接口
            let provider: ICredentialProvider = SampleProvider::new().into();
            // 查询请求的接口并返回
            let result = provider.query(riid, ppv_object);
            if result.is_err() {
                error!("接口查询失败: {:?}", result.message());
                Err(E_INVALIDARG.into())
            } else {
                info!("凭据提供程序实例创建成功");
                Ok(())
            }
        }
    }

    /// 锁定或解锁DLL，用于控制DLL卸载
    /// flock: true表示锁定（增加引用计数），false表示解锁（减少引用计数）
    fn LockServer(&self, flock: BOOL) -> windows::core::Result<()> {
        if flock.as_bool() {
            info!("LockServer: 锁定DLL");
            dll_add_ref();
        } else {
            info!("LockServer: 解锁DLL");
            dll_release();
        }
        Ok(())
    }
}

/// DLL导出函数，用于获取类工厂
/// rclsid: 要创建的组件的CLSID
/// riid: 要获取的接口ID（通常是IClassFactory）
/// ppv: 输出参数，接收类工厂接口
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    info!("DllGetClassObject 被调用 - 尝试获取类工厂");

    // 检查输入参数有效性
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        error!("输入参数为空，返回E_INVALIDARG");
        return E_INVALIDARG;
    }

    // 检查请求的CLSID是否为我们的凭据提供程序
    if unsafe { *rclsid } == CLSID_SampleProvider {
        info!("请求的CLSID匹配，创建类工厂实例");
        let factory: IClassFactory = SampleClassFactory.into();
        // 查询请求的接口
        unsafe {
            let result = factory.query(riid, ppv);
            if result.is_err() {
                error!("类工厂接口查询失败: {:?}", result.message());
                E_INVALIDARG
            } else {
                info!("类工厂接口查询成功");
                S_OK
            }
        }
    } else {
        error!("不支持的CLSID，返回CLASS_E_CLASSNOTAVAILABLE");
        CLASS_E_CLASSNOTAVAILABLE
    }
}

/// DLL导出函数，用于判断DLL是否可以卸载
/// 当引用计数为0时可以卸载
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllCanUnloadNow() -> HRESULT {
    let count = G_REF_COUNT.load(Ordering::SeqCst);
    info!("DllCanUnloadNow 被调用 - 当前引用计数: {}", count);

    if count == 0 {
        info!("引用计数为0，可以卸载DLL");
        S_OK
    } else {
        info!("引用计数不为0，不能卸载DLL");
        S_FALSE
    }
}

/// DLL入口点函数，处理DLL加载和卸载事件
/// hinst_dll: DLL实例句柄
/// dw_reason: 调用原因（加载、卸载等）
/// reserved: 保留参数
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    dw_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match dw_reason {
        DLL_PROCESS_ATTACH => {
            // 读取注册表设置
            let result = read_facewinunlock_registry("DLL_LOG_PATH");
            let mut log_path = String::from("C:");

            if let Ok(log_path_reg) = result.clone() {
                log_path = if log_path_reg.starts_with("\\\\?\\") {
                    log_path_reg["\\\\?\\".len()..].to_string()
                } else {
                    log_path_reg
                };
            }

            // 初始化日志系统
            // 使用 append + FILE_SHARE_READ|WRITE(0x03)，允许多进程（如 credentialuibroker.exe）同时写入同一日志文件
            let log_file_path = format!("{}\\facewinunlock.log", log_path);
            if let Ok(file) = OpenOptions::new()
                .create(true)
                .append(true)
                .share_mode(0x00000003) // FILE_SHARE_READ | FILE_SHARE_WRITE
                .open(&log_file_path)
            {
                if let Ok(config) = ConfigBuilder::new().set_time_offset_to_local(){
                    match CombinedLogger::init(
                        vec![
                            WriteLogger::new(
                                LevelFilter::Info,
                                config.build(),
                                file
                            ),
                        ]
                    ) {
                        Ok(_) => info!("日志系统初始化成功 (PID: {})", std::process::id()),
                        _ => {},
                    }
                }
            }

            info!("DllMain: 基础框架初始化完成");

            if let Err(e) = result {
                warn!("从注册表加载配置失败：{}", e);
            }
        }
        // DLL_THREAD_ATTACH/DETACH 等高频事件不做任何处理：DllMain 持有 loader lock，
        // 在锁内写文件日志有死锁风险，也会产生大量噪音。这里保持空处理、立即返回。
        _ => {}
    }
    BOOL::from(true)
}

#[cfg(test)]
mod shared_credentials_tests {
    use super::{classify_broker_context, BrokerContext, BrokerScene, SharedCredentials};

    fn context(
        titles: &str,
        owner_processes: &[&str],
        webauthn_ready: bool,
        webauthn_active: bool,
        private_browser: bool,
    ) -> BrokerContext {
        BrokerContext {
            titles: titles.to_string(),
            owner_processes: owner_processes
                .iter()
                .map(|value| value.to_string())
                .collect(),
            dwflags: 0x250,
            webauthn_ready,
            webauthn_active,
            private_browser,
        }
    }

    #[test]
    fn reset_for_new_usage_clears_previous_broker_session() {
        let mut credentials = SharedCredentials {
            username: "stale-user".to_string(),
            password: "stale-password".to_string(),
            domain: "STALE".to_string(),
            is_ready: true,
            is_unlocked: true,
            broker_fallback_to_pin: true,
        };

        credentials.reset_for_new_usage();

        assert!(credentials.username.is_empty());
        assert!(credentials.password.is_empty());
        assert_eq!(credentials.domain, ".");
        assert!(!credentials.is_ready);
        assert!(!credentials.is_unlocked);
        assert!(!credentials.broker_fallback_to_pin);
    }

    #[test]
    fn broker_scene_detects_password_manager_titles() {
        let chinese = context(
            "windows 安全中心 google 密码管理工具",
            &["chrome.exe"],
            false,
            false,
            false,
        );
        assert_eq!(classify_broker_context(&chinese, true), BrokerScene::Password);

        let english = context(
            "windows security google password manager",
            &["msedge.exe"],
            false,
            false,
            false,
        );
        assert_eq!(classify_broker_context(&english, true), BrokerScene::Password);
    }

    #[test]
    fn broker_scene_keeps_passkey_ahead_of_password_words() {
        let context = context(
            "windows 安全中心 通行密钥和安全密钥 password manager",
            &["chrome.exe"],
            true,
            false,
            false,
        );
        assert_eq!(classify_broker_context(&context, true), BrokerScene::Passkey);
    }

    #[test]
    fn active_webauthn_overrides_explicit_password_text() {
        let context = context(
            "windows security password manager",
            &["chrome.exe"],
            true,
            true,
            false,
        );
        assert_eq!(classify_broker_context(&context, true), BrokerScene::Passkey);
    }

    #[test]
    fn ready_monitor_with_browser_triggers_password_fill() {
        let ready_no_keywords = context(
            "windows 安全中心 登录qq邮箱",
            &["credentialuibroker.exe", "chrome.exe"],
            true,
            false,
            false,
        );
        assert_eq!(
            classify_broker_context(&ready_no_keywords, true),
            BrokerScene::BrowserPasswordFill
        );
        assert_eq!(classify_broker_context(&ready_no_keywords, false), BrokerScene::Unknown);

        let unavailable = context(
            "windows 安全中心 登录qq邮箱",
            &["chrome.exe"],
            false,
            false,
            false,
        );
        assert_eq!(
            classify_broker_context(&unavailable, true),
            BrokerScene::MonitorUnavailable
        );
    }

    #[test]
    fn broker_scene_detects_password_fill_prompt_text() {
        let context = context(
            "windows 安全中心 chrome 正尝试在 wx.mail.qq.com 上填充您的密码",
            &["chrome.exe"],
            false,
            false,
            false,
        );
        assert_eq!(
            classify_broker_context(&context, true),
            BrokerScene::BrowserPasswordFill
        );
    }

    #[test]
    fn settings_pin_and_private_windows_fail_closed() {
        let settings = context(
            "windows 安全中心 password",
            &["systemsettings.exe"],
            true,
            false,
            false,
        );
        assert_eq!(
            classify_broker_context(&settings, true),
            BrokerScene::PinOrSettings
        );

        let private = context(
            "windows security login example",
            &["msedge.exe"],
            true,
            false,
            true,
        );
        assert_eq!(
            classify_broker_context(&private, true),
            BrokerScene::PrivateBrowser
        );
    }

    #[test]
    fn ready_monitor_with_browser_triggers_fill_even_without_keywords() {
        // 旧架构：分类阶段不依赖标题关键词——ready + browser 即参与，
        // 由 debounce 和枚举事件在后续流程中拦截 passkey。
        let qq = context(
            "windows 安全中心 登录 - google 账号 - google chrome",
            &["credentialuibroker.exe", "chrome.exe"],
            true,
            false,
            false,
        );
        assert_eq!(
            classify_broker_context(&qq, true),
            BrokerScene::BrowserPasswordFill
        );
    }

    #[test]
    fn active_ctap_transaction_skips_face_even_on_plain_login_page() {
        // 同一登录页，但此刻有进行中的 CTAP 事务（用户在走 passkey）→ 跳过人脸。
        let passkey_in_flight = context(
            "windows 安全中心 登录qq邮箱 - google chrome 登录qq邮箱 - google chrome",
            &["credentialuibroker.exe", "chrome.exe"],
            true,
            true,
            false,
        );
        assert_eq!(
            classify_broker_context(&passkey_in_flight, true),
            BrokerScene::Passkey
        );
    }
}
