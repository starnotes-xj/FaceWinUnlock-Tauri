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
pub mod animation;

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

/// broker CredUI 场景分类。credentialuibroker.exe 同时托管「浏览器查看密码」「Chrome 通行
/// 密钥(passkey)验证」「Windows 设置启用插件的 PIN 验证」，三者 cpus/dwflags/CLSID 完全
/// 一致（实测 dwflags 均为 0x250），无法用这些区分。唯一可靠信号是「触发弹窗的应用窗口标题」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerScene {
    /// 查看已保存密码 — 走人脸识别
    Password,
    /// 通行密钥(passkey)验证 — 跳过人脸，交还 Windows 原生（选原生 Hello 正常输 PIN）
    Passkey,
    /// 设置 PIN / 登录 / 无法判断 — 保守跳过人脸，避免误触发与卡死
    Unknown,
}

/// 收集前台窗口及其所有者/根所有者窗口的标题（拼接小写）。
///
/// broker 弹窗(GetForegroundWindow)的标题是「Windows 安全中心」（无区分信息），但它的
/// 所有者窗口就是触发它的应用（Chrome / 设置），标题直接反映用户意图。仅用 GetWindowTextW
/// 读这些应用窗口标题——应用进程非受限，能稳定读到（不像 broker 进程内 UIA COM 被封）。
fn foreground_window_titles() -> String {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindow, GW_OWNER, GetWindowTextW, GetAncestor, GET_ANCESTOR_FLAGS,
    };
    fn title_of(hwnd: HWND) -> String {
        if hwnd.0.is_null() { return String::new(); }
        let mut buf = [0u16; 512];
        let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
        if n <= 0 { return String::new(); }
        String::from_utf16_lossy(&buf[..n as usize])
    }
    let fg = unsafe { GetForegroundWindow() };
    let mut parts = vec![title_of(fg)];
    if let Ok(owner) = unsafe { GetWindow(fg, GW_OWNER) } {
        parts.push(title_of(owner));
    }
    // GA_ROOTOWNER = 3：根所有者窗口（兜底，确保拿到触发应用的主窗口标题）
    let root = unsafe { GetAncestor(fg, GET_ANCESTOR_FLAGS(3)) };
    parts.push(title_of(root));
    parts.join(" ").to_lowercase()
}

/// 按前台窗口链标题区分 broker 场景。passkey 关键词优先（"通行密钥"含"密钥"但绝不含"密码"，
/// "密码管理工具"含"密码"，二者无交集，安全）。读不到任何关键词 → Unknown（保守跳过）。
pub fn classify_broker_scene() -> BrokerScene {
    let titles = foreground_window_titles();
    info!("classify_broker_scene - 前台窗口标题: {:?}", titles);
    const PASSKEY_KW: &[&str] = &[
        "通行密钥", "passkey", "安全密钥", "security key", "证实是您本人", "确保是你本人",
    ];
    const PASSWORD_KW: &[&str] = &[
        "密码", "password",
    ];
    if PASSKEY_KW.iter().any(|k| titles.contains(&k.to_lowercase())) {
        BrokerScene::Passkey
    } else if PASSWORD_KW.iter().any(|k| titles.contains(&k.to_lowercase())) {
        BrokerScene::Password
    } else {
        BrokerScene::Unknown
    }
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
        // 在锁内写文件日志（尤其配合动画 UI 的 D3D/DComp 多线程频繁 attach/detach）有死锁
        // 风险，还会把日志刷爆（曾达 3368/5304 行噪音）。这里保持空处理、立即返回。
        _ => {}
    }
    BOOL::from(true)
}

#[cfg(test)]
mod shared_credentials_tests {
    use super::SharedCredentials;

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
}
