// 引入必要的Win32 API和同步原语
use windows::Win32::{Foundation::{E_NOTIMPL, HANDLE, STATUS_SUCCESS}, Security::Authentication::Identity::{LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, LSA_STRING}, UI::Shell::*};
use std::sync::{Arc, Mutex};
use crate::{dll_add_ref, dll_release, read_facewinunlock_registry, CPipeListener::CPipeListener, CSampleCredential::SampleCredential, SharedCredentials};
use windows_core::{implement, PSTR, PWSTR};
use windows::Win32::Foundation::BOOL;

/// 凭据提供程序主类，负责管理凭据和与系统交互
#[implement(ICredentialProvider)]
pub struct SampleProvider {
    // 内部状态（使用互斥锁保证线程安全）
    inner: Mutex<ProviderInner>,
}

/// 凭据提供程序的内部状态
struct ProviderInner {
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    dwflags: u32,
    is_scenario_supported: bool,
    events: Option<ICredentialProviderEvents>,
    advise_context: usize,
    listener: Option<Arc<Mutex<CPipeListener>>>,
    pub shared_creds: Arc<Mutex<SharedCredentials>>,
    pub auth_package_id: u32,
    pub credential: Option<ICredentialProviderCredential>,
}

impl SampleProvider {
    /// 创建新的凭据提供程序实例
    pub fn new() -> Self {
        info!("SampleProvider::new - 创建凭据提供程序实例");
        dll_add_ref(); // 增加DLL引用计数

        // 创建共享的凭据列表实例
        let shared = Arc::new(Mutex::new(SharedCredentials {
            username: String::new(),
            password: String::new(),
            domain: String::from("."),
            is_ready: false,
            is_unlocked: false,
            broker_fallback_to_pin: false,
        }));

        // 获取认证包ID
        let auth_id = retrieve_negotiate_auth_package().unwrap_or(0);

        Self {
            inner: Mutex::new(ProviderInner {
                usage_scenario: CPUS_LOGON,
                dwflags: 0,
                is_scenario_supported: true,
                events: None,
                advise_context: 0,
                listener: None,
                shared_creds: shared,
                auth_package_id: auth_id,
                credential: None,
            }),
        }
    }

    fn reset_broker_session_state(inner: &mut ProviderInner) {
        if let Some(listener) = inner.listener.take() {
            listener.lock().unwrap().stop_and_join();
        }
        inner.credential = None;
        inner.shared_creds.lock().unwrap().reset_for_new_usage();
        crate::CPipeListener::reset_broker_pin_fallback();
    }
}

/// 实现Drop trait，在对象销毁时减少引用计数
impl Drop for SampleProvider {
    fn drop(&mut self) {
        info!("SampleProvider::drop - 销毁凭据提供程序实例");
        dll_release(); // 减少DLL引用计数
    }
}

/// 实现ICredentialProvider接口，这是凭据提供程序的核心接口
impl ICredentialProvider_Impl for SampleProvider_Impl {
    /// 设置凭据提供程序的使用场景
    /// cpus: 使用场景（登录、解锁、切换用户等）
    /// dwflags: 附加标志（CREDUI 场景下包含调用方传入的 CREDUIWIN_* 标志）
    fn SetUsageScenario(&self, cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO, dwflags: u32) -> windows_core::Result<()> {
        let host = crate::current_process_exe_name();
        info!(
            "SampleProvider::SetUsageScenario - 设置使用场景: {:?}, flags: {:#X}, 宿主进程: {}",
            cpus, dwflags, host
        );
        let mut inner = self.inner.lock().unwrap();
        inner.usage_scenario = cpus;
        inner.dwflags = dwflags;

        // 读取 UNLOCK_SCENE 注册表（逗号分隔的场景 ID，如 "1,2"）
        // CPUS_LOGON=1, CPUS_UNLOCK_WORKSTATION=2, CPUS_CREDUI=4
        let supported: Vec<u32> = crate::read_facewinunlock_registry("UNLOCK_SCENE")
            .unwrap_or_else(|_| "1,2,4".to_string())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        info!("支持的解锁场景: {:?}", supported);

        inner.is_scenario_supported = supported.contains(&(cpus.0 as u32));
        if !inner.is_scenario_supported {
            // 告知 Windows 此提供程序不处理该场景，修复浏览器 PIN 弹窗卡顿问题 (#118)
            info!("SampleProvider::SetUsageScenario - 场景 {} 不受支持，跳过", cpus.0);
            return Err(E_NOTIMPL.into());
        }

        // CREDUI 场景黑名单过滤 (#114):
        // 应用（如 RDP/mstsc）调用 CredUIPromptForWindowsCredentials 时会带 CREDUIWIN_GENERIC (0x1)
        // UAC 系统提权则不带此标志。通过过滤 GENERIC 请求避免干扰 RDP 等应用的密码验证。
        if cpus.0 == 4 && (dwflags & 0x1) != 0 {
            let allow_generic = crate::read_facewinunlock_registry("CREDUI_ALLOW_GENERIC")
                .unwrap_or_else(|_| "0".to_string());
            if allow_generic != "1" {
                info!("SampleProvider::SetUsageScenario - CREDUI GENERIC 请求已被过滤（CREDUI_ALLOW_GENERIC=0），跳过");
                inner.is_scenario_supported = false;
                return Err(E_NOTIMPL.into());
            }
        }

        if cpus.0 == 4 && host == "credentialuibroker.exe" {
            let scene = crate::classify_broker_scene(dwflags);
            info!("SampleProvider::SetUsageScenario - broker 场景分类: {:?}", scene);
            if !scene.uses_face() {
                // 通行密钥(选原生 Hello)/设置 PIN/未知 → 不介入，交还 Windows 原生（PIN/Hello）。
                // 返回 E_NOTIMPL 后本 Provider 完全不参与：不启动人脸监听、不装输入 Hook、
                // 不创建动画、摄像头不亮——根治「选原生 Hello 移动鼠标触发人脸」与「启用插件输 PIN 卡死」。
                info!("SampleProvider::SetUsageScenario - 跳过人脸，交还 Windows");
                inner.is_scenario_supported = false;
                return Err(E_NOTIMPL.into());
            }
            match scene {
                crate::BrokerScene::Password => {
                    info!("SampleProvider::SetUsageScenario - 查看密码场景，启用人脸");
                }
                crate::BrokerScene::BrowserPasswordFill => {
                    info!("SampleProvider::SetUsageScenario - 浏览器填充密码场景，启用人脸");
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// 设置序列化的凭据信息（用于预填充凭据）。
    /// 诊断用途：credentialuibroker 的「网页填密码」与「passkey 登录」触发窗口标题相同、无法区分，
    /// 而调用方(Chrome)传入的序列化(auth 包 / CLSID / 字节)很可能不同——这是唯一未挖过的可靠信号。
    /// 此处把序列化全量打进 facewinunlock.log，供对比两场景后确定区分字段（下版据此自动分类）。
    fn SetSerialization(&self, pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION) -> windows_core::Result<()> {
        unsafe {
            if let Some(cs) = pcpcs.as_ref() {
                let hex = if !cs.rgbSerialization.is_null() && cs.cbSerialization > 0 {
                    let n = (cs.cbSerialization as usize).min(96);
                    let slice = std::slice::from_raw_parts(cs.rgbSerialization, n);
                    slice.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                } else {
                    String::from("(空)")
                };
                info!(
                    "SampleProvider::SetSerialization - authPkg={} clsidCP={:?} cbSer={} hex[..96]={}",
                    cs.ulAuthenticationPackage, cs.clsidCredentialProvider, cs.cbSerialization, hex
                );
            } else {
                info!("SampleProvider::SetSerialization - pcpcs=null");
            }
        }
        Ok(())
    }

    /// 注册系统事件通知
    /// pcpe: 系统提供的事件接口
    /// upadvisecontext: 通知上下文ID
    fn Advise(&self, pcpe: windows_core::Ref<ICredentialProviderEvents>, upadvisecontext: usize) -> windows_core::Result<()> {
        info!("SampleProvider::Advise - 注册事件通知，上下文ID: {}", upadvisecontext);
        let mut inner = self.inner.lock().unwrap();
        let is_broker = inner.usage_scenario.0 == 4
            && crate::current_process_exe_name() == "credentialuibroker.exe";

        if is_broker {
            // credentialuibroker.exe 可能复用同一 Provider 实例而不重新走
            // SetUsageScenario。每次 Advise 都视为新的 broker 会话边界，再清一次
            // 缓存状态，防止第二次查看密码沿用上次 fallback / credential 对象。
            SampleProvider::reset_broker_session_state(&mut inner);
            let scene = crate::classify_broker_scene(inner.dwflags);
            if !scene.uses_face() {
                info!(
                    "SampleProvider::Advise - broker 场景复查为 {:?}，停止参与",
                    scene
                );
                inner.is_scenario_supported = false;
                return Err(E_NOTIMPL.into());
            }
        }

        inner.events = pcpe.clone(); // 保存事件接口
        inner.advise_context = upadvisecontext; // 保存上下文ID

        // 只在受支持的场景下启动管道监听（防止不必要的场景触发面容识别）
        if inner.is_scenario_supported {
            if let Some(events) = &inner.events {
                // 主场景（登录/解锁）：允许 stop_and_join 时通知 Unlock EXE 释放摄像头 (#117)
                let is_primary = inner.usage_scenario.0 == 1 || inner.usage_scenario.0 == 2;
                // Broker 仅在分类器明确允许密码验证时启动；WebAuthn 状态还会在
                // CPipeListener 发送 prepare/run 前继续复查，关闭订阅延迟竞态。
                inner.listener = Some(CPipeListener::start(
                    events.clone(),
                    upadvisecontext,
                    inner.shared_creds.clone(),
                    is_primary,
                    is_broker,
                ));
            }
        }

        Ok(())
    }

    /// 取消事件通知
    fn UnAdvise(&self) -> windows_core::Result<()> {
        info!("SampleProvider::UnAdvise - 取消事件通知");
        info!("SampleProvider::UnAdvise - 获取 inner 锁...");
        let mut inner = self.inner.lock().unwrap();
        info!("SampleProvider::UnAdvise - inner 锁已获取");
        inner.events = None; // 清除事件接口
        inner.advise_context = 0; // 重置上下文ID

        // 2026-01-23 无意中发现,在锁屏界面黑屏后,Windows会调用UnAdvise
        // 这会导致管道监听线程无法正常停止,从而导致内存泄漏
        // 因此,在取消事件通知时,我们需要停止并清理管道监听线程
        // 停止并清理管道监听线程
        if let Some(listener) = inner.listener.take() {
            info!("SampleProvider::UnAdvise - 获取 listener 锁并停止监听...");
            let mut listener = listener.lock().unwrap();
            info!("SampleProvider::UnAdvise - listener 锁已获取，调用 stop_and_join");
            listener.stop_and_join();
            info!("SampleProvider::UnAdvise - stop_and_join 返回");
        }
        inner.listener = None;
        info!("SampleProvider::UnAdvise - 完成");
        Ok(())
    }

    /// 获取字段描述符的数量
    fn GetFieldDescriptorCount(&self) -> windows_core::Result<u32> {
        let count = if is_pin_enabled() { 4 } else { 2 };
        info!("SampleProvider::GetFieldDescriptorCount - 字段数量: {}", count);
        Ok(count)
    }

    /// 获取指定索引的字段描述符
    /// dwindex: 字段索引
    fn GetFieldDescriptorAt(&self, dwindex: u32) -> windows_core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        info!("SampleProvider::GetFieldDescriptorAt - 获取字段 {} 的描述符", dwindex);
        unsafe {
            // 分配字段描述符的内存（使用CoTaskMemAlloc，系统会负责释放）
            let size = std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>();
            let ptr = windows::Win32::System::Com::CoTaskMemAlloc(size) as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
            if ptr.is_null() {
                error!("SampleProvider::GetFieldDescriptorAt - 内存分配失败");
                return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
            }
    
            // 根据索引设置字段类型和标签
            // 使用 SMALL_TEXT 让磁贴更小巧，类似状态指示器 (#91)
            // PIN 启用时新增字段 2 (密码输入框) 和 3 (提交按钮)
            let (ft, label) = match dwindex {
                0 => (CPFT_TILE_IMAGE, "面容图标"),
                1 => (CPFT_SMALL_TEXT, "面容解锁"),
                2 if is_pin_enabled() => (CPFT_PASSWORD_TEXT, "Hello PIN"),
                3 if is_pin_enabled() => (CPFT_SUBMIT_BUTTON, "PIN 解锁"),
                _ => {
                    error!("SampleProvider::GetFieldDescriptorAt - 无效的字段索引: {}", dwindex);
                    return Err(windows::Win32::Foundation::E_INVALIDARG.into());
                }
            };
    
            // 转换标签为UTF-16并分配内存
            let label_u16: Vec<u16> = label.encode_utf16().chain(Some(0)).collect();
            let label_ptr = windows::Win32::System::Com::CoTaskMemAlloc(label_u16.len() * 2) as *mut u16;
            if label_ptr.is_null() {
                error!("SampleProvider::GetFieldDescriptorAt - 标签内存分配失败");
                windows::Win32::System::Com::CoTaskMemFree(Some(ptr as *mut _)); // 释放之前分配的内存
                return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
            }
            std::ptr::copy_nonoverlapping(label_u16.as_ptr(), label_ptr, label_u16.len());
    
            // 设置字段描述符的属性
            (*ptr).dwFieldID = dwindex;
            (*ptr).cpft = ft;
            (*ptr).pszLabel = PWSTR(label_ptr);
    
            Ok(ptr)
        }
    }

    /// 获取凭据的数量和默认凭据
    /// pdwcount: 输出参数，凭据数量
    /// pdwdefault: 输出参数，默认选中的凭据索引
    /// pbautologonwithdefault: 输出参数，是否使用默认凭据自动登录
    fn GetCredentialCount(
        &self, 
        pdwcount: *mut u32, 
        pdwdefault: *mut u32, 
        pbautologonwithdefault: *mut BOOL
    ) -> windows_core::Result<()> {
        info!("SampleProvider::GetCredentialCount - 获取凭据数量");
        let inner = self.inner.lock().unwrap();
        let mut show_tile = true;
        if let Ok(result) = read_facewinunlock_registry("SHOW_TILE") {
            if result.as_str() == "0" {
                show_tile = false;
            }
        } else {
            warn!("注册表配置读取失败!");
        }

        info!( "是否显示图标: {}", show_tile);

        unsafe {
            // 始终初始化输出指针，防止未定义行为。
            // pdwdefault 默认设为 CREDENTIAL_PROVIDER_NO_DEFAULT (0xFFFFFFFF)，
            // 仅当 autologon 确实就绪时才设为有效索引 0。
            // 若始终设为 0，LogonUI 会默认选中我们的磁贴并调用 SetSelected，
            // 结合 SetSelected(true) 即触发自动登录，在凭据未就绪时形成无限重试循环。
            const CREDENTIAL_PROVIDER_NO_DEFAULT: u32 = u32::MAX;
            *pdwdefault = CREDENTIAL_PROVIDER_NO_DEFAULT;

            let broker_fallback_to_pin = inner.usage_scenario.0 == 4
                && crate::current_process_exe_name() == "credentialuibroker.exe"
                && {
                    let creds = inner.shared_creds.lock().unwrap();
                    creds.broker_fallback_to_pin
                };

            if broker_fallback_to_pin {
                *pdwcount = 0;
                *pbautologonwithdefault = BOOL::from(false);
                info!("SampleProvider::GetCredentialCount - broker 场景已回退 PIN，隐藏 FaceWinUnlock 凭据");
                return Ok(());
            }

            // 检查是否有面容识别完成的凭据待自动登录
            // 使用 shared_creds.is_unlocked（脉冲信号），由 GetSerialization 成功后重置
            // 防止 UAC 多次调用 GetCredentialCount 导致 autologon 丢失 (#112)
            let autologon = {
                let creds = inner.shared_creds.lock().unwrap();
                creds.is_unlocked
            };

            if autologon {
                *pdwdefault = 0; // 有效的默认凭据索引
                *pdwcount = 1;
                *pbautologonwithdefault = BOOL::from(true);
                info!("SampleProvider::GetCredentialCount - 自动登录已触发");
            } else if let Some(_l) = &inner.listener {
                *pdwcount = if show_tile { 1 } else { 0 };
                *pbautologonwithdefault = BOOL::from(false);
            } else {
                *pdwcount = 0;
                *pbautologonwithdefault = BOOL::from(false);
            }
        }
        Ok(())
    }

    /// 获取指定索引的凭据
    /// dwindex: 凭据索引
    fn GetCredentialAt(&self, dwindex: u32) -> windows_core::Result<ICredentialProviderCredential> {
        info!("SampleProvider::GetCredentialAt - 获取凭据，索引: {}", dwindex);
        if dwindex == 0 {
            let mut inner = self.inner.lock().unwrap();
            if let Some(ref credential) = inner.credential {
                info!("SampleProvider::GetCredentialAt - 复用已存在的凭据实例");
                return Ok(credential.clone());
            }

            // 创建凭据实例并转换为接口返回，并传递收到的用户名和密码
            info!("SampleProvider::GetCredentialAt - 首次创建凭据实例");
            let is_broker = inner.usage_scenario.0 == 4
                && crate::current_process_exe_name() == "credentialuibroker.exe";
            let cred = SampleCredential::new(
                inner.shared_creds.clone(),
                inner.auth_package_id,
                inner.events.clone(),
                inner.advise_context,
                is_broker,
            );
            let cred_interface: ICredentialProviderCredential = cred.into();
            inner.credential = Some(cred_interface.clone());
            Ok(cred_interface)
        } else {
            error!("SampleProvider::GetCredentialAt - 无效的凭据索引: {}", dwindex);
            Err(windows::core::Error::from_hresult(windows::Win32::Foundation::E_INVALIDARG))
        }
    }
}

// 获取Negotiate AuthPackage ID
pub fn retrieve_negotiate_auth_package() -> windows_core::Result<u32> {
    info!("正在获取 AuthPackage ID...");
    let mut lsa_handle = HANDLE::default();
    
    // 建立与 LSA 的非信任连接
    let status = unsafe { LsaConnectUntrusted(&mut lsa_handle) };
    if status != STATUS_SUCCESS {
        error!("LsaConnectUntrusted 失败: {:?}", status);
        return Err(status.into());
    }

    // 准备包名称字符串 "Negotiate"
    let package_name_str = "Negotiate";
    let name_bytes = package_name_str.as_bytes();

    let package_name = LSA_STRING {
        Buffer: PSTR(name_bytes.as_ptr() as *mut u8),
        Length: name_bytes.len() as u16,
        MaximumLength: (name_bytes.len() + 1) as u16,
    };

    // 查找 ID
    let mut package_id = 0;
    let status = unsafe { LsaLookupAuthenticationPackage(lsa_handle, &package_name, &mut package_id) };
    
    // 关闭连接
    let _ = unsafe { LsaDeregisterLogonProcess(lsa_handle) };

    if status == STATUS_SUCCESS {
        info!("成功获取 AuthPackage ID: {}", package_id);
        Ok(package_id)
    } else {
        error!("获取 AuthPackage ID 失败: {:?}", status);
        Err(status.into())
    }
}

/// 检查注册表 PIN_ENABLED 是否启用 Hello PIN 解锁功能
/// 默认 "0"（关闭），设为 "1" 后凭据磁贴显示 PIN 输入框
pub fn is_pin_enabled() -> bool {
    crate::read_facewinunlock_registry("PIN_ENABLED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
