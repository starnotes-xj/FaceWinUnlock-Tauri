// 引入必要的同步原语和Win32 API
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::{
    Foundation::{E_NOTIMPL, STATUS_SUCCESS},
    Graphics::Gdi::HBITMAP,
    Security::Credentials::{CredPackAuthenticationBufferW, CRED_PACK_PROTECTED_CREDENTIALS},
    System::Com::{CoTaskMemAlloc, CoTaskMemFree},
    UI::Shell::{
        ICredentialProviderCredential, ICredentialProviderCredentialEvents,
        ICredentialProviderEvents,
        ICredentialProviderCredential_Impl, CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH,
        CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_NO_CREDENTIAL_FINISHED,
        CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        CREDENTIAL_PROVIDER_STATUS_ICON
    }
};
use windows_core::{implement, PCWSTR, PWSTR};
use windows::Win32::Foundation::BOOL;
use crate::{CLSID_SampleProvider, SharedCredentials};

pub(crate) const BROKER_FACE_LINK_FIELD_ID: u32 = 2;

/// 凭据实现类，代表登录界面上的一个磁贴
/// 每个凭据对应一个可选择的登录选项
#[implement(ICredentialProviderCredential)]
pub struct SampleCredential {
    // 用于接收系统事件通知的接口（互斥锁保护线程安全）
    events: Mutex<Option<ICredentialProviderCredentialEvents>>,
    shared_creds: Arc<Mutex<SharedCredentials>>,
    auth_package_id: u32,
    provider_events: Mutex<Option<ICredentialProviderEvents>>,
    provider_advise_context: usize,
    broker_fallback_enabled: bool,
    broker_manual_run: Arc<AtomicBool>,
    broker_observation: Mutex<Option<crate::credui_observation::HostObservation>>,
}

impl SampleCredential {
    /// 创建新的凭据实例
    pub fn new(
        shared_creds: Arc<Mutex<SharedCredentials>>,
        auth_package_id: u32,
        provider_events: Option<ICredentialProviderEvents>,
        provider_advise_context: usize,
        broker_fallback_enabled: bool,
        broker_manual_run: Arc<AtomicBool>,
    ) -> Self {
        info!("SampleCredential::new - 创建凭据实例");
        Self {
            events: Mutex::new(None),
            shared_creds,
            auth_package_id,
            provider_events: Mutex::new(provider_events),
            provider_advise_context,
            broker_fallback_enabled,
            broker_manual_run,
            broker_observation: Mutex::new(None),
        }
    }

    fn queue_broker_manual_run(&self, broker_guard_blocks_face: bool) -> bool {
        if !self.broker_fallback_enabled || broker_guard_blocks_face {
            return false;
        }
        let creds = self.shared_creds.lock().unwrap();
        if creds.broker_fallback_to_pin || creds.is_ready {
            return false;
        }
        self.broker_manual_run.store(true, Ordering::SeqCst);
        true
    }
}

impl Drop for SampleCredential {
    fn drop(&mut self) {
        info!("SampleCredential::drop - 销毁凭据实例");
        if let Ok(observation) = self.broker_observation.get_mut() {
            if let Some(observation) = observation.take() {
                observation.end("drop");
            }
        }
    }
}

impl ICredentialProviderCredential_Impl for SampleCredential_Impl {
    /// 设置事件通知接口，用于向系统发送状态变化
    /// pcpce: 系统提供的事件接口
    fn Advise(&self, pcpce: windows_core::Ref<ICredentialProviderCredentialEvents>) -> windows_core::Result<()> {
        info!("SampleCredential::Advise - 注册事件通知");
        let events = pcpce.clone();
        *self.events.lock().unwrap() = events.clone(); // 保存事件接口

        if self.broker_fallback_enabled {
            let observation = events.as_ref().and_then(crate::credui_observation::observe_after_advise);
            let previous = std::mem::replace(&mut *self.broker_observation.lock().unwrap(), observation);
            if let Some(previous) = previous {
                previous.end("re_advise");
            }
        }

        Ok(())
    }

    /// 取消事件通知
    fn UnAdvise(&self) -> windows_core::Result<()> {
        info!("SampleCredential::UnAdvise - 取消事件通知");

        let mut events = self.events.lock().unwrap();
        *events = None; // 清除事件接口
        drop(events);
        if let Some(observation) = self.broker_observation.lock().unwrap().take() {
            observation.end("unadvise");
        }
        Ok(())
    }

    /// 当凭据磁贴被选中时调用。
    /// 返回值即为 `*pbAutoLogon`——仅当凭据已就绪（面容识别完成）时返回 TRUE，
    /// 否则返回 FALSE 防止 LogonUI 进入「SetSelected(true)→GetSerialization(未就绪)」
    /// 的无限重试循环，导致桌面加载卡死（白色圆点转圈→强制关机）。
    /// 参考：Stack Overflow #66706711, #55512774; Microsoft CPUS_LOGON 文档。
    fn SetSelected(&self) -> windows_core::Result<BOOL> {
        let creds = self.shared_creds.lock().unwrap();
        let ready = creds.has_pending_face_authorization();
        info!(
            "SampleCredential::SetSelected - 磁贴被选中, autoLogon={}",
            ready
        );
        Ok(BOOL::from(ready))
    }

    /// 当凭据磁贴被取消选中时调用
    fn SetDeselected(&self) -> windows_core::Result<()> {
        info!("SampleCredential::SetDeselected - 磁贴被取消选中");
        Ok(())
    }

    /// 获取字段的状态（可见性和交互性）
    /// dwfieldid: 字段ID
    /// pcpfs: 输出参数，字段的显示状态
    /// pcpfis: 输出参数，字段的交互状态
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE
    ) -> windows_core::Result<()> {
        info!("SampleCredential::GetFieldState - 获取字段 {} 的状态", dwfieldid);
        unsafe {
            match dwfieldid {
                // 字段0: 图标，字段1: 文本
                0 | 1 => {
                    *pcpfs = CPFS_DISPLAY_IN_BOTH; // 在磁贴和详细视图中都显示
                    *pcpfis = CPFIS_NONE;          // 非交互元素（不能点击或编辑）
                }
                BROKER_FACE_LINK_FIELD_ID if self.broker_fallback_enabled => {
                    // BOTH：CredUI 主机在同调用方的后续对话框会预选上次使用的
                    // （PIN/密码）磁贴，仅选中态显示会让链接在第二个对话框里不可见。
                    // FOCUSED：把初始焦点从主机的「取消」按钮移到链接上，使回车
                    // 等效于点击链接而不是直接取消。
                    *pcpfs = CPFS_DISPLAY_IN_BOTH;
                    *pcpfis = CPFIS_FOCUSED;
                }
                _ => {
                    error!("SampleCredential::GetFieldState - 无效的字段ID: {}", dwfieldid);
                    return Err(windows::Win32::Foundation::E_INVALIDARG.into());
                }
            }
        }
        Ok(())
    }

    /// 获取文本字段的内容
    /// dwfieldid: 字段ID
    fn GetStringValue(&self, dwfieldid: u32) -> windows_core::Result<PWSTR> {
        info!("SampleCredential::GetStringValue - 获取字段 {} 的文本内容", dwfieldid);
        let val = match dwfieldid {
            1 if self.broker_fallback_enabled => "仅在浏览器填充密码时使用下方人脸验证链接",
            1 => "FaceWinUnlock - 开机延迟识别；锁屏后触碰鼠标或按键启动",
            BROKER_FACE_LINK_FIELD_ID if self.broker_fallback_enabled => "这是密码填充，使用人脸验证",
            _ => {
                warn!("SampleCredential::GetStringValue - 字段 {} 无文本内容", dwfieldid);
                ""
            }
        };
        
        // 分配COM可释放的内存（使用CoTaskMemAlloc）
        unsafe {
            let utf16: Vec<u16> = val.encode_utf16().chain(Some(0)).collect(); // 转换为UTF-16并添加终止符
            let ptr = windows::Win32::System::Com::CoTaskMemAlloc(utf16.len() * 2); // 分配内存
            if ptr.is_null() {
                error!("SampleCredential::GetStringValue - 内存分配失败");
                return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
            }
            // 复制数据到分配的内存
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr as *mut u16, utf16.len());
            Ok(PWSTR(ptr as *mut _))
        }
    }

    /// 获取图标字段的位图
    /// _dwfieldid: 字段ID（这里是0）
    fn GetBitmapValue(&self, _dwfieldid: u32) -> windows_core::Result<HBITMAP> {
        info!("SampleCredential::GetBitmapValue - 获取图标字段的位图");
        Ok(HBITMAP::default())  // 返回默认图标
    }

    /// 获取复选框字段的值（未实现）
    fn GetCheckboxValue(&self, _dwfieldid: u32, _pbchecked: *mut BOOL, _ppszlabel: *mut PWSTR) -> windows_core::Result<()> {
        info!("SampleCredential::GetCheckboxValue - 未实现的接口");
        Err(E_NOTIMPL.into())
    }

    /// 获取提交按钮字段的值（未实现）
    fn GetSubmitButtonValue(&self, _dwfieldid: u32) -> windows_core::Result<u32> {
        Err(E_NOTIMPL.into())
    }

    /// 获取下拉框字段的选项数量（未实现）
    fn GetComboBoxValueCount(&self, _dwfieldid: u32, _pcitems: *mut u32, _pdwselecteditem: *mut u32) -> windows_core::Result<()> {
        info!("SampleCredential::GetComboBoxValueCount - 未实现的接口");
        Err(E_NOTIMPL.into())
    }

    /// 获取下拉框指定选项的文本（未实现）
    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows_core::Result<PWSTR> {
        info!("SampleCredential::GetComboBoxValueAt - 未实现的接口");
        Err(E_NOTIMPL.into())
    }

    /// 设置文本字段的值（未实现）
    fn SetStringValue(&self, _dwfieldid: u32, _psz: &windows_core::PCWSTR) -> windows_core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    /// 设置复选框字段的值（未实现）
    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> windows_core::Result<()> {
        info!("SampleCredential::SetCheckboxValue - 未实现的接口");
        Err(E_NOTIMPL.into())
    }

    /// 设置下拉框选中项（未实现）
    fn SetComboBoxSelectedValue(&self, _dwfieldid: u32, _dwselecteditem: u32) -> windows_core::Result<()> {
        info!("SampleCredential::SetComboBoxSelectedValue - 未实现的接口");
        Err(E_NOTIMPL.into())
    }

    /// 浏览器 CredUI 只在用户明确选择密码填充时启动面容识别。
    fn CommandLinkClicked(&self, dwfieldid: u32) -> windows_core::Result<()> {
        if dwfieldid != BROKER_FACE_LINK_FIELD_ID || !self.broker_fallback_enabled {
            return Err(windows::Win32::Foundation::E_INVALIDARG.into());
        }
        if self.queue_broker_manual_run(crate::browser_broker_guard_blocks_face()) {
            info!("SampleCredential::CommandLinkClicked - 用户明确请求浏览器人脸验证");
        } else {
            info!("SampleCredential::CommandLinkClicked - 当前会话不接受人脸请求");
        }
        Ok(())
    }

    /// 序列化凭据信息（登录时调用）
    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        // 提交即意图：broker 密码场景中「确定」按钮与回车都是对已选中人脸磁贴的
        // 显式提交，与点击命令链接等效。凭据未就绪时触发同一条手动识别路径，下方
        // 既有逻辑仍返回 NOT_FINISHED 保持对话框打开，刷脸成功后由 CredentialsChanged
        // 流程完成提交。queue_broker_manual_run 内部会获取 shared_creds 锁，必须在
        // 下面长生命周期锁之前调用，避免 std::sync::Mutex 重入死锁。
        if self.queue_broker_manual_run(crate::browser_broker_guard_blocks_face()) {
            info!("SampleCredential::GetSerialization - 提交即意图，已请求浏览器人脸验证");
        }
        let mut creds = self.shared_creds.lock().unwrap();

        if !creds.is_ready {
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED; }
            return Ok(());
        }
        if !creds.has_pending_face_authorization() {
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
            return Ok(());
        }

        // Passkey authorization owns the same inter-process route mutex while
        // face verification is pending. Never serialize a generic broker
        // credential if the mutex is busy, missing, or was abandoned.
        let _route_guard = if self.broker_fallback_enabled {
            match crate::credui_route_guard::try_acquire() {
                Ok(guard) => Some(guard),
                Err(reason) => {
                    error!(
                        "SampleCredential::GetSerialization - broker route arbitration denied serialization: {}",
                        reason
                    );
                    crate::zeroization::zeroize_string(&mut creds.username);
                    crate::zeroization::zeroize_string(&mut creds.password);
                    crate::zeroization::zeroize_string(&mut creds.domain);
                    creds.is_ready = false;
                    creds.is_unlocked = false;
                    creds.broker_fallback_to_pin = true;
                    unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
                    crate::CPipeListener::reject_broker_route_async(
                        "Passkey route arbitration denied broker serialization",
                        self.provider_events.lock().unwrap().clone(),
                        self.provider_advise_context,
                    );
                    return Ok(());
                }
            }
        } else {
            None
        };

        info!("SampleCredential::GetSerialization - 开始序列化凭据");

        // 本地账户使用 ".\username"，域账户使用 "domain\username"。
        // 初始化测试链路会显式传 ".\username"，普通面容记录只保存裸用户名；
        // 两条链路必须打包出一致的本地账户格式，否则 Windows 会返回 0xC000006D。
        let qualified_user = if creds.domain == "." {
            if creds.username.contains('\\') || creds.username.contains('@') {
                creds.username.clone()
            } else {
                format!(".\\{}", creds.username)
            }
        } else if creds.domain.is_empty() {
            creds.username.clone()
        } else {
            format!("{}\\{}", creds.domain, creds.username)
        };

        let user_wide = SecretWideBuffer::new(&qualified_user);
        let pwd_wide = SecretWideBuffer::new(&creds.password);
        let pwd_ptr = PCWSTR::from_raw(pwd_wide.as_ptr());

        // 第一次调用：查询所需缓冲区大小（预期返回 ERROR_INSUFFICIENT_BUFFER）
        let mut cb_packed = 0u32;
        unsafe {
            let _ = CredPackAuthenticationBufferW(
                CRED_PACK_PROTECTED_CREDENTIALS,
                PCWSTR::from_raw(user_wide.as_ptr()),
                pwd_ptr,
                None,
                &mut cb_packed,
            );
        }

        if cb_packed == 0 {
            error!("SampleCredential::GetSerialization - 无法获取缓冲区大小");
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
            // 凭据打包失败，重置标志防止死循环
            creds.consume_face_authorization();
            return Ok(());
        }

        // 分配输出缓冲区（Windows 负责释放）
        let packed_capacity = cb_packed as usize;
        let buf = unsafe { CoTaskMemAlloc(packed_capacity) as *mut u8 };
        if buf.is_null() {
            error!("SampleCredential::GetSerialization - 内存分配失败");
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
            creds.consume_face_authorization();
            return Ok(());
        }

        // 第二次调用：实际打包凭据
        let pack_result = unsafe {
            CredPackAuthenticationBufferW(
                CRED_PACK_PROTECTED_CREDENTIALS,
                PCWSTR::from_raw(user_wide.as_ptr()),
                pwd_ptr,
                Some(buf),
                &mut cb_packed,
            )
        };

        if let Err(e) = pack_result {
            error!("SampleCredential::GetSerialization - CredPackAuthenticationBufferW 失败: {:?}", e);
            unsafe {
                crate::zeroization::zeroize_raw_bytes(buf, packed_capacity);
                CoTaskMemFree(Some(buf as *mut _));
                *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
            }
            creds.consume_face_authorization();
            return Ok(());
        }

        // 凭据打包成功，重置 is_unlocked 标志（#112 修复：延迟重置防止 UAC 竞态）
        if !creds.consume_face_authorization() {
            unsafe {
                crate::zeroization::zeroize_raw_bytes(buf, packed_capacity);
                CoTaskMemFree(Some(buf as *mut _));
                *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
            }
            error!("SampleCredential::GetSerialization - 人脸授权在序列化期间失效");
            return Ok(());
        }
        drop(creds);

        unsafe {
            (*pcpcs).ulAuthenticationPackage = self.auth_package_id;
            (*pcpcs).cbSerialization         = cb_packed;
            (*pcpcs).rgbSerialization        = buf;
            (*pcpcs).clsidCredentialProvider = CLSID_SampleProvider;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }

        info!("SampleCredential::GetSerialization - 凭据序列化完成");
        Ok(())
    }

    /// 报告登录结果
    fn ReportResult(
        &self,
        ntsstatus: windows::Win32::Foundation::NTSTATUS,
        _ntssubstatus: windows::Win32::Foundation::NTSTATUS,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        if ntsstatus == STATUS_SUCCESS {
            info!("SampleCredential::ReportResult - 登录成功");
            return Ok(());
        }

        // 登录失败：清除凭据，防止 Windows 持续用错误凭据重试 (#102)
        error!("SampleCredential::ReportResult - 登录失败，NTSTATUS: {:#010X}", ntsstatus.0);
        let fallback_to_pin = self.broker_fallback_enabled
            && crate::current_process_exe_name() == "credentialuibroker.exe";
        {
            let mut creds = self.shared_creds.lock().unwrap();
            crate::zeroization::zeroize_string(&mut creds.username);
            crate::zeroization::zeroize_string(&mut creds.password);
            creds.is_ready = false;
            creds.is_unlocked = false;
            if fallback_to_pin {
                creds.broker_fallback_to_pin = true;
            }
        }

        unsafe {
            if !ppszoptionalstatustext.is_null() {
                let msg = if fallback_to_pin {
                    "人脸验证未通过，已切回 Windows PIN"
                } else {
                    "用户名或密码错误，请检查设置"
                };
                let wide: Vec<u16> = msg.encode_utf16().chain(Some(0)).collect();
                let ptr = CoTaskMemAlloc(wide.len() * 2) as *mut u16;
                if !ptr.is_null() {
                    std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                    *ppszoptionalstatustext = PWSTR(ptr);
                }
            }
            if !pcpsioptionalstatusicon.is_null() {
                *pcpsioptionalstatusicon = CPSI_ERROR;
            }
        }

        if fallback_to_pin {
            warn!("SampleCredential::ReportResult - broker 凭据被拒绝，立即回退 Windows PIN");
            crate::CPipeListener::mark_broker_pin_fallback();
            crate::CPipeListener::request_broker_release("broker ReportResult failure");
            if let Some(events) = self.provider_events.lock().unwrap().as_ref() {
                if let Err(e) = unsafe { events.CredentialsChanged(self.provider_advise_context) } {
                    error!("SampleCredential::ReportResult - 触发 PIN 回退重枚举失败: {:?}", e);
                }
            }
        }
        Ok(())
    }
}

// 将 String 转换为符合 Win32 要求的 UTF-16 向量（带 null 结尾）
fn to_wide_vec(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct SecretWideBuffer(Vec<u16>);

impl SecretWideBuffer {
    fn new(value: &str) -> Self {
        Self(to_wide_vec(value))
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

impl Drop for SecretWideBuffer {
    fn drop(&mut self) {
        crate::zeroization::zeroize_wide(&mut self.0);
    }
}

#[cfg(test)]
mod manual_broker_run_tests {
    use super::*;

    fn credential(is_broker: bool) -> (SampleCredential, Arc<Mutex<SharedCredentials>>, Arc<AtomicBool>) {
        let creds = Arc::new(Mutex::new(SharedCredentials {
            username: String::new(),
            password: String::new(),
            domain: ".".to_string(),
            is_ready: false,
            is_unlocked: false,
            broker_fallback_to_pin: false,
        }));
        let request = Arc::new(AtomicBool::new(false));
        let credential = SampleCredential::new(creds.clone(), 0, None, 0, is_broker, request.clone());
        (credential, creds, request)
    }

    #[test]
    fn only_explicit_browser_request_queues_a_run() {
        let (broker, creds, request) = credential(true);
        assert!(!broker.queue_broker_manual_run(true));
        assert!(!request.load(Ordering::SeqCst));
        assert!(broker.queue_broker_manual_run(false));
        assert!(request.swap(false, Ordering::SeqCst));
        creds.lock().unwrap().broker_fallback_to_pin = true;
        assert!(!broker.queue_broker_manual_run(false));
        assert!(!request.load(Ordering::SeqCst));

        let (non_broker, _, request) = credential(false);
        assert!(!non_broker.queue_broker_manual_run(false));
        assert!(!request.load(Ordering::SeqCst));
    }
}
