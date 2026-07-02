// 引入必要的同步原语和Win32 API
use std::sync::{Arc, Mutex};
use windows::Win32::{
    Foundation::{E_NOTIMPL, STATUS_SUCCESS},
    Graphics::Gdi::HBITMAP,
    Security::Credentials::{CredPackAuthenticationBufferW, CRED_PACK_PROTECTED_CREDENTIALS},
    System::Com::{CoTaskMemAlloc, CoTaskMemFree},
    UI::Shell::{
        ICredentialProviderCredential, ICredentialProviderCredentialEvents,
        ICredentialProviderEvents,
        ICredentialProviderCredential_Impl, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH,
        CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_NO_CREDENTIAL_FINISHED,
        CPFS_DISPLAY_IN_SELECTED_TILE,
        CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        CREDENTIAL_PROVIDER_STATUS_ICON
    }
};
use windows_core::{implement, PCWSTR, PWSTR};
use windows::Win32::Foundation::BOOL;
use crate::{CLSID_SampleProvider, SharedCredentials};

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
    /// Hello PIN 输入缓冲区。PIN 启用时，用户输入的 PIN 暂存于此。
    /// 提交后清零（SecureZeroMemory 风格）。
    pin_buffer: Mutex<String>,
}

impl SampleCredential {
    /// 创建新的凭据实例
    pub fn new(
        shared_creds: Arc<Mutex<SharedCredentials>>,
        auth_package_id: u32,
        provider_events: Option<ICredentialProviderEvents>,
        provider_advise_context: usize,
        broker_fallback_enabled: bool,
    ) -> Self {
        info!("SampleCredential::new - 创建凭据实例");
        Self {
            events: Mutex::new(None),
            shared_creds,
            auth_package_id,
            provider_events: Mutex::new(provider_events),
            provider_advise_context,
            broker_fallback_enabled,
            pin_buffer: Mutex::new(String::new()),
        }
    }
}

impl Drop for SampleCredential {
    fn drop(&mut self) {
        info!("SampleCredential::drop - 销毁凭据实例");
    }
}

impl ICredentialProviderCredential_Impl for SampleCredential_Impl {
    /// 设置事件通知接口，用于向系统发送状态变化
    /// pcpce: 系统提供的事件接口
    fn Advise(&self, pcpce: windows_core::Ref<ICredentialProviderCredentialEvents>) -> windows_core::Result<()> {
        info!("SampleCredential::Advise - 注册事件通知");
        let mut events = self.events.lock().unwrap();
        *events = pcpce.clone(); // 保存事件接口

        Ok(())
    }

    /// 取消事件通知
    fn UnAdvise(&self) -> windows_core::Result<()> {
        info!("SampleCredential::UnAdvise - 取消事件通知");

        let mut events = self.events.lock().unwrap();
        *events = None; // 清除事件接口
        Ok(())
    }

    /// 当凭据磁贴被选中时调用。
    /// 返回值即为 `*pbAutoLogon`——仅当凭据已就绪（面容识别完成）时返回 TRUE，
    /// 否则返回 FALSE 防止 LogonUI 进入「SetSelected(true)→GetSerialization(未就绪)」
    /// 的无限重试循环，导致桌面加载卡死（白色圆点转圈→强制关机）。
    /// 参考：Stack Overflow #66706711, #55512774; Microsoft CPUS_LOGON 文档。
    fn SetSelected(&self) -> windows_core::Result<BOOL> {
        let creds = self.shared_creds.lock().unwrap();
        let ready = creds.is_ready && creds.is_unlocked;
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
        let pin_enabled = crate::CSampleProvider::is_pin_enabled();
        let broker_fallback = self.shared_creds.lock().unwrap().broker_fallback_to_pin;
        unsafe {
            match dwfieldid {
                // 字段0: 图标，字段1: 文本
                0 | 1 => {
                    *pcpfs = CPFS_DISPLAY_IN_BOTH; // 在磁贴和详细视图中都显示
                    *pcpfis = CPFIS_NONE;          // 非交互元素（不能点击或编辑）
                }
                // 字段2: Hello PIN 输入框（仅 PIN 启用且未 broker 回退时可见）
                2 if pin_enabled && !broker_fallback => {
                    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE; // 仅选中时显示
                    *pcpfis = CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE(1); // CPFIS_FOCUSED
                }
                // 字段3: 提交按钮（仅 PIN 启用且未 broker 回退时可见）
                3 if pin_enabled && !broker_fallback => {
                    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
                    *pcpfis = CPFIS_NONE;
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
            1 => "FaceWinUnlock - 触碰鼠标或按下键盘即可启动人脸识别",  // 字段1的文本内容
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

    /// 获取提交按钮字段的值
    /// 字段 3 为 PIN 提交按钮，点击后返回该字段 ID
    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> windows_core::Result<u32> {
        info!("SampleCredential::GetSubmitButtonValue - 字段 {}", dwfieldid);
        if dwfieldid == 3 && crate::CSampleProvider::is_pin_enabled() {
            Ok(dwfieldid) // 返回点击的字段 ID，LogonUI 随后调用 GetSerialization
        } else {
            Err(E_NOTIMPL.into())
        }
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

    /// 设置文本字段的值
    /// 字段 2 为 Hello PIN 输入框，用户输入的 PIN 在此接收
    fn SetStringValue(&self, dwfieldid: u32, psz: &windows_core::PCWSTR) -> windows_core::Result<()> {
        if dwfieldid == 2 && crate::CSampleProvider::is_pin_enabled() {
            let pin = unsafe { psz.to_string() }.unwrap_or_default();
            info!("SampleCredential::SetStringValue - 收到 PIN 输入 (长度: {})", pin.len());
            let mut buffer = self.pin_buffer.lock().unwrap();
            *buffer = pin;
            return Ok(());
        }
        info!("SampleCredential::SetStringValue - 字段 {} 不支持文本输入", dwfieldid);
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

    /// 命令链接被点击（未实现）
    fn CommandLinkClicked(&self, _dwfieldid: u32) -> windows_core::Result<()> {
        info!("SampleCredential::CommandLinkClicked - 未实现的接口");
        Err(E_NOTIMPL.into())
    }

    /// 序列化凭据信息（登录时调用）
    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        // ── Hello PIN 路径 ──────────────────────────────────────────────
        // 用户输入了 PIN 并点击提交 → 发送到 Unlock EXE 进行 NGC 解密
        let pin_to_send = {
            let mut pin_buf = self.pin_buffer.lock().unwrap();
            if pin_buf.is_empty() {
                None
            } else {
                let pin = std::mem::take(&mut *pin_buf);
                Some(pin)
            }
        };

        if let Some(pin) = pin_to_send {
            info!("SampleCredential::GetSerialization - Hello PIN 模式，开始 NGC 解密");

            // 获取当前用户名，传给 Unlock EXE 进行 SID 查找
            let username = match get_current_username() {
                Some(u) => u,
                None => {
                    error!("SampleCredential::GetSerialization - 无法获取用户名");
                    unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
                    return Ok(());
                }
            };

            // 发送 PIN 和用户名到 Unlock EXE 进行 NGC 解密
            // Unlock (SYSTEM) 会根据用户名查找 SID 并执行解密链
            match crate::Pipe::send_pin_to_unlock(&username, &pin, 15_000) {
                Ok(true) => {
                    // PIN 正确 — Unlock 端已设置 matched_creds，
                    // Creds 线程将收到凭据 → CredentialsChanged → autologon
                    info!("SampleCredential::GetSerialization - PIN NGC 解密成功，等待 autologon");
                    unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED; }
                    return Ok(());
                }
                Ok(false) => {
                    // PIN 错误
                    warn!("SampleCredential::GetSerialization - PIN NGC 解密失败（密码错误）");
                    unsafe {
                        if !_ppszoptionalstatustext.is_null() {
                            let msg = "PIN 错误，请重试";
                            let wide: Vec<u16> = msg.encode_utf16().chain(Some(0)).collect();
                            let ptr = CoTaskMemAlloc(wide.len() * 2) as *mut u16;
                            if !ptr.is_null() {
                                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                                *_ppszoptionalstatustext = PWSTR(ptr);
                            }
                        }
                        if !_pcpsioptionalstatusicon.is_null() {
                            *_pcpsioptionalstatusicon = CPSI_ERROR;
                        }
                        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
                    }
                    return Ok(());
                }
                Err(e) => {
                    error!("SampleCredential::GetSerialization - PIN 管道通信失败: {}", e);
                    unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
                    return Ok(());
                }
            }
        }

        // ── 面容识别路径（原有逻辑）──────────────────────────────────
        let creds = self.shared_creds.lock().unwrap();

        if !creds.is_ready {
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED; }
            return Ok(());
        }

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

        let user_wide = to_wide_vec(&qualified_user);
        let pwd_wide  = to_wide_vec(&creds.password);

        // 第一次调用：查询所需缓冲区大小（预期返回 ERROR_INSUFFICIENT_BUFFER）
        let mut cb_packed = 0u32;
        unsafe {
            let _ = CredPackAuthenticationBufferW(
                CRED_PACK_PROTECTED_CREDENTIALS,
                PCWSTR::from_raw(user_wide.as_ptr()),
                PCWSTR::from_raw(pwd_wide.as_ptr()),
                None,
                &mut cb_packed,
            );
        }

        if cb_packed == 0 {
            error!("SampleCredential::GetSerialization - 无法获取缓冲区大小");
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
            // 凭据打包失败，重置标志防止死循环
            drop(creds);
            self.shared_creds.lock().unwrap().is_unlocked = false;
            return Ok(());
        }

        // 分配输出缓冲区（Windows 负责释放）
        let buf = unsafe { CoTaskMemAlloc(cb_packed as usize) as *mut u8 };
        if buf.is_null() {
            error!("SampleCredential::GetSerialization - 内存分配失败");
            unsafe { *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED; }
            drop(creds);
            self.shared_creds.lock().unwrap().is_unlocked = false;
            return Ok(());
        }

        // 第二次调用：实际打包凭据
        let pack_result = unsafe {
            CredPackAuthenticationBufferW(
                CRED_PACK_PROTECTED_CREDENTIALS,
                PCWSTR::from_raw(user_wide.as_ptr()),
                PCWSTR::from_raw(pwd_wide.as_ptr()),
                Some(buf),
                &mut cb_packed,
            )
        };

        if let Err(e) = pack_result {
            error!("SampleCredential::GetSerialization - CredPackAuthenticationBufferW 失败: {:?}", e);
            unsafe {
                CoTaskMemFree(Some(buf as *mut _));
                *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
            }
            drop(creds);
            self.shared_creds.lock().unwrap().is_unlocked = false;
            return Ok(());
        }

        // 凭据打包成功，重置 is_unlocked 标志（#112 修复：延迟重置防止 UAC 竞态）
        drop(creds);
        {
            let mut s = self.shared_creds.lock().unwrap();
            s.is_unlocked = false;
        }

        unsafe {
            (*pcpcs).ulAuthenticationPackage = self.auth_package_id;
            (*pcpcs).cbSerialization         = cb_packed;
            (*pcpcs).rgbSerialization        = buf;
            (*pcpcs).clsidCredentialProvider = CLSID_SampleProvider;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }

        info!("SampleCredential::GetSerialization - 凭据序列化完成，用户: {}", qualified_user);
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
            creds.username.clear();
            creds.password.clear();
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

/// 获取当前登录用户的 SID 字符串
///
/// 使用 GetUserNameW → LookupAccountNameW 获取 SID，
/// 再用 ConvertSidToStringSidW 转换为字符串。
/// 获取当前登录用户名
///
/// 由于 windows-rs 0.59 中 ConvertSidToStringSidW 可能不可用，
/// 我们通过 GetUserNameW 获取用户名，然后将用户名传给 Unlock EXE，
/// 由 SYSTEM 权限的 Unlock 进程查找 SID。
fn get_current_username() -> Option<String> {
    use windows::Win32::System::WindowsProgramming::GetUserNameW;
    use windows_core::PWSTR;

    unsafe {
        let mut name_len = 0u32;
        let _ = GetUserNameW(None, &mut name_len);
        if name_len == 0 {
            return None;
        }
        let mut name_buf: Vec<u16> = vec![0u16; name_len as usize];
        if GetUserNameW(Some(PWSTR(name_buf.as_mut_ptr())), &mut name_len).is_err() {
            return None;
        }
        let username = String::from_utf16_lossy(&name_buf[..name_len as usize - 1]);
        if username.is_empty() {
            None
        } else {
            Some(username)
        }
    }
}
