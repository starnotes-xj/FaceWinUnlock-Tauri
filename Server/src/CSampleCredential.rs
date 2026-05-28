// 引入必要的同步原语和Win32 API
use std::sync::{Arc, Mutex};
use windows::Win32::{
    Foundation::{E_NOTIMPL, STATUS_SUCCESS},
    Graphics::Gdi::HBITMAP,
    Security::Credentials::{CredPackAuthenticationBufferW, CRED_PACK_PROTECTED_CREDENTIALS},
    System::Com::{CoTaskMemAlloc, CoTaskMemFree},
    UI::Shell::{
        ICredentialProviderCredential, ICredentialProviderCredentialEvents,
        ICredentialProviderCredential_Impl, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH,
        CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_NO_CREDENTIAL_FINISHED,
        CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        CREDENTIAL_PROVIDER_STATUS_ICON
    }
};
use windows_core::{implement, PCWSTR, PWSTR};
use windows::Win32::Foundation::BOOL;
use crate::animation::{AnimationContext, AnimationSlot};
use crate::{CLSID_SampleProvider, SharedCredentials};

/// 凭据实现类，代表登录界面上的一个磁贴
/// 每个凭据对应一个可选择的登录选项
#[implement(ICredentialProviderCredential)]
pub struct SampleCredential {
    // 用于接收系统事件通知的接口（互斥锁保护线程安全）
    events: Mutex<Option<ICredentialProviderCredentialEvents>>,
    shared_creds: Arc<Mutex<SharedCredentials>>,
    auth_package_id: u32,
    /// 动画 UI 上下文（阶段 A）。Advise 时在 LogonUI 进程内创建子窗口+DComp 管线，
    /// UnAdvise 时释放。失败不影响登录功能。
    animation: AnimationSlot,
}

impl SampleCredential {
    /// 创建新的凭据实例
    pub fn new(shared_creds: Arc<Mutex<SharedCredentials>>, auth_package_id: u32, animation: AnimationSlot) -> Self {
        info!("SampleCredential::new - 创建凭据实例");
        Self {
            events: Mutex::new(None),
            shared_creds,
            auth_package_id,
            animation,
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

        // ── 动画 UI 管线（路径 C：DComp topmost + 磁贴定位）──────
        // 绑定 DComp 到 LogonUI 父窗口（topmost=true），通过
        // EnumChildWindows 定位凭据磁贴，在头像区叠加 60 FPS GPU 动画。
        if let Some(ev) = events.as_ref() {
            if is_animation_enabled() {
                match unsafe { ev.OnCreatingWindow() } {
                    Ok(parent_hwnd) => {
                        info!("SampleCredential::Advise - LogonUI 父 HWND: {:?}", parent_hwnd);
                        // 用磁贴文本片段定位（容错：EnumChildWindows 找不到时回退到默认位置）
                        match AnimationContext::new(parent_hwnd, "FaceWinUnlock") {
                            Ok(ctx) => {
                                info!("SampleCredential::Advise - 动画渲染线程已启动（路径 C：topmost 叠加）");
                                *self.animation.lock().unwrap() = Some(ctx);
                            }
                            Err(e) => {
                                warn!("SampleCredential::Advise - AnimationContext 失败: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("SampleCredential::Advise - OnCreatingWindow 失败: {:?}", e);
                    }
                }
            } else {
                info!("SampleCredential::Advise - ANIMATION_UI_ENABLED=0，跳过");
            }
        }

        Ok(())
    }

    /// 取消事件通知
    fn UnAdvise(&self) -> windows_core::Result<()> {
        info!("SampleCredential::UnAdvise - 取消事件通知");

        // 先释放动画上下文（销毁子窗口、Release COM 对象）
        // 必须在 events 清空前完成，避免 DComp Commit 时 LogonUI 已经卸载
        {
            let mut animation = self.animation.lock().unwrap();
            if animation.is_some() {
                info!("SampleCredential::UnAdvise - 释放动画 UI 资源");
                *animation = None; // 触发 AnimationContext 的 Drop
            }
        }

        let mut events = self.events.lock().unwrap();
        *events = None; // 清除事件接口
        Ok(())
    }

    /// 当凭据磁贴被选中时调用
    fn SetSelected(&self) -> windows_core::Result<BOOL> {
        info!("SampleCredential::SetSelected - 磁贴被选中");
        Ok(true.into()) // 返回true表示处理成功
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

    /// 获取提交按钮字段的值（未实现）
    fn GetSubmitButtonValue(&self, _dwfieldid: u32) -> windows_core::Result<u32> {
        info!("SampleCredential::GetSubmitButtonValue - 未实现的接口");
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
        info!("SampleCredential::SetStringValue - 未实现的接口");
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
        {
            let mut creds = self.shared_creds.lock().unwrap();
            creds.username.clear();
            creds.password.clear();
            creds.is_ready = false;
            creds.is_unlocked = false;
        }

        unsafe {
            if !ppszoptionalstatustext.is_null() {
                let msg = "用户名或密码错误，请检查设置";
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
        Ok(())
    }
}

// 将 String 转换为符合 Win32 要求的 UTF-16 向量（带 null 结尾）
fn to_wide_vec(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A9：动画 UI 灰度开关 — 注册表 ANIMATION_UI_ENABLED == "1" 才启用
/// 默认 "0"（不启用），保护开发期 LogonUI 不被未稳定的动画管线影响。
fn is_animation_enabled() -> bool {
    crate::read_facewinunlock_registry("ANIMATION_UI_ENABLED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
