/// Broker 凭据弹窗场景检测
///
/// 当凭据提供程序 DLL 运行在 credentialuibroker.exe 中时，同一宿主进程同时托管：
/// - 浏览器「查看密码」（应允许面容识别）
/// - Google/passkey WebAuthn「通行密钥」（应直接走 PIN）
///
/// 二者窗口标题相同（"Windows 安全中心"）、窗口类名相同（"Credential Dialog Xaml Host"），
/// dwflags/auth package/CLSID/rgbSerialization 完全一致，唯一可用判据是 **弹窗大标题文本**：
///
/// - passkey → 含「密钥/通行密钥/passkey」，无「密码」
/// - 查看密码 → 含「密码/password」，无「密钥」
///
/// 本模块通过 raw COM UI Automation 读取 XAML 弹窗文字，返回场景分类。
///
/// 安全策略：检测失败或不确定时一律返回 Passkey（回退 PIN），
/// 确保 passkey 永不被面容劫持。最坏情况只是查看密码也变 PIN。

use std::ffi::c_void;

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetForegroundWindow};
use windows_core::{GUID, HRESULT, PCWSTR, IUnknown, Interface};

// ── UIA COM CLSID/IID ──────────────────────────────────────────
const CLSID_CUIAUTOMATION: GUID = GUID::from_u128(0xff48dbaf_60ef_4201_aa87_54103eef594e);
const IID_IUIAUTOMATION: GUID = GUID::from_u128(0x30cbe57d_d9d0_452a_ab13_7ac5ac4825ee);

// ── UIA TreeScope ─────────────────────────────────────────────
const TREE_SCOPE_DESCENDANTS: u32 = 0x4;

// ── 关键词检测 ──────────────────────────────────────────────────

/// 命中任一关键词 → 判定为 passkey 场景（跳过面容，直接 PIN）
const PASSKEY_KEYWORDS: &[&str] = &[
    "密钥", "通行密钥", "passkey", "安全密钥", "security key", "webauthn",
];

/// 命中任一关键词 → 判定为密码场景（允许面容识别）
const PASSWORD_KEYWORDS: &[&str] = &[
    "密码", "password", "正在尝试显示密码", "credentials",
];

/// 弹窗文本最短长度（过滤短字符串噪音）
const MIN_TEXT_LEN: usize = 3;

/// 查找弹窗的最大重试次数和间隔
const FIND_DIALOG_MAX_RETRIES: u32 = 10;
const FIND_DIALOG_RETRY_MS: u64 = 150;

// ── 场景分类枚举 ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BrokerScenario {
    /// Passkey/WebAuthn — 跳过面容，直接回退 Windows PIN
    Passkey,
    /// 查看密码 — 允许面容识别
    Password,
    /// 无法判断 — 安全兜底：回退 PIN
    Unknown,
}

impl BrokerScenario {
    /// 是否应该跳过面容识别
    pub fn should_skip_face(&self) -> bool {
        match self {
            Self::Passkey | Self::Unknown => true,
            Self::Password => false,
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// Raw COM vtable 定义
//
// 命名约定：_padN 中的 N = vtable 索引（0-based）
// IUnknown 占 0-2，COM 接口自有方法从索引 3 开始
// ══════════════════════════════════════════════════════════════════

type VtblSlot = *const c_void;

/// IUIAutomation vtable（精简版：仅含我们调用的方法 + padding）
///
/// 方法顺序来自 UIAutomationClient.h：
/// IUnknown(0-2) → CompareElements(3) → ... → CreateTrueCondition(20) → ...
#[repr(C)]
struct IUIAutomationVtbl {
    // IUnknown
    query_interface: unsafe extern "system" fn(
        *mut c_void, *const GUID, *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    // IUIAutomation
    _pad3: VtblSlot,                           //  3: CompareElements
    _pad4: VtblSlot,                           //  4: GetRootElement
    // 5: ElementFromHandle
    element_from_handle: unsafe extern "system" fn(
        this: *mut c_void,
        hwnd: isize,
        element: *mut *mut c_void,
    ) -> HRESULT,
    _pad6: VtblSlot,                           //  6: ElementFromPoint
    _pad7: VtblSlot,                           //  7: GetFocusedElement
    _pad8: VtblSlot,                           //  8: GetRootElementBuildCache
    _pad9: VtblSlot,                           //  9: ElementFromHandleBuildCache
    _pad10: VtblSlot,                          // 10: ElementFromPointBuildCache
    _pad11: VtblSlot,                          // 11: GetFocusedElementBuildCache
    _pad12: VtblSlot,                          // 12: CreateTreeWalker
    _pad13: VtblSlot,                          // 13: get_ControlViewWalker
    _pad14: VtblSlot,                          // 14: get_ContentViewWalker
    _pad15: VtblSlot,                          // 15: get_RawViewWalker
    _pad16: VtblSlot,                          // 16: get_RawViewCondition
    _pad17: VtblSlot,                          // 17: get_ControlViewCondition
    _pad18: VtblSlot,                          // 18: get_ContentViewCondition
    _pad19: VtblSlot,                          // 19: CreateCacheRequest
    // 20: CreateTrueCondition
    create_true_condition: unsafe extern "system" fn(
        this: *mut c_void,
        new_condition: *mut *mut c_void,
    ) -> HRESULT,
    _pad21: VtblSlot,                          // 21: CreateFalseCondition
    _pad22: VtblSlot,                          // 22: CreatePropertyCondition
}

/// IUIAutomationElement vtable（精简版）
///
/// 我们只需要 FindAll (idx 6)、get_CurrentName (idx 39)。
/// 其他 ~100 个方法用 VtblSlot 填充。
#[repr(C)]
struct IUIAutomationElementVtbl {
    // IUnknown
    query_interface: unsafe extern "system" fn(
        *mut c_void, *const GUID, *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    // IUIAutomationElement
    _pad3: VtblSlot,                           //  3: SetFocus
    _pad4: VtblSlot,                           //  4: GetRuntimeId
    _pad5: VtblSlot,                           //  5: FindFirst
    // 6: FindAll
    find_all: unsafe extern "system" fn(
        this: *mut c_void,
        scope: u32,             // TreeScope
        condition: *mut c_void,  // IUIAutomationCondition*
        found: *mut *mut c_void, // IUIAutomationElementArray**
    ) -> HRESULT,
    _pad7: VtblSlot,                           //  7: FindFirstBuildCache
    _pad8: VtblSlot,                           //  8: FindAllBuildCache
    _pad9: VtblSlot,                           //  9: BuildUpdatedCache
    _pad10: VtblSlot,                          // 10: get_CurrentAcceleratorKey
    _pad11: VtblSlot,                          // 11: get_CurrentAccessKey
    _pad12: VtblSlot,                          // 12: get_CurrentAriaProperties
    _pad13: VtblSlot,                          // 13: get_CurrentAriaRole
    _pad14: VtblSlot,                          // 14: get_CurrentAutomationId
    _pad15: VtblSlot,                          // 15: get_CurrentBoundingRectangle
    _pad16: VtblSlot,                          // 16: get_CurrentClassName
    _pad17: VtblSlot,                          // 17: get_CurrentClickablePoint
    _pad18: VtblSlot,                          // 18: get_CurrentControllerFor
    _pad19: VtblSlot,                          // 19: get_CurrentControlType
    _pad20: VtblSlot,                          // 20: get_CurrentCulture
    _pad21: VtblSlot,                          // 21: get_CurrentDescribedBy
    _pad22: VtblSlot,                          // 22: get_CurrentFlowsFrom
    _pad23: VtblSlot,                          // 23: get_CurrentFlowsTo
    _pad24: VtblSlot,                          // 24: get_CurrentFrameworkId
    _pad25: VtblSlot,                          // 25: get_CurrentHasKeyboardFocus
    _pad26: VtblSlot,                          // 26: get_CurrentHelpText
    _pad27: VtblSlot,                          // 27: get_CurrentIsContentElement
    _pad28: VtblSlot,                          // 28: get_CurrentIsControlElement
    _pad29: VtblSlot,                          // 29: get_CurrentIsDataValidForForm
    _pad30: VtblSlot,                          // 30: get_CurrentIsEnabled
    _pad31: VtblSlot,                          // 31: get_CurrentIsKeyboardFocusable
    _pad32: VtblSlot,                          // 32: get_CurrentIsOffscreen
    _pad33: VtblSlot,                          // 33: get_CurrentIsPassword
    _pad34: VtblSlot,                          // 34: get_CurrentIsRequiredForForm
    _pad35: VtblSlot,                          // 35: get_CurrentItemStatus
    _pad36: VtblSlot,                          // 36: get_CurrentItemType
    _pad37: VtblSlot,                          // 37: get_CurrentLabeledBy
    _pad38: VtblSlot,                          // 38: get_CurrentLocalizedControlType
    // 39: get_CurrentName — 获取元素的可访问名称（文本内容）
    get_current_name: unsafe extern "system" fn(
        this: *mut c_void,
        ret_val: *mut *mut u16,  // BSTR* → raw *mut u16
    ) -> HRESULT,
    _pad40: VtblSlot,                          // 40: get_CurrentNativeWindowHandle
    _pad41: VtblSlot,                          // 41: get_CurrentOrientation
    _pad42: VtblSlot,                          // 42: get_CurrentProcessId
    _pad43: VtblSlot,                          // 43: get_CurrentProviderDescription
    _pad44: VtblSlot,                          // 44: GetCachedParent
}

/// IUIAutomationElementArray vtable
#[repr(C)]
struct IUIAutomationElementArrayVtbl {
    query_interface: unsafe extern "system" fn(
        *mut c_void, *const GUID, *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    // 3: get_Length
    get_length: unsafe extern "system" fn(
        this: *mut c_void,
        length: *mut i32,
    ) -> HRESULT,
    // 4: GetElement
    get_element: unsafe extern "system" fn(
        this: *mut c_void,
        index: i32,
        element: *mut *mut c_void,
    ) -> HRESULT,
}

/// IUIAutomationCondition — 无自有方法，仅引用计数
#[repr(C)]
struct GenericVtbl {
    query_interface: unsafe extern "system" fn(
        *mut c_void, *const GUID, *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

// ══════════════════════════════════════════════════════════════════
// COM 对象 RAII 句柄
// ══════════════════════════════════════════════════════════════════

struct UIAutomationHandle(*mut c_void);
struct UIElementHandle(*mut c_void);
struct UIConditionHandle(*mut c_void);

impl Drop for UIAutomationHandle {
    fn drop(&mut self) { unsafe { com_release(self.0); } }
}
impl Drop for UIElementHandle {
    fn drop(&mut self) { unsafe { com_release(self.0); } }
}
impl Drop for UIConditionHandle {
    fn drop(&mut self) { unsafe { com_release(self.0); } }
}

unsafe fn com_release(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let vtbl = &**(ptr as *const *const GenericVtbl);
            (vtbl.release)(ptr);
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// BSTR 读取辅助（不使用 windows BSTR 类型，手动解析 raw BSTR）
// ══════════════════════════════════════════════════════════════════

/// 从 raw BSTR 指针读取 UTF-16 字符串
///
/// BSTR 内存布局（稳定，自 Windows 95 起未变）:
///   [-4 bytes: byte length][UTF-16 wchar data][null wchar terminator]
///
/// `raw_bstr` 指向 wchar data 起始处
unsafe fn read_raw_bstr(raw_bstr: *mut u16) -> Option<String> {
    if raw_bstr.is_null() {
        return None;
    }
    unsafe {
        // BSTR 长度前缀（字节数，不含 null terminator）
        let byte_len = *((raw_bstr as *const u32).offset(-1)) as usize;
        if byte_len == 0 {
            return None;
        }
        let char_len = byte_len / 2;
        let slice = std::slice::from_raw_parts(raw_bstr as *const u16, char_len);
        Some(String::from_utf16_lossy(slice))
    }
}

// ══════════════════════════════════════════════════════════════════
// UIA 检测主逻辑
// ══════════════════════════════════════════════════════════════════

/// 检测 broker CredUI 弹窗场景类型
///
/// # 安全兜底
/// 任何检测失败都返回 Unknown → should_skip_face() == true → 回退 PIN
pub fn detect_broker_scenario() -> BrokerScenario {
    match detect_broker_scenario_internal() {
        Ok(scenario) => scenario,
        Err(e) => {
            warn!("broker_detect: 检测失败，回退 PIN: {}", e);
            BrokerScenario::Unknown
        }
    }
}

fn detect_broker_scenario_internal() -> Result<BrokerScenario, String> {
    // 确保当前线程 COM 已初始化（可能已被宿主进程初始化，忽略错误）
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok(); }

    // 1. 查找凭据弹窗 HWND（带重试）
    let hwnd = find_credential_dialog_hwnd().ok_or("找不到凭据弹窗")?;
    info!("broker_detect: 找到凭据弹窗 HWND: {:?}", hwnd);

    // 2. 创建 CUIAutomation 实例
    let uia = create_uiautomation().ok_or("创建 CUIAutomation 失败")?;

    // 3. 获取弹窗对应的 UIA Element
    let dialog_element = element_from_handle(&uia, hwnd).ok_or("ElementFromHandle 失败")?;

    // 4. 读取弹窗中所有可见文字
    let all_texts = collect_all_texts(&uia, &dialog_element)
        .map_err(|e| format!("collect_all_texts: {e}"))?;

    // 5. 关键词检测
    let scenario = classify_texts(&all_texts);
    info!(
        "broker_detect: 收集到 {} 段文本 → 分类: {:?}",
        all_texts.len(),
        scenario
    );

    // 6. 诊断日志
    for (i, t) in all_texts.iter().enumerate() {
        info!("broker_detect:   [{}] {:?}", i, t);
    }

    Ok(scenario)
}

// ── 第 1 步：查找凭据弹窗 HWND ──

fn find_credential_dialog_hwnd() -> Option<HWND> {
    let class_name = to_utf16_null("Credential Dialog Xaml Host");
    for attempt in 0..FIND_DIALOG_MAX_RETRIES {
        // FindWindowW returns Result<HWND, Error> in windows 0.59
        match unsafe { FindWindowW(PCWSTR(class_name.as_ptr()), None) } {
            Ok(hwnd) if hwnd.0 != std::ptr::null_mut() => {
                return Some(hwnd);
            }
            _ => {
                if attempt == 0 {
                    let fg = unsafe { GetForegroundWindow() };
                    if fg.0 != std::ptr::null_mut() {
                        info!(
                            "broker_detect: FindWindow 未找到凭据弹窗，回退使用前台窗口: {:?}",
                            fg
                        );
                        return Some(fg);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(FIND_DIALOG_RETRY_MS));
    }
    warn!("broker_detect: 重试后仍未找到凭据弹窗");
    None
}

// ── 第 2 步：创建 CUIAutomation ──

fn create_uiautomation() -> Option<UIAutomationHandle> {
    // CoCreateInstance<P, T> 在 windows 0.59 中返回 Result<T>
    // 先创建为 IUnknown，再 QueryInterface 获取 IUIAutomation
    let unk: IUnknown = match unsafe {
        CoCreateInstance(&CLSID_CUIAUTOMATION, None, CLSCTX_INPROC_SERVER)
    } {
        Ok(u) => u,
        Err(e) => {
            warn!("broker_detect: CoCreateInstance 失败: {:?}", e);
            return None;
        }
    };

    let mut uia_ptr: *mut c_void = std::ptr::null_mut();
    let hr = unsafe { unk.query(&IID_IUIAUTOMATION, &mut uia_ptr) };
    if hr.is_ok() && !uia_ptr.is_null() {
        Some(UIAutomationHandle(uia_ptr))
    } else {
        warn!("broker_detect: QueryInterface(IUIAutomation) 失败: {:?}", hr);
        None
    }
    // unk 的 Drop 会 Release，使 refcount 保持平衡
}

// ── 第 3 步：ElementFromHandle ──

fn element_from_handle(uia: &UIAutomationHandle, hwnd: HWND) -> Option<UIElementHandle> {
    let mut elem: *mut c_void = std::ptr::null_mut();
    // SAFETY: IUIAutomation vtable index 5 → ElementFromHandle
    let vtbl = unsafe { &**(uia.0 as *const *const IUIAutomationVtbl) };
    let hr = unsafe { (vtbl.element_from_handle)(uia.0, hwnd.0 as isize, &mut elem) };
    if hr.is_err() || elem.is_null() {
        warn!("broker_detect: ElementFromHandle 失败: {:?}", hr);
        None
    } else {
        Some(UIElementHandle(elem))
    }
}

// ── 第 4 步：收集所有文本 ──

fn collect_all_texts(
    uia: &UIAutomationHandle,
    element: &UIElementHandle,
) -> Result<Vec<String>, String> {
    let condition = create_true_condition(uia).ok_or("CreateTrueCondition 失败")?;
    let elements = find_all_descendants(element, &condition, 300)
        .map_err(|e| format!("find_all_descendants: {e}"))?;

    let mut texts = Vec::with_capacity(32);
    for child in &elements {
        if let Some(name) = get_element_name(child) {
            let trimmed = name.trim().to_string();
            // 过滤短字符串和纯标点符号
            if trimmed.len() >= MIN_TEXT_LEN
                && !trimmed.chars().all(|c| c.is_ascii_punctuation() || c == ' ')
            {
                texts.push(trimmed);
            }
        }
    }

    for child in elements {
        unsafe { com_release(child.0); }
    }
    Ok(texts)
}

fn create_true_condition(uia: &UIAutomationHandle) -> Option<UIConditionHandle> {
    let mut cond: *mut c_void = std::ptr::null_mut();
    let vtbl = unsafe { &**(uia.0 as *const *const IUIAutomationVtbl) };
    let hr = unsafe { (vtbl.create_true_condition)(uia.0, &mut cond) };
    if hr.is_err() || cond.is_null() {
        warn!("broker_detect: CreateTrueCondition 失败: {:?}", hr);
        None
    } else {
        Some(UIConditionHandle(cond))
    }
}

fn find_all_descendants(
    element: &UIElementHandle,
    condition: &UIConditionHandle,
    max_count: i32,
) -> Result<Vec<UIElementHandle>, String> {
    let mut array: *mut c_void = std::ptr::null_mut();
    let vtbl = unsafe { &**(element.0 as *const *const IUIAutomationElementVtbl) };
    let hr = unsafe {
        (vtbl.find_all)(element.0, TREE_SCOPE_DESCENDANTS, condition.0, &mut array)
    };
    if hr.is_err() || array.is_null() {
        return Err(format!("FindAll HRESULT: {:?}", hr));
    }

    let arr_vtbl =
        unsafe { &**(array as *const *const IUIAutomationElementArrayVtbl) };

    let mut len: i32 = 0;
    let hr = unsafe { (arr_vtbl.get_length)(array, &mut len) };
    if hr.is_err() {
        unsafe { com_release(array); }
        return Err(format!("get_Length 失败: {:?}", hr));
    }

    let count = len.min(max_count);
    let mut elements = Vec::with_capacity(count as usize);

    for i in 0..count {
        let mut elem: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { (arr_vtbl.get_element)(array, i, &mut elem) };
        if hr.is_ok() && !elem.is_null() {
            elements.push(UIElementHandle(elem));
        }
    }

    unsafe { com_release(array); }
    Ok(elements)
}

fn get_element_name(element: &UIElementHandle) -> Option<String> {
    let mut raw_bstr: *mut u16 = std::ptr::null_mut();
    let vtbl = unsafe { &**(element.0 as *const *const IUIAutomationElementVtbl) };
    let hr = unsafe { (vtbl.get_current_name)(element.0, &mut raw_bstr) };
    if hr.is_ok() && !raw_bstr.is_null() {
        unsafe { read_raw_bstr(raw_bstr) }
    } else {
        None
    }
}

// ── 第 5 步：关键词分类 ──

fn classify_texts(texts: &[String]) -> BrokerScenario {
    let joined = texts.join(" ");
    let joined_lower = joined.to_lowercase();

    let has_passkey = PASSKEY_KEYWORDS
        .iter()
        .any(|kw| joined_lower.contains(&kw.to_lowercase()));
    let has_password = PASSWORD_KEYWORDS
        .iter()
        .any(|kw| joined_lower.contains(&kw.to_lowercase()));

    match (has_passkey, has_password) {
        (true, false) => BrokerScenario::Passkey,
        (false, true) => BrokerScenario::Password,
        (true, true) => {
            warn!("broker_detect: 同时命中 passkey 和 password 关键词，保守判定为 Passkey");
            BrokerScenario::Passkey
        }
        (false, false) => {
            info!(
                "broker_detect: 未检测到关键词（首段文本: {:?}），保守判定为 Unknown → PIN 回退",
                texts.first().unwrap_or(&String::new())
            );
            BrokerScenario::Unknown
        }
    }
}

fn to_utf16_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ══════════════════════════════════════════════════════════════════
// 单元测试
// ══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_passkey() {
        let texts = vec![
            "Windows 安全中心".to_string(),
            "使用密钥登录".to_string(),
            "google.com 的通行密钥".to_string(),
        ];
        assert_eq!(classify_texts(&texts), BrokerScenario::Passkey);
    }

    #[test]
    fn test_classify_password() {
        let texts = vec![
            "Windows 安全中心".to_string(),
            "确保那是你".to_string(),
            "Google Chrome 正在尝试显示密码".to_string(),
            "Windows密码".to_string(),
        ];
        assert_eq!(classify_texts(&texts), BrokerScenario::Password);
    }

    #[test]
    fn test_classify_unknown() {
        let texts = vec!["Windows 安全中心".to_string(), "登录".to_string()];
        assert_eq!(classify_texts(&texts), BrokerScenario::Unknown);
    }

    #[test]
    fn test_classify_both_keywords() {
        let texts = vec!["使用密码和密钥登录".to_string()];
        assert_eq!(classify_texts(&texts), BrokerScenario::Passkey);
    }

    #[test]
    fn test_classify_passkey_english() {
        let texts = vec![
            "Windows Security".to_string(),
            "Use passkey to sign in".to_string(),
            "security key".to_string(),
        ];
        assert_eq!(classify_texts(&texts), BrokerScenario::Passkey);
    }

    #[test]
    fn test_classify_password_english() {
        let texts = vec![
            "Windows Security".to_string(),
            "Chrome is trying to show passwords".to_string(),
        ];
        assert_eq!(classify_texts(&texts), BrokerScenario::Password);
    }

    #[test]
    fn test_should_skip_face() {
        assert!(BrokerScenario::Passkey.should_skip_face());
        assert!(BrokerScenario::Unknown.should_skip_face());
        assert!(!BrokerScenario::Password.should_skip_face());
    }
}
