//! UI Automation 对话框探测器 + 自动填充
//!
//! 现代 Win11 上，第三方无法 headless 把 PIN 注入 KSP（SmartcardPin 被忽略、
//! FIDO 密钥 NCrypt 不可签、KSP 坚持弹原生框）。因此改走「UIA 自动填充原生
//! Windows Hello PIN 框」——参照 joseangelmt/AutoInsertPin。
//!
//! # 2026.1 安全加固 (CVE-2026-20824)
//! 凭据对话框仅接受「可信本地输入」：物理键盘 / UIAccess 辅助应用 /
//! **以提升(管理员)完整性运行的应用**。因此本组件必须以管理员或 SYSTEM
//! 完整性、在用户交互会话内运行，否则输入会被系统忽略。
//!
//! # 模块入口
//! 1. `dump_all_windows` — 用 EnumWindows 枚举所有顶层窗口并 dump UIA 树（诊断）
//! 2. `dump_credential_dialogs` — 用 EnumWindows 找凭据/PIN 对话框（增强版）
//! 3. `autofill_pin` — 定位 PIN 框，填入 PIN 并提交（实际功能）

use windows_core::Interface;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationValuePattern,
    IUIAutomationInvokePattern, IUIAutomationTreeWalker,
    UIA_ValuePatternId, UIA_InvokePatternId,
};
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, GetWindowTextW, GetWindow, GetForegroundWindow,
    GW_OWNER, GW_ENABLEDPOPUP,
};

use std::sync::Mutex;

/// 把 UIA ControlType ID 映射为可读名
fn control_type_name(id: i32) -> &'static str {
    match id {
        50000 => "Button",      50001 => "Calendar",    50002 => "CheckBox",
        50003 => "ComboBox",    50004 => "Edit",        50005 => "Hyperlink",
        50006 => "Image",       50007 => "ListItem",    50008 => "List",
        50009 => "Menu",        50010 => "MenuBar",     50011 => "MenuItem",
        50012 => "ProgressBar", 50013 => "RadioButton", 50014 => "ScrollBar",
        50015 => "Slider",      50016 => "Spinner",     50017 => "StatusBar",
        50018 => "Tab",         50019 => "TabItem",     50020 => "Text",
        50021 => "ToolBar",     50022 => "ToolTip",     50023 => "Tree",
        50024 => "TreeItem",    50025 => "Custom",      50026 => "Group",
        50027 => "Thumb",       50028 => "DataGrid",    50029 => "DataItem",
        50030 => "Document",    50031 => "SplitButton", 50032 => "Window",
        50033 => "Pane",        50034 => "Header",      50035 => "HeaderItem",
        50036 => "Table",       50037 => "TitleBar",    50038 => "Separator",
        _ => "?",
    }
}

/// 通过 PID 取进程 exe 名（小写，失败返回空串）
fn process_name(pid: u32) -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_core::PWSTR;
    if pid == 0 { return String::new(); }
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return String::new(),
        };
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h, PROCESS_NAME_FORMAT(0),
            PWSTR::from_raw(buf.as_mut_ptr()), &mut size,
        );
        let _ = CloseHandle(h);
        if ok.is_err() { return String::new(); }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        path.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase()
    }
}

/// 获取窗口标题
fn window_title(hwnd: HWND) -> String {
    unsafe {
        let mut buf = vec![0u16; 512];
        let len = GetWindowTextW(hwnd, &mut buf);
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

fn bstr_of<F>(f: F) -> String
where F: FnOnce() -> windows_core::Result<windows_core::BSTR>,
{
    f().map(|b| b.to_string()).unwrap_or_default()
}

/// 判断一个顶层窗口是否是「凭据/PIN」对话框
fn is_credential_window(name: &str, exe: &str) -> bool {
    let exe_hit = matches!(
        exe,
        "credentialuibroker.exe" | "consent.exe" | "logonui.exe"
        | "credwiz.exe" | "pickerhost.exe" | "systemsettings.exe"
    );
    let lname = name.to_lowercase();
    let name_hit = name.contains("Windows Security")
        || name.contains("Windows 安全")
        || name.contains("安全")
        || lname.contains("pin")
        || name.contains("Hello")
        || name.contains("Windows 安全中心")
        || name.contains("Credential")
        || name.contains("登录")
        || name.contains("密码");
    exe_hit || name_hit
}

/// 递归 dump 一个 UIA 元素子树
unsafe fn dump_element(
    uia: &IUIAutomation,
    el: &IUIAutomationElement,
    depth: usize,
    log: &mut Vec<String>,
) {
    if depth > 12 { return; }
    let pad = "  ".repeat(depth);
    let name = bstr_of(|| el.CurrentName());
    let ct = el.CurrentControlType().map(|c| control_type_name(c.0)).unwrap_or("?");
    let aid = bstr_of(|| el.CurrentAutomationId());
    let cls = bstr_of(|| el.CurrentClassName());
    let val = get_value(el).unwrap_or_default();
    let is_enabled = el.CurrentIsEnabled().map(|b| b.as_bool()).unwrap_or(false);
    let is_kf = el.CurrentIsKeyboardFocusable().map(|b| b.as_bool()).unwrap_or(false);
    log.push(format!(
        "{pad}[{ct}] name='{name}' autoId='{aid}' class='{cls}' enabled={is_enabled} kbfocus={is_kf}{}",
        if val.is_empty() { String::new() } else { format!(" value='{val}'") }
    ));

    if let Ok(cond) = uia.CreateTrueCondition() {
        if let Ok(kids) = el.FindAll(
            windows::Win32::UI::Accessibility::TreeScope_Children, &cond,
        ) {
            let n = kids.Length().unwrap_or(0);
            for i in 0..n {
                if let Ok(k) = kids.GetElement(i) {
                    dump_element(uia, &k, depth + 1, log);
                }
            }
        }
    }
}

/// 取元素的 ValuePattern 当前值
unsafe fn get_value(el: &IUIAutomationElement) -> Option<String> {
    let pat = el.GetCurrentPattern(UIA_ValuePatternId).ok()?;
    let vp: IUIAutomationValuePattern = pat.cast().ok()?;
    vp.CurrentValue().ok().map(|b| b.to_string())
}

// ══════════════════════════════════════════════════════════════════════
//  Strategy 1: EnumWindows — 枚举所有顶层 HWND，逐窗口分析
// ══════════════════════════════════════════════════════════════════════

struct EnumState {
    hwnds: Mutex<Vec<(isize, u32, String)>>, // (hwnd, pid, title)
}

/// 用 EnumWindows 枚举所有顶层窗口，返回 (hwnd, pid, title) 列表
fn enum_all_top_level_windows() -> Vec<(HWND, u32, String)> {
    let state = EnumState { hwnds: Mutex::new(Vec::new()) };
    let state_ptr = &state as *const _ as isize;

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_callback),
            LPARAM(state_ptr),
        );
    }

    let mut result = Vec::new();
    for (hwnd_isize, pid, title) in state.hwnds.lock().unwrap().drain(..) {
        result.push((HWND(hwnd_isize as *mut _), pid, title));
    }
    // 按非空标题优先排序，方便阅读
    result.sort_by(|a, b| {
        let a_empty = a.2.is_empty();
        let b_empty = b.2.is_empty();
        a_empty.cmp(&b_empty).then_with(|| a.2.cmp(&b.2))
    });
    result
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &*(lparam.0 as *const EnumState);
    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    let title = window_title(hwnd);
    if let Ok(mut list) = state.hwnds.lock() {
        list.push((hwnd.0 as isize, pid, title));
    }
    BOOL(1)
}

/// GetWindow 的安全封装（windows-rs 0.59 返回 Result）
fn get_window_safe(hwnd: HWND, cmd: u32) -> Option<HWND> {
    unsafe { GetWindow(hwnd, windows::Win32::UI::WindowsAndMessaging::GET_WINDOW_CMD(cmd)).ok() }
}

// ══════════════════════════════════════════════════════════════════════
//  Public: dump_all_windows — 无差别 dump 所有顶层窗口的 UIA 信息
// ══════════════════════════════════════════════════════════════════════

/// 用 EnumWindows 枚举所有顶层窗口，对每个窗口输出其进程、标题、
/// 以及 UIA 树（如果可通过 ElementFromHandle 访问）。
/// 这是最彻底的诊断方式——不依赖窗口标题/进程名的启发式判断。
pub fn dump_all_windows() -> Vec<String> {
    let mut log = Vec::new();
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let uia: IUIAutomation = match CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) {
            Ok(u) => u,
            Err(e) => {
                log.push(format!("CoCreateInstance(CUIAutomation) 失败: {e}"));
                return log;
            }
        };

        let windows = enum_all_top_level_windows();
        log.push(format!("=== 枚举到 {} 个顶层窗口 ===\n", windows.len()));

        for (hwnd, pid, title) in &windows {
            let exe = process_name(*pid);
            let is_cred = is_credential_window(title, &exe);
            let marker = if is_cred { " ★ 疑似凭据框" } else { "" };

            log.push(format!(
                "── HWND=0x{:X} PID={} EXE={} TITLE='{}'{}",
                hwnd.0 as usize, pid, exe, title, marker
            ));

            // 对可疑窗口和可见窗口做 UIA 深度 dump
            if is_cred || (!title.is_empty() && *pid != 0) {
                if let Ok(el) = uia.ElementFromHandle(*hwnd) {
                    log.push("  UIA 子树:".to_string());
                    dump_element(&uia, &el, 1, &mut log);
                }
            }

            // 检查 owned popup 窗口
            if let Some(popup) = get_window_safe(*hwnd, GW_ENABLEDPOPUP.0) {
                if popup.0 != hwnd.0 && !popup.0.is_null() {
                    let ptitle = window_title(popup);
                    let mut ppid = 0u32;
                    GetWindowThreadProcessId(popup, Some(&mut ppid));
                    let pexe = process_name(ppid);
                    log.push(format!(
                        "  └─ Popup: HWND=0x{:X} PID={} EXE={} TITLE='{}'",
                        popup.0 as usize, ppid, pexe, ptitle
                    ));
                    if let Ok(pel) = uia.ElementFromHandle(popup) {
                        log.push("    Popup UIA 子树:".to_string());
                        dump_element(&uia, &pel, 2, &mut log);
                    }
                }
            }

            // 检查 owner 窗口
            if let Some(owner) = get_window_safe(*hwnd, GW_OWNER.0) {
                if owner.0 != hwnd.0 && !owner.0.is_null() {
                    let otitle = window_title(owner);
                    let mut opid = 0u32;
                    GetWindowThreadProcessId(owner, Some(&mut opid));
                    let oexe = process_name(opid);
                    log.push(format!(
                        "  └─ Owner: HWND=0x{:X} PID={} EXE={} TITLE='{}'",
                        owner.0 as usize, opid, oexe, otitle
                    ));
                }
            }
        }

        // 额外：检查前台窗口
        let fg = GetForegroundWindow();
        if fg.0 != std::ptr::null_mut() {
            let ftitle = window_title(fg);
            let mut fpid = 0u32;
            GetWindowThreadProcessId(fg, Some(&mut fpid));
            let fexe = process_name(fpid);
            log.push(format!(
                "\n── 前台窗口: HWND=0x{:X} PID={} EXE={} TITLE='{}'",
                fg.0 as usize, fpid, fexe, ftitle
            ));
            if let Ok(fel) = uia.ElementFromHandle(fg) {
                log.push("  前台窗口 UIA 子树:".to_string());
                dump_element(&uia, &fel, 1, &mut log);
            }
        }

        // 检查焦点元素及其祖先链
        if let Ok(focused) = uia.GetFocusedElement() {
            log.push("\n── 当前焦点元素:".to_string());
            let fname = bstr_of(|| focused.CurrentName());
            let fct = focused.CurrentControlType().map(|c| control_type_name(c.0)).unwrap_or("?");
            let faid = bstr_of(|| focused.CurrentAutomationId());
            let fcls = bstr_of(|| focused.CurrentClassName());
            let mut fpid = 0u32;
            let _ = focused.CurrentProcessId().map(|p| { fpid = p as u32; });
            let fexe = process_name(fpid);
            log.push(format!("  [{fct}] name='{fname}' autoId='{faid}' class='{fcls}' pid={fpid} exe={fexe}"));
            // dump 焦点元素的祖先链（用 TreeWalker 向上遍历）
            log.push("  焦点元素祖先链（从桌面到焦点）:".to_string());
            if let Ok(walker) = uia.ControlViewWalker() {
                dump_ancestor_chain_with_walker(&walker, &focused, &mut log);
            }
        }
    }
    log
}

/// dump 从桌面到当前元素的祖先链（使用 ControlViewWalker）
unsafe fn dump_ancestor_chain_with_walker(
    walker: &IUIAutomationTreeWalker,
    el: &IUIAutomationElement,
    log: &mut Vec<String>,
) {
    let mut chain: Vec<String> = Vec::new();
    let mut depth = 0;

    // 先收集祖先链
    if let Ok(mut current) = walker.NormalizeElement(el) {
        chain.push(format!("  0 [TARGET]"));
        depth += 1;
        while depth < 20 {
            match walker.GetParentElement(&current) {
                Ok(parent) => {
                    let name = bstr_of(|| parent.CurrentName());
                    let ct = parent.CurrentControlType().map(|c| control_type_name(c.0)).unwrap_or("?");
                    let aid = bstr_of(|| parent.CurrentAutomationId());
                    let cls = bstr_of(|| parent.CurrentClassName());
                    chain.push(format!("  {depth} [{ct}] name='{name}' autoId='{aid}' class='{cls}'"));
                    current = parent;
                    depth += 1;
                }
                Err(_) => break,
            }
        }
    }

    // 反向输出（桌面在上）
    for line in chain.into_iter().rev() {
        log.push(line);
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Public: dump_credential_dialogs — 增强版凭据对话框探测
// ══════════════════════════════════════════════════════════════════════

/// 探测并 dump 凭据/PIN 对话框的 UIA 树。
/// `timeout_secs` 内轮询；发现即 dump 并立即返回。
pub fn dump_credential_dialogs(timeout_secs: u64) -> Vec<String> {
    let mut log = Vec::new();
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let uia: IUIAutomation = match CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) {
            Ok(u) => u,
            Err(e) => {
                log.push(format!("CoCreateInstance(CUIAutomation) 失败: {e}"));
                return log;
            }
        };

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        log.push(format!("开始轮询凭据对话框（最多 {timeout_secs}s）。请在此期间触发 Hello PIN 框。"));
        log.push("使用 EnumWindows + ElementFromHandle 全窗口扫描。".to_string());

        let mut prev_count = enum_all_top_level_windows().len();

        loop {
            let windows = enum_all_top_level_windows();
            // 检测新窗口出现
            let current_count = windows.len();
            if current_count != prev_count {
                log.push(format!(
                    "\n[轮询] 窗口数变化: {prev_count} → {current_count} (可能新窗口出现)"
                ));
                prev_count = current_count;

                // dump 所有新增窗口
                for (hwnd, pid, title) in &windows {
                    let exe = process_name(*pid);
                    if is_credential_window(title, &exe)
                        || exe == "credentialuibroker.exe"
                        || exe == "consent.exe"
                    {
                        log.push(format!(
                            "\n==== 命中可疑凭据窗口: HWND=0x{:X} name='{title}' pid={pid} exe={exe} ====",
                            hwnd.0 as usize,
                        ));
                        if let Ok(el) = uia.ElementFromHandle(*hwnd) {
                            dump_element(&uia, &el, 0, &mut log);
                        } else {
                            log.push("  ElementFromHandle 失败（可能是受保护的系统窗口）".to_string());
                        }
                    }
                }
            }

            // 每轮也扫描所有窗口的凭据框
            let mut found = false;
            for (hwnd, pid, title) in &windows {
                let exe = process_name(*pid);
                if is_credential_window(title, &exe) {
                    found = true;
                    log.push(format!(
                        "\n==== 命中凭据窗口: HWND=0x{:X} name='{title}' pid={pid} exe={exe} ====",
                        hwnd.0 as usize,
                    ));
                    if let Ok(el) = uia.ElementFromHandle(*hwnd) {
                        dump_element(&uia, &el, 0, &mut log);
                    }
                    // 也 dump popup
                    if let Some(popup) = get_window_safe(*hwnd, GW_ENABLEDPOPUP.0) {
                        if popup.0 != hwnd.0 && !popup.0.is_null() {
                            log.push(format!(
                                "  Popup: HWND=0x{:X} title='{}'",
                                popup.0 as usize, window_title(popup)
                            ));
                            if let Ok(pel) = uia.ElementFromHandle(popup) {
                                dump_element(&uia, &pel, 1, &mut log);
                            }
                        }
                    }
                }
            }

            if found {
                log.push("\n[完成] 已 dump 凭据对话框 UIA 树。".to_string());
                break;
            }

            // 检查焦点元素（是否在凭据进程的 Edit 上）
            if let Ok(focused) = uia.GetFocusedElement() {
                let fname = bstr_of(|| focused.CurrentName());
                let fct = focused.CurrentControlType().map(|c| control_type_name(c.0)).unwrap_or("?");
                let fpid = focused.CurrentProcessId().unwrap_or(0) as u32;
                let fexe = process_name(fpid);
                if fct == "Edit" && (fexe == "credentialuibroker.exe" || fexe == "consent.exe") {
                    log.push(format!(
                        "\n==== 焦点位于凭据 Edit: name='{fname}' pid={fpid} exe={fexe} ===="
                    ));
                    if let Ok(walker) = uia.ControlViewWalker() {
                        dump_ancestor_chain_with_walker(&walker, &focused, &mut log);
                    }
                }
            }

            if std::time::Instant::now() >= deadline {
                log.push("\n[超时] 未发现凭据/PIN 对话框。".to_string());
                log.push(format!("\n--- 当前所有 {} 个顶层窗口快照 ---", windows.len()));
                for (hwnd, pid, title) in &windows {
                    let exe = process_name(*pid);
                    log.push(format!(
                        "  HWND=0x{:X} pid={pid} exe={exe} title='{title}'",
                        hwnd.0 as usize,
                    ));
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    log
}

// ══════════════════════════════════════════════════════════════════════
//  Public: autofill_pin — 自动填充 PIN 并提交
// ══════════════════════════════════════════════════════════════════════

/// 自动填充 PIN：定位凭据对话框的 PIN Edit 框，填入 `pin` 并提交。
/// 必须以提升(管理员/SYSTEM)完整性、在用户会话运行（2026.1 加固要求）。
///
/// 使用 EnumWindows + ElementFromHandle 找目标窗口。
pub fn autofill_pin(pin: &str, timeout_secs: u64) -> Result<String, String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let uia: IUIAutomation = CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("CoCreateInstance: {e}"))?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            // 策略: 用 EnumWindows 找到 credentialuibroker.exe 的窗口
            if let Some(win_el) = find_credential_window_enum(&uia) {
                // 找 Edit（PIN 框）
                let edit = find_first_by_control_type(&uia, &win_el, 50004);
                if let Some(edit) = edit {
                    // 设焦点
                    let _ = edit.SetFocus();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    // 先尝试 UIA ValuePattern.SetValue
                    if set_value(&edit, pin).is_err() {
                        // 回退: SendInput 逐字符键入（提升权限可用）
                        send_keys_digits(pin);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    // 提交: 找按钮 Invoke；不行则回车
                    if !invoke_submit(&uia, &win_el) {
                        send_enter();
                    }
                    return Ok("PIN 已填入并提交".to_string());
                }
            }

            // 也尝试通过焦点元素找
            if let Ok(focused) = uia.GetFocusedElement() {
                let fct = focused.CurrentControlType().map(|c| control_type_name(c.0)).unwrap_or("?");
                let fpid = focused.CurrentProcessId().unwrap_or(0) as u32;
                let fexe = process_name(fpid);
                if fct == "Edit" && (fexe == "credentialuibroker.exe" || fexe == "consent.exe") {
                    let _ = focused.SetFocus();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    if set_value(&focused, pin).is_err() {
                        send_keys_digits(pin);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    send_enter();
                    return Ok("PIN 已填入焦点 Edit 并回车提交".to_string());
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err("超时：未找到 PIN 输入框".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }
}

unsafe fn find_credential_window_enum(uia: &IUIAutomation) -> Option<IUIAutomationElement> {
    let windows = enum_all_top_level_windows();
    for (hwnd, pid, title) in &windows {
        let exe = process_name(*pid);
        // 匹配 credentialuibroker / consent / 凭据窗口
        if exe == "credentialuibroker.exe" || exe == "consent.exe"
            || is_credential_window(title, &exe)
        {
            if let Ok(el) = uia.ElementFromHandle(*hwnd) {
                // 检查是否有 PIN 输入框（深度搜索）
                if find_first_by_control_type(uia, &el, 50004).is_some() {
                    return Some(el);
                }
                // 检查 popup
                if let Some(popup) = get_window_safe(*hwnd, GW_ENABLEDPOPUP.0) {
                    if popup.0 != hwnd.0 && !popup.0.is_null() {
                        if let Ok(pel) = uia.ElementFromHandle(popup) {
                            if find_first_by_control_type(uia, &pel, 50004).is_some() {
                                return Some(pel);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

unsafe fn find_first_by_control_type(
    uia: &IUIAutomation,
    root: &IUIAutomationElement,
    control_type: i32,
) -> Option<IUIAutomationElement> {
    let _ = uia;
    let cond = uia.CreateTrueCondition().ok()?;
    let kids = root.FindAll(
        windows::Win32::UI::Accessibility::TreeScope_Descendants, &cond,
    ).ok()?;
    let n = kids.Length().unwrap_or(0);
    for i in 0..n {
        let k = kids.GetElement(i).ok()?;
        if k.CurrentControlType().map(|c| c.0).unwrap_or(0) == control_type {
            return Some(k);
        }
    }
    None
}

unsafe fn set_value(el: &IUIAutomationElement, val: &str) -> Result<(), String> {
    let pat = el.GetCurrentPattern(UIA_ValuePatternId).map_err(|e| e.to_string())?;
    let vp: IUIAutomationValuePattern = pat.cast().map_err(|e| e.to_string())?;
    vp.SetValue(&windows_core::BSTR::from(val)).map_err(|e| e.to_string())
}

/// 找 OK/确定/提交 按钮并 Invoke
unsafe fn invoke_submit(uia: &IUIAutomation, win: &IUIAutomationElement) -> bool {
    let labels = ["确定", "OK", "提交", "Submit", "下一步", "Next", "Sign in", "登录", "是", "Yes"];
    if let Ok(cond) = uia.CreateTrueCondition() {
        if let Ok(all) = win.FindAll(
            windows::Win32::UI::Accessibility::TreeScope_Descendants, &cond,
        ) {
            let n = all.Length().unwrap_or(0);
            for i in 0..n {
                if let Ok(el) = all.GetElement(i) {
                    let is_button = el.CurrentControlType().map(|c| c.0).unwrap_or(0) == 50000;
                    if !is_button { continue; }
                    let name = bstr_of(|| el.CurrentName());
                    if labels.iter().any(|l| name.eq_ignore_ascii_case(l) || name.contains(l)) {
                        if let Ok(pat) = el.GetCurrentPattern(UIA_InvokePatternId) {
                            if let Ok(inv) = pat.cast::<IUIAutomationInvokePattern>() {
                                if inv.Invoke().is_ok() { return true; }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// 用 SendInput 键入数字 PIN（回退方案，2026.1 加固后提升权限仍可用）
pub fn send_keys_digits(pin: &str) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VIRTUAL_KEY,
    };
    for ch in pin.encode_utf16() {
        unsafe {
            let down = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: ch,
                        dwFlags: KEYEVENTF_UNICODE,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let up = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: ch,
                        dwFlags: KEYBD_EVENT_FLAGS(KEYEVENTF_UNICODE.0 | KEYEVENTF_KEYUP.0),
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32);
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
}

/// 发送回车键
pub fn send_enter() {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_KEYUP, VK_RETURN,
    };
    unsafe {
        let down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_RETURN,
                    wScan: 0,
                    dwFlags: KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_RETURN,
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32);
    }
}
