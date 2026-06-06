/// FaceWinUnlock UIA Helper
/// =========================
///
/// 独立进程，通过 UI Automation 读取凭据弹窗文本，判断 passkey vs password。
/// DLL 通过 CreateProcess 启动本程序，传入弹窗 HWND（十六进制），
/// 本程序输出 "passkey" / "password" / "unknown" 到 stdout 后退出。
///
/// 独立进程设计避免 UIA COM 调用与 credentialuibroker.exe 的 STA
/// apartment 发生跨线程死锁。

use std::ffi::c_void;
use std::process;

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
use windows_core::{GUID, HRESULT, PCWSTR, IUnknown, Interface};

// ── UIA CLSID/IID ─────────────────────────────────────────────
const CLSID_CUIAUTOMATION: GUID = GUID::from_u128(0xff48dbaf_60ef_4201_aa87_54103eef594e);
const IID_IUIAUTOMATION: GUID = GUID::from_u128(0x30cbe57d_d9d0_452a_ab13_7ac5ac4825ee);
const TREE_SCOPE_DESCENDANTS: u32 = 0x4;

// ── 关键词 ────────────────────────────────────────────────────
const PASSKEY_KW: &[&str] = &["密钥", "通行密钥", "passkey", "安全密钥", "security key", "webauthn"];
const PASSWORD_KW: &[&str] = &["密码", "password", "credentials"];
const MIN_TEXT_LEN: usize = 3;

// ═══════════════════════════════════════════════════════════════
// Raw COM vtable
// ═══════════════════════════════════════════════════════════════
type VtblSlot = *const c_void;

#[repr(C)]
struct IUIAutomationVtbl {
    qi: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    addref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    _3: VtblSlot, _4: VtblSlot,
    element_from_handle: unsafe extern "system" fn(*mut c_void, isize, *mut *mut c_void) -> HRESULT,
    _6: VtblSlot, _7: VtblSlot, _8: VtblSlot, _9: VtblSlot, _10: VtblSlot,
    _11: VtblSlot, _12: VtblSlot, _13: VtblSlot, _14: VtblSlot, _15: VtblSlot,
    _16: VtblSlot, _17: VtblSlot, _18: VtblSlot, _19: VtblSlot,
    create_true_condition: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT,
    _21: VtblSlot, _22: VtblSlot,
}

#[repr(C)]
struct IUIAutomationElementVtbl {
    qi: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    addref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    _3: VtblSlot, _4: VtblSlot, _5: VtblSlot,
    find_all: unsafe extern "system" fn(*mut c_void, u32, *mut c_void, *mut *mut c_void) -> HRESULT,
    _7: VtblSlot, _8: VtblSlot, _9: VtblSlot, _10: VtblSlot,
    _11: VtblSlot, _12: VtblSlot, _13: VtblSlot, _14: VtblSlot, _15: VtblSlot,
    _16: VtblSlot, _17: VtblSlot, _18: VtblSlot, _19: VtblSlot, _20: VtblSlot,
    _21: VtblSlot, _22: VtblSlot, _23: VtblSlot, _24: VtblSlot, _25: VtblSlot,
    _26: VtblSlot, _27: VtblSlot, _28: VtblSlot, _29: VtblSlot, _30: VtblSlot,
    _31: VtblSlot, _32: VtblSlot, _33: VtblSlot, _34: VtblSlot, _35: VtblSlot,
    _36: VtblSlot, _37: VtblSlot, _38: VtblSlot,
    get_current_name: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> HRESULT,
    _40: VtblSlot, _41: VtblSlot, _42: VtblSlot, _43: VtblSlot, _44: VtblSlot,
}

#[repr(C)]
struct ArrayVtbl {
    qi: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    addref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    get_length: unsafe extern "system" fn(*mut c_void, *mut i32) -> HRESULT,
    get_element: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> HRESULT,
}

#[repr(C)]
struct GenericVtbl {
    qi: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    addref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

unsafe fn com_release(p: *mut c_void) {
    if !p.is_null() {
        let vtbl = unsafe { &**(p as *const *const GenericVtbl) };
        unsafe { (vtbl.release)(p); }
    }
}

struct H(*mut c_void);
impl Drop for H { fn drop(&mut self) { unsafe { com_release(self.0); } } }

unsafe fn read_bstr(p: *mut u16) -> Option<String> {
    if p.is_null() { return None; }
    unsafe {
        let blen = *((p as *const u32).offset(-1)) as usize;
        if blen == 0 { return None; }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p as *const u16, blen / 2));
        Some(s)
    }
}

// ═══════════════════════════════════════════════════════════════
fn main() {
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok(); }

    let hwnd = parse_hwnd();
    match detect(hwnd) {
        Ok(r) => { println!("{r}"); process::exit(0); }
        Err(e) => { eprintln!("{e}"); println!("unknown"); process::exit(0); }
    }
}

fn parse_hwnd() -> HWND {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let s = arg.trim_start_matches("0x").trim_start_matches("0X");
    let v = isize::from_str_radix(s, 16).unwrap_or(0);
    HWND(v as *mut c_void)
}

fn detect(hwnd: HWND) -> Result<String, String> {
    if hwnd.0.is_null() {
        // 无 HWND → 尝试查找弹窗
        let cn = to_utf16("Credential Dialog Xaml Host");
        match unsafe { FindWindowW(PCWSTR(cn.as_ptr()), None) } {
            Ok(w) if w.0 != std::ptr::null_mut() => return detect_window(w),
            _ => return Err("找不到凭据弹窗".into()),
        }
    }
    detect_window(hwnd)
}

fn detect_window(hwnd: HWND) -> Result<String, String> {
    // 1. CUIAutomation
    let unk: IUnknown = unsafe { CoCreateInstance(&CLSID_CUIAUTOMATION, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| format!("CoCreateInstance: {e:?}"))?;

    let mut uia_p: *mut c_void = std::ptr::null_mut();
    let hr = unsafe { unk.query(&IID_IUIAUTOMATION, &mut uia_p) };
    if hr.is_err() || uia_p.is_null() { return Err("QueryInterface IUIAutomation 失败".into()); }
    let uia = H(uia_p);

    // 2. ElementFromHandle
    let mut el_p: *mut c_void = std::ptr::null_mut();
    let vt = unsafe { &**(uia.0 as *const *const IUIAutomationVtbl) };
    let hr = unsafe { (vt.element_from_handle)(uia.0, hwnd.0 as isize, &mut el_p) };
    if hr.is_err() || el_p.is_null() { return Err("ElementFromHandle 失败".into()); }
    let el = H(el_p);

    // 3. CreateTrueCondition
    let mut cond_p: *mut c_void = std::ptr::null_mut();
    let hr = unsafe { (vt.create_true_condition)(uia.0, &mut cond_p) };
    if hr.is_err() || cond_p.is_null() { return Err("CreateTrueCondition 失败".into()); }
    let cond = H(cond_p);

    // 4. FindAll
    let mut arr_p: *mut c_void = std::ptr::null_mut();
    let evt = unsafe { &**(el.0 as *const *const IUIAutomationElementVtbl) };
    let hr = unsafe { (evt.find_all)(el.0, TREE_SCOPE_DESCENDANTS, cond.0, &mut arr_p) };
    if hr.is_err() || arr_p.is_null() { return Err("FindAll 失败".into()); }
    let arr = H(arr_p);

    // 5. 读取所有文本
    let avt = unsafe { &**(arr.0 as *const *const ArrayVtbl) };
    let mut len: i32 = 0;
    unsafe { (avt.get_length)(arr.0, &mut len); }
    let n = len.min(300);

    let mut texts = Vec::with_capacity(32);
    for i in 0..n {
        let mut ep: *mut c_void = std::ptr::null_mut();
        if unsafe { (avt.get_element)(arr.0, i, &mut ep) }.is_ok() && !ep.is_null() {
            let child = H(ep);
            let mut raw: *mut u16 = std::ptr::null_mut();
            let cevt = unsafe { &**(child.0 as *const *const IUIAutomationElementVtbl) };
            if unsafe { (cevt.get_current_name)(child.0, &mut raw) }.is_ok() && !raw.is_null() {
                if let Some(s) = unsafe { read_bstr(raw) } {
                    let t = s.trim().to_string();
                    if t.len() >= MIN_TEXT_LEN && !t.chars().all(|c| c.is_ascii_punctuation() || c == ' ') {
                        texts.push(t);
                    }
                }
            }
        }
    }

    // 6. 分类
    let joined = texts.join(" ").to_lowercase();
    let has_pass = PASSKEY_KW.iter().any(|k| joined.contains(&k.to_lowercase()));
    let has_pwd = PASSWORD_KW.iter().any(|k| joined.contains(&k.to_lowercase()));

    Ok(match (has_pass, has_pwd) {
        (true, false) => "passkey",
        (false, true) => "password",
        _ => "unknown",
    }.to_string())
}

fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
