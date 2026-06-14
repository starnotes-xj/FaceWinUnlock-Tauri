//! Path A: Windows NCrypt API — NGC Key Storage Provider 签名
//!
//! 使用 "Microsoft Passport Key Storage Provider" 加载 NGC 密钥，
//! 通过 NCryptSetProperty 设置 PIN 进行签名验证。
//! 私钥不出 KSP，由系统内部验证 PIN 正确性。
//!
//! # 设计决策
//!
//! 为什么走 NCrypt 而不是继续逆向 KDF：
//! - 现代 NgcIso（GUID 46FEE803）使用 CNG/KSP 内部管理的密钥层次
//! - PBKDF2+SHA512 派生的 AES 密钥与实际使用的完全不同（GCM 全部认证失败）
//! - SRK 只有 20 字节，不是标准 DPAPI blob，也不是 AES-256 密钥
//! - NCrypt 让 KSP 内部处理 PIN 验证和密钥解封，无需知道内部 KDF
//!
//! # 参考
//! - Shwmae (DEF CON 32): C# NCryptOpenKey + SmartcardPin + NCryptSignHash
//! - dpapilab-ng: NCrypt 路线的 PIN 供给策略

use super::NgcError;

/// NCrypt 签名结果
#[derive(Debug)]
pub struct NcryptSignResult {
    pub success: bool,
    pub key_name: String,
    pub algorithm: String,
    pub key_length: u32,
    pub signature: Vec<u8>,
    pub log: Vec<String>,
}

/// 用 NCrypt KSP 验证 PIN 并签名数据
pub fn verify_pin_and_sign(
    _sid: &str,
    pin: &str,
    data: &[u8],
) -> Result<(NcryptSignResult, Vec<String>), (NgcError, Vec<String>)> {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenStorageProvider, NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject,
        NCryptOpenKey, NCryptSetProperty, NCryptExportKey,
        NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE, NCryptKeyName,
        NCRYPT_FLAGS, CERT_KEY_SPEC,
        NCRYPT_SILENT_FLAG,
    };
    use windows_core::PCWSTR;

    let provider = "Microsoft Passport Key Storage Provider";
    let prov_wide: Vec<u16> = provider.encode_utf16().chain(Some(0)).collect();
    let mut prov = NCRYPT_PROV_HANDLE::default();

    unsafe {
        if let Err(e) = NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw(prov_wide.as_ptr()), 0) {
            return Err((NgcError::DecryptionFailed(format!("NCryptOpenStorageProvider: {e}")), Vec::new()));
        }
    }

    let mut log: Vec<String> = Vec::new();

    // 枚举所有密钥
    let mut all_keys: Vec<(String, bool)> = Vec::new();
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();

    loop {
        let mut kn: *mut NCryptKeyName = std::ptr::null_mut();
        match unsafe {
            NCryptEnumKeys(prov, PCWSTR::null(), &mut kn, &mut enum_state, NCRYPT_FLAGS(0))
        } {
            Ok(()) => {
                if kn.is_null() { break; }
                unsafe {
                    let name = (*kn).pszName.to_string().unwrap_or_default();
                    let is_fido = name.contains("FIDO_AUTHENTICATOR");
                    all_keys.push((name, is_fido));
                    let _ = NCryptFreeBuffer(kn as *mut core::ffi::c_void);
                }
            }
            Err(e) => {
                if (e.code().0 as u32) == 0x8009_002A { break; }
                log.push(format!("NCryptEnumKeys error: {e}"));
                break;
            }
        }
    }
    if !enum_state.is_null() { unsafe { let _ = NCryptFreeBuffer(enum_state); } }

    if all_keys.is_empty() {
        log.push("Passport KSP 中没有密钥！用户可能未设置 Windows Hello".to_string());
        unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
        return Err((NgcError::ContainerNotFound, log));
    }

    // FIDO 密钥排前面先试 —— passkey 断言需要 FIDO 密钥能签，
    // 优先确认它（而非 uvkey）是否可用注入的 PIN 签名。
    all_keys.sort_by_key(|(_, is_fido)| !*is_fido);

    log.push(format!("枚举到 {} 个密钥（FIDO 优先）:", all_keys.len()));
    for (name, is_fido) in &all_keys {
        log.push(format!("  [{}] {}", if *is_fido { "FIDO" } else { "NGC" }, name));
    }

    // 准备 PIN 格式变体
    let raw_pin_bytes: Vec<u8> = pin.encode_utf16()
        .chain(Some(0))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let hex_pin: String = pin.as_bytes().iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let hex_pin_bytes: Vec<u8> = hex_pin.encode_utf16()
        .chain(Some(0))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    const PIN_PROPERTIES: &[&str] = &["SmartcardPin", "PIN"];

    let mut last_error = String::new();

    for (key_name, _is_fido) in &all_keys {
        let key_name_w: Vec<u16> = key_name.encode_utf16().chain(Some(0)).collect();
        log.push(format!("\n--- 尝试密钥: {} ---", key_name));

        let mut k = NCRYPT_KEY_HANDLE::default();
        match unsafe {
            NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(key_name_w.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))
        } {
            Ok(()) => {},
            Err(e) => {
                log.push(format!("  NCryptOpenKey 失败: {e}"));
                last_error = format!("OpenKey({}): {}", key_name, e);
                continue;
            }
        };
        let kh = NCRYPT_HANDLE(k.0);

        let alg_name = get_string_prop(kh, "Algorithm Name").unwrap_or_else(|| "?".into());
        let key_len = get_dword_prop(kh, "Length").map(|v| v.to_string()).unwrap_or_else(|| "?".into());
        let key_group = get_string_prop(kh, "Algorithm Group").unwrap_or_else(|| "?".into());
        let export_pol = get_dword_prop(kh, "Export Policy").unwrap_or(0);
        log.push(format!("  Alg={} Len={} bits Group={} ExportPol=0x{:X}", alg_name, key_len, key_group, export_pol));

        // ── 🔑 KSP 增强版：尝试设置 Export Policy 允许导出密钥 ──
        // NCRYPT_ALLOW_EXPORT_FLAG = 1
        let desired_pol: u32 = 1; // Allow export
        let pol_bytes = desired_pol.to_le_bytes();
        let pol_prop: Vec<u16> = "Export Policy\0".encode_utf16().collect();
        match unsafe { NCryptSetProperty(kh, PCWSTR::from_raw(pol_prop.as_ptr()), &pol_bytes, NCRYPT_FLAGS(0)) } {
            Ok(()) => log.push("  ✅ 已设置 Export Policy = AllowExport".to_string()),
            Err(e) => log.push(format!("  ⚠️ 未能设置 Export Policy: {e}")),
        }

        // 关键新增：设置窗口句柄 (NCRYPT_WINDOW_HANDLE_PROPERTY)。
        // DeepSeek 的所有策略都漏了这一步 —— UI(非 silent) 模式没有窗口句柄无法弹原生框
        // 必然失败；而智能卡场景下「窗口句柄 + SmartCardPin」可能让 KSP 直接用提供的
        // PIN 而不弹框（headless 注入）。这是路 A 唯一没验证过、最可能成立的组合。
        unsafe { set_window_handle_prop(kh, &mut log); }

        let is_ecdsa = alg_name.contains("ECDSA") || alg_name.contains("ECDH")
            || key_group.contains("ECC");

        let _pin_ascii_bytes: Vec<u8> = pin.as_bytes().to_vec();
        let pin_ascii_null: Vec<u8> = {
            let mut v = pin.as_bytes().to_vec();
            v.push(0);
            v
        };
        let pin_utf16_no_null: Vec<u8> = pin.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut strategies: Vec<(&str, &[u8], bool, &str)> = Vec::new();

        strategies.push(("SmartcardPin", raw_pin_bytes.as_slice(), true, "SmartcardPin+raw+SILENT"));
        strategies.push(("SmartcardPin", hex_pin_bytes.as_slice(), true, "SmartcardPin+hex+SILENT"));
        strategies.push(("SmartcardPin", pin_utf16_no_null.as_slice(), true, "SmartcardPin+utf16_noNull+SILENT"));
        strategies.push(("SmartcardPin", pin_ascii_null.as_slice(), true, "SmartcardPin+asciiNull+SILENT"));

        strategies.push(("SmartcardPin", raw_pin_bytes.as_slice(), false, "SmartcardPin+raw+UI"));
        strategies.push(("SmartcardPin", hex_pin_bytes.as_slice(), false, "SmartcardPin+hex+UI"));
        strategies.push(("SmartcardPin", pin_utf16_no_null.as_slice(), false, "SmartcardPin+utf16_noNull+UI"));

        // 正确大小写 NCRYPT_PIN_PROPERTY = "SmartCardPin"（大写 C）。DeepSeek 全用小写 c。
        // 配合上面已设的窗口句柄，这是「headless 注入」最可能成立的组合。
        strategies.push(("SmartCardPin", raw_pin_bytes.as_slice(), false, "SmartCardPin+raw+UI+HWND"));
        strategies.push(("SmartCardPin", raw_pin_bytes.as_slice(), true, "SmartCardPin+raw+SILENT"));
        strategies.push(("SmartCardPin", pin_utf16_no_null.as_slice(), false, "SmartCardPin+utf16+UI+HWND"));
        strategies.push(("SmartCardPin", hex_pin_bytes.as_slice(), false, "SmartCardPin+hex+UI+HWND"));

        strategies.push(("", &[], true, "(no PIN)+SILENT"));
        // (no PIN)+UI 现在有窗口句柄 → 应能弹出原生 Hello PIN 框；若此项成功说明密钥
        // 本身可用、只是无法 headless 注入（需走原生框）。
        strategies.push(("", &[], false, "(no PIN)+UI+HWND"));

        for (prop_name, pin_bytes, use_silent, desc) in &strategies {
            if !prop_name.is_empty() {
                let prop_wide: Vec<u16> = prop_name.encode_utf16().chain(Some(0)).collect();
                let set_result = unsafe {
                    NCryptSetProperty(kh, PCWSTR::from_raw(prop_wide.as_ptr()), *pin_bytes, NCRYPT_FLAGS(0))
                };
                match set_result {
                    Ok(()) => {},
                    Err(e) => {
                        if !prop_name.is_empty() {
                            log.push(format!("  [{}] SetProperty 失败: {e}", desc));
                        }
                        continue;
                    }
                };
            }

            let flags = if *use_silent { NCRYPT_SILENT_FLAG } else { NCRYPT_FLAGS(0) };
            let full_label = if prop_name.is_empty() { desc.to_string() } else { format!("[{}]", desc) };
            log.push(format!("  尝试 {} ...", full_label));

            let sig_result = unsafe { try_ncrypt_sign(k, data, is_ecdsa, flags) };

            match sig_result {
                Ok(sig) => {
                    log.push(format!("  OK {} -> success! sig_len={}", full_label, sig.len()));

                    // ── 🔑 KSP 增强版：签名成功后尝试导出密钥 ──
                    // 此时 KSP 内部已解密密钥（用于签名），立即尝试 NCryptExportKey
                    log.push("  >>> KSP密钥捕获：尝试导出签名用的密钥...".to_string());
                    let export_formats: &[(&str, &str)] = &[
                        ("PLAINTEXTKEYBLOB", "RAW"),
                        ("OPAQUEBLOB", "Opaque"),
                        ("ECCPRIVATEBLOB", "ECC_Priv"),
                        ("ECCFULLPRIVATEBLOB", "ECC_Full"),
                        ("PKCS8_PRIVATEKEYBLOB", "PKCS8"),
                    ];
                    for (fmt, label) in export_formats {
                        let fmt_w: Vec<u16> = fmt.encode_utf16().chain(Some(0)).collect();
                        let mut sz = 0u32;
                        if unsafe { NCryptExportKey(k, None,
                            PCWSTR::from_raw(fmt_w.as_ptr()), None, None, &mut sz, NCRYPT_FLAGS(0)) }.is_ok()
                            && sz > 0 && sz <= 8192
                        {
                            let mut buf = vec![0u8; sz as usize];
                            let mut actual = 0u32;
                            if unsafe { NCryptExportKey(k, None,
                                PCWSTR::from_raw(fmt_w.as_ptr()), None,
                                Some(&mut buf), &mut actual, NCRYPT_FLAGS(0)) }.is_ok()
                            {
                                let hex: String = buf[..actual.min(64) as usize].iter()
                                    .map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                log.push(format!("  ✅ EXPORT [{}]: {}B, hex={}", label, actual, hex));
                                // 写入文件
                                let out_dir = r"C:\FaceWinUnlock\captured_keys";
                                let _ = std::fs::create_dir_all(out_dir);
                                let fname = format!("{}\\ncrypt_export_{}.bin", out_dir, fmt);
                                let _ = std::fs::write(&fname, &buf[..actual as usize]);
                                log.push(format!("  💾 密钥已保存: {}", fname));
                            } else {
                                log.push(format!("  ❌ Export [{}] body failed", label));
                            }
                        } else {
                            log.push(format!("  - Export [{}] size query: sz={}", label, sz));
                        }
                    }

                    unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }

                    return Ok((NcryptSignResult {
                        success: true,
                        key_name: key_name.clone(),
                        algorithm: alg_name,
                        key_length: key_len.parse().unwrap_or(0),
                        signature: sig,
                        log,
                    }, Vec::new()));
                }
                Err(e) => {
                    let err_code = e.code().0 as u32;
                    log.push(format!("    FAIL sign: 0x{err_code:08X} ({})", e));
                    last_error = format!("Sign({})=0x{err_code:08X}: {}", full_label, e);
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        unsafe { let _ = NCryptFreeObject(kh); }
    }

    unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
    log.push("\n=== 所有密钥/格式组合均失败 ===".to_string());
    log.push(format!("最后错误: {}", last_error));
    Err((NgcError::InvalidPin, log))
}

// ══════════════════════════════════════════════════════════════════
//  路B-4 探针: NCryptSecretAgreement / NCryptDeriveKey
// ══════════════════════════════════════════════════════════════════
//
// 目标: 不通过 NCryptDecrypt 间接解密，而是用 NCryptSecretAgreement 让
//       KSP 导出 key agreement 状态，然后通过 NCryptDeriveKey 派生中间密钥。
//       这可能揭示 NGC KSP 的内部 KDF 状态或允许直接拿到 AES key。
//
// 用法: --ngc-probe-derive <user> <pin>

/// 路B-4: 探针 KSP SecretAgreement 派生能力
pub fn probe_secret_agreement(sid: &str, pin: &str) -> Vec<String> {
    use windows::Win32::Security::Cryptography::*;
    use windows_core::PCWSTR;
    let mut log: Vec<String> = Vec::new();

    let (k, prov, key_name) = match open_passport_rsa_key(pin) {
        Ok(v) => v,
        Err((e, l)) => { log.push(format!("[OpenKsp] 失败: {e}")); log.extend(l); return log; }
    };
    log.push(format!("KSP 已打开密钥: {key_name}"));

    // 列出 KSP 支持的所有算法 (Algorithm Group / Algorithm Name)
    let alg_name = get_string_prop(NCRYPT_HANDLE(k.0), "Algorithm Name").unwrap_or_default();
    let alg_grp = get_string_prop(NCRYPT_HANDLE(k.0), "Algorithm Group").unwrap_or_default();
    let alg_len = get_dword_prop(NCRYPT_HANDLE(k.0), "Length").map(|v| v.to_string()).unwrap_or_else(|| "?".into());
    let key_type = get_string_prop(NCRYPT_HANDLE(k.0), "Key Type").unwrap_or_default();
    let key_usage = get_dword_prop(NCRYPT_HANDLE(k.0), "Key Usage").map(|v| format!("0x{v:X}")).unwrap_or_else(|| "?".into());
    let export_pol = get_dword_prop(NCRYPT_HANDLE(k.0), "Export Policy").map(|v| format!("0x:v{v:X}")).unwrap_or_else(|| "?".into());
    let impl_pol = get_dword_prop(NCRYPT_HANDLE(k.0), "Implementation Policy").map(|v| format!("0x{v:X}")).unwrap_or_else(|| "?".into());

    log.push(format!("[Key Properties]"));
    log.push(format!("  Algorithm Name: {alg_name}"));
    log.push(format!("  Algorithm Group: {alg_grp}"));
    log.push(format!("  Length: {alg_len} bits"));
    log.push(format!("  Key Type: {key_type}"));
    log.push(format!("  Key Usage: {key_usage}"));
    log.push(format!("  Export Policy: {export_pol}"));
    log.push(format!("  Implementation Policy: {impl_pol}"));

    // 尝试 NCryptSecretAgreement + NCryptDeriveKey
    // 1) SecretAgreement 需要 ephemeral key
    let mut secret = NCRYPT_SECRET_HANDLE::default();
    let k_handle: NCRYPT_KEY_HANDLE = k;
    let sa_result = unsafe { NCryptSecretAgreement(k_handle, NCRYPT_KEY_HANDLE::default(), &mut secret, NCRYPT_FLAGS(0)) };
    match sa_result {
        Ok(()) => log.push("[NCryptSecretAgreement] ✅ 成功 (拿到 secret handle)".to_string()),
        Err(e) => {
            let code = e.code().0 as u32;
            log.push(format!("[NCryptSecretAgreement] ❌ 失败 0x{code:08X}: {e}"));
            log.push("  提示: RSA key 不支持 SecretAgreement (那是 DH/ECDH 用的)".to_string());
        }
    }

    // 2) 尝试 NCryptDeriveKey (直接派生)
    let derive_targets: &[(&str, &str)] = &[
        ("SHA256", "KDF_SP800_108"),  // SP800-108 KDF
        ("SHA512", "KDF_SP800_108"),
        ("SHA256", "KDF_HMAC"),
        ("SHA512", "KDF_HMAC"),
        ("SHA256", "KDF_HASH"),
        ("SHA512", "KDF_HASH"),
        ("SHA256", "TLS_PRF"),
        ("SHA512", "PBKDF2"),
    ];
    log.push("".to_string());
    log.push("[NCryptDeriveKey 探针]".to_string());
    for (alg, kdf) in derive_targets {
        let alg_w: Vec<u16> = alg.encode_utf16().chain(Some(0)).collect();
        let _kdf_w: Vec<u16> = kdf.encode_utf16().chain(Some(0)).collect();
        let mut derived_size = 0u32;
        let res = unsafe {
            NCryptDeriveKey(
                NCRYPT_SECRET_HANDLE(secret.0),
                PCWSTR::from_raw(alg_w.as_ptr()),
                None,  // pParameter: Option<*const BCryptBufferDesc>
                None,  // pbDerivedKey
                &mut derived_size,
                0u32,  // dwFlags
            )
        };
        match res {
            Ok(()) => log.push(format!("  [KDF={kdf} + {alg}] ✅ 派生查询 OK (需要 {derived_size} B)")),
            Err(e) => {
                let code = e.code().0 as u32;
                log.push(format!("  [KDF={kdf} + {alg}] ❌ 0x{code:08X}"));
            }
        }
    }

    unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0)); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
    log
}

unsafe fn try_ncrypt_sign(
    key: windows::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    data: &[u8],
    ecdsa: bool,
    extra_flags: windows::Win32::Security::Cryptography::NCRYPT_FLAGS,
) -> Result<Vec<u8>, windows_core::Error> {
    use windows::Win32::Security::Cryptography::{
        NCryptSignHash, BCRYPT_PKCS1_PADDING_INFO, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_FLAGS,
    };
    use windows_core::PCWSTR;

    let padding_info: Option<*const core::ffi::c_void> = if ecdsa {
        None
    } else {
        let sha256_str: String = "SHA256\0".to_string();
        let alg: Vec<u16> = sha256_str.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let pad = Box::new(BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: PCWSTR::from_raw(alg.as_ptr()),
        });
        Some(Box::leak(pad) as *const _ as *const core::ffi::c_void)
    };

    let flags: NCRYPT_FLAGS = if ecdsa {
        extra_flags
    } else {
        NCRYPT_FLAGS(NCRYPT_PAD_PKCS1_FLAG.0 | extra_flags.0)
    };

    let mut sig_size = 0u32;
    NCryptSignHash(
        key, padding_info, data, None, &mut sig_size, flags,
    )?;

    if sig_size == 0 || sig_size > 8192 {
        let mut junk = [0u8; 1];
        let mut junk_size = 0u32;
        let _ = NCryptSignHash(key, padding_info, data, Some(&mut junk), &mut junk_size, flags);
        return Err(windows_core::Error::from_win32());
    }

    let mut sig = vec![0u8; sig_size as usize];
    let mut actual_size = 0u32;
    NCryptSignHash(
        key, padding_info, data, Some(&mut sig), &mut actual_size, flags,
    )?;

    sig.truncate(actual_size as usize);
    Ok(sig)
}

const fn WIN32_FROM_NTSTATUS(ntstatus: u32) -> u32 {
    if ntstatus & 0x10000000 != 0 { ntstatus & 0x0000FFFF } else { ntstatus }
}

// ─── 属性读取辅助 ────────────────────────────────────────────────────

fn get_string_prop(h: windows::Win32::Security::Cryptography::NCRYPT_HANDLE, prop: &str) -> Option<String> {
    use windows::Win32::Security::Cryptography::{NCryptGetProperty};
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    use windows_core::PCWSTR;
    let pw: Vec<u16> = prop.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut needed = 0u32;
        if NCryptGetProperty(h, PCWSTR::from_raw(pw.as_ptr()), None, &mut needed, OBJECT_SECURITY_INFORMATION(0)).is_err()
            || needed == 0 { return None; }
        let mut buf = vec![0u8; needed as usize];
        if NCryptGetProperty(h, PCWSTR::from_raw(pw.as_ptr()), Some(&mut buf), &mut needed, OBJECT_SECURITY_INFORMATION(0)).is_err() { return None; }
        let u16s: Vec<u16> = buf[..needed as usize].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string())
    }
}

fn get_dword_prop(h: windows::Win32::Security::Cryptography::NCRYPT_HANDLE, prop: &str) -> Option<u32> {
    use windows::Win32::Security::Cryptography::{NCryptGetProperty};
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    use windows_core::PCWSTR;
    let pw: Vec<u16> = prop.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut buf = [0u8; 4];
        let mut needed = 0u32;
        if NCryptGetProperty(h, PCWSTR::from_raw(pw.as_ptr()), Some(&mut buf), &mut needed, OBJECT_SECURITY_INFORMATION(0)).is_err()
            || needed < 4 { return None; }
        Some(u32::from_le_bytes(buf))
    }
}

/// 设置 NCRYPT_WINDOW_HANDLE_PROPERTY ("HWND Handle")。
/// 用前台窗口（回退桌面窗口）作为 UI 上下文；值为 HWND 指针的字节表示。
/// 这是 headless PIN 注入可能成立的关键前置（KSP 需要窗口上下文）。
unsafe fn set_window_handle_prop(
    kh: windows::Win32::Security::Cryptography::NCRYPT_HANDLE,
    log: &mut Vec<String>,
) {
    use windows::Win32::Security::Cryptography::{NCryptSetProperty, NCRYPT_FLAGS};
    use windows::Win32::UI::WindowsAndMessaging::{GetDesktopWindow, GetForegroundWindow};
    use windows_core::PCWSTR;

    let mut hwnd = GetForegroundWindow();
    if hwnd.0.is_null() {
        hwnd = GetDesktopWindow();
    }
    let hwnd_val = hwnd.0 as isize;
    let bytes = hwnd_val.to_ne_bytes();
    let prop: Vec<u16> = "HWND Handle\0".encode_utf16().collect();
    match NCryptSetProperty(kh, PCWSTR::from_raw(prop.as_ptr()), &bytes, NCRYPT_FLAGS(0)) {
        Ok(()) => log.push(format!("  NCRYPT_WINDOW_HANDLE_PROPERTY OK (hwnd={hwnd_val:#x})")),
        Err(e) => log.push(format!("  窗口句柄设置失败: 0x{:08X}", e.code().0 as u32)),
    }
}

/// 枚举 Passport KSP 中的所有密钥信息
pub fn enumerate_ngc_keys(_sid: &str) -> Result<Vec<(String, String, u32, bool)>, NgcError> {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenStorageProvider, NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject,
        NCryptOpenKey, NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE, NCryptKeyName, NCRYPT_FLAGS,
        CERT_KEY_SPEC,
    };
    use windows_core::PCWSTR;

    let provider = "Microsoft Passport Key Storage Provider";
    let prov_wide: Vec<u16> = provider.encode_utf16().chain(Some(0)).collect();
    let mut prov = NCRYPT_PROV_HANDLE::default();

    unsafe {
        if let Err(e) = NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw(prov_wide.as_ptr()), 0) {
            return Err(NgcError::DecryptionFailed(format!("NCryptOpenStorageProvider: {e}")));
        }
    }

    let mut results = Vec::new();
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();

    loop {
        let mut kn: *mut NCryptKeyName = std::ptr::null_mut();
        match unsafe { NCryptEnumKeys(prov, PCWSTR::null(), &mut kn, &mut enum_state, NCRYPT_FLAGS(0)) } {
            Ok(()) => {
                if kn.is_null() { break; }
                unsafe {
                    let name = (*kn).pszName.to_string().unwrap_or_default();
                    let is_fido = name.contains("FIDO_AUTHENTICATOR");
                    let name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                    let mut k = NCRYPT_KEY_HANDLE::default();
                    let (alg, len) = if NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(name_w.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_ok() {
                        let h = NCRYPT_HANDLE(k.0);
                        let a = get_string_prop(h, "Algorithm Name").unwrap_or_default();
                        let l = get_dword_prop(h, "Length").unwrap_or(0);
                        let _ = NCryptFreeObject(h);
                        (a, l)
                    } else { ("?".into(), 0) };
                    results.push((name, alg, len, is_fido));
                    let _ = NCryptFreeBuffer(kn as *mut core::ffi::c_void);
                }
            }
            Err(e) => {
                if (e.code().0 as u32) == 0x8009002A { break; }
                unsafe { if !enum_state.is_null() { let _ = NCryptFreeBuffer(enum_state); } let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
                return Err(NgcError::DecryptionFailed(format!("NCryptEnumKeys: {e}")));
            }
        }
    }

    unsafe { if !enum_state.is_null() { let _ = NCryptFreeBuffer(enum_state); } let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
    Ok(results)
}

/// 快速验证：PIN 是否正确
pub fn quick_verify_pin(sid: &str, pin: &str) -> Result<bool, NgcError> {
    use sha2::{Sha256, Digest};
    let test_data = Sha256::digest(b"FaceWinUnlock-PIN-verify").to_vec();
    match verify_pin_and_sign(sid, pin, &test_data) {
        Ok((result, _log)) => Ok(result.success),
        Err((NgcError::InvalidPin, _)) => Ok(false),
        Err((e, _)) => Err(e),
    }
}

// ─── Path A 扩展: NCryptDecrypt 解密 Vault ────────────────────────────

/// 尝试用 NCryptDecrypt 通过 RSA 私钥解密 EncData/vault
pub fn try_ncrypt_decrypt_vault(
    sid: &str,
    pin: &str,
) -> Result<(Vec<u8>, Vec<String>), (NgcError, Vec<String>)> {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenStorageProvider, NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject,
        NCryptOpenKey, NCryptSetProperty,
        NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE, NCryptKeyName,
        NCRYPT_FLAGS, CERT_KEY_SPEC,
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_PKCS1_PADDING_INFO,
    };
    use windows_core::PCWSTR;
    use base64::Engine;

    let mut log = Vec::new();
    let provider = "Microsoft Passport Key Storage Provider";
    let prov_wide: Vec<u16> = provider.encode_utf16().chain(Some(0)).collect();
    let mut prov = NCRYPT_PROV_HANDLE::default();

    unsafe {
        if let Err(e) = NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw(prov_wide.as_ptr()), 0) {
            return Err((NgcError::DecryptionFailed(format!("NCryptOpenStorageProvider: {e}")), log));
        }
    }

    // 枚举密钥找 RSA uvkey
    let mut rsa_key_name: Option<String> = None;
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();

    loop {
        let mut kn: *mut NCryptKeyName = std::ptr::null_mut();
        match unsafe { NCryptEnumKeys(prov, PCWSTR::null(), &mut kn, &mut enum_state, NCRYPT_FLAGS(0)) } {
            Ok(()) => {
                if kn.is_null() { break; }
                unsafe {
                    let name = (*kn).pszName.to_string().unwrap_or_default();
                    if name.contains("uvkey") || (!name.contains("FIDO") && rsa_key_name.is_none()) {
                        let nw: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                        let mut tk = NCRYPT_KEY_HANDLE::default();
                        if NCryptOpenKey(prov, &mut tk, PCWSTR::from_raw(nw.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_ok() {
                            let th = NCRYPT_HANDLE(tk.0);
                            let alg = get_string_prop(th, "Algorithm Name").unwrap_or_default();
                            if alg.contains("RSA") || name.contains("uvkey") { rsa_key_name = Some(name); }
                            let _ = NCryptFreeObject(th);
                        }
                    }
                    let _ = NCryptFreeBuffer(kn as *mut core::ffi::c_void);
                }
            }
            Err(_) => break,
        }
    }
    if !enum_state.is_null() { unsafe { let _ = NCryptFreeBuffer(enum_state); } }

    let key_name = match rsa_key_name {
        Some(n) => n,
        None => {
            unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
            return Err((NgcError::ContainerNotFound, vec!["未找到 RSA/uvkey 密钥".into()]));
        }
    };
    log.push(format!("使用密钥: {}", key_name));

    let kw: Vec<u16> = key_name.encode_utf16().chain(Some(0)).collect();
    let mut k = NCRYPT_KEY_HANDLE::default();
    match unsafe { NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(kw.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) } {
        Ok(()) => {},
        Err(e) => {
            unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
            return Err((NgcError::DecryptionFailed(format!("NCryptOpenKey: {e}")), log));
        }
    };
    let kh = NCRYPT_HANDLE(k.0);

    let pin_bytes: Vec<u8> = pin.encode_utf16().chain(Some(0)).flat_map(|c| c.to_le_bytes()).collect();
    let scpin_w: Vec<u16> = "SmartcardPin".encode_utf16().chain(Some(0)).collect();
    match unsafe { NCryptSetProperty(kh, PCWSTR::from_raw(scpin_w.as_ptr()), &pin_bytes, NCRYPT_FLAGS(0)) } {
        Ok(()) => log.push("PIN 设置成功 (SmartcardPin+UTF16)".to_string()),
        Err(e) => {
            unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
            return Err((NgcError::DecryptionFailed(format!("SetProperty: {e}")), log));
        }
    };

    // 通过 container.rs 查找 GUID 目录
    let ci = match super::container::find_ngc_container(sid) {
        Ok(c) => {
            log.push(format!("容器路径: {}", c.container_path.display()));
            log.push(format!("Salt: {} bytes, Rounds: {}", c.salt.len(), c.rounds));
            c
        }
        Err(e) => {
            log.push(format!("find_ngc_container 失败: {e}"));
            log.push("提示: 需要 SYSTEM 身份才能枚举 NGC 目录".into());
            unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
            return Err((e, log));
        }
    };

    let cj_path = ci.container_path.join("Container.json");
    if !cj_path.exists() {
        log.push("Container.json 不存在(现代格式可能无此文件)".into());
        let pj_path = ci.container_path.join("Protectors.json");
        if pj_path.exists() {
            log.push(format!("找到: {}", pj_path.display()));
            if let Ok(ps) = std::fs::read_to_string(&pj_path) {
                log.push(format!("Protectors.json 大小: {} chars", ps.len()));
                if let Ok(pv) = serde_json::from_str::<serde_json::Value>(&ps) {
                    let keys: Vec<String> = pv.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
                    log.push(format!("Protectors 字段: {:?}", keys));
                    if let Some(pin_obj) = pv.get("pin") {
                        log.push(format!("pin 对象 keys: {:?}", pin_obj.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())));
                        if let Some(ss) = pin_obj.get("secretStore") {
                            log.push(format!("secretStore keys: {:?}", ss.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())));
                            if let Some(ec) = ss.get("encryptedCbor").and_then(|v| v.as_str()) {
                                log.push(format!("encryptedCbor: {} chars", ec.len()));
                            }
                        }
                    }
                }
            }
        } else {
            log.push("Protectors.json 也不存在".into());
            if let Ok(entries) = std::fs::read_dir(&ci.container_path) {
                for e in entries.flatten() {
                    let m = e.metadata().ok();
                    log.push(format!("  {} ({}B)", e.file_name().to_string_lossy(), m.map(|m| m.len()).unwrap_or(0)));
                }
            }
        }
        unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
        return Err((NgcError::ContainerNotFound, log));
    }

    let json_str = match std::fs::read_to_string(&cj_path) {
        Ok(s) => s,
        Err(e) => { unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
                   return Err((NgcError::IoError(e), log)); }
    };
    let v: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => { unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
                   return Err((NgcError::DecryptionFailed(format!("JSON: {e}")), log)); }
    };

    let fields: Vec<&str> = v.as_object().map(|o| o.keys().map(|s| s.as_str()).collect()).unwrap_or_default();
    log.push(format!("Container.json 字段: {:?}", fields));

    // 提取 encryptedCbor -> 统一用 String
    let enc_b64: Option<String> = v.get("encryptedCbor").and_then(|x| x.as_str())
        .or_else(|| v.get("EncData").and_then(|x| x.as_str()))
        .or_else(|| v.get("encData").and_then(|x| x.as_str()))
        .map(|s| s.to_string());

    // 回退到 Protectors.json
    let enc_b64 = match enc_b64 {
        Some(s) => Some(s),
        None => {
            log.push("Container.json 无加密数据字段, 回退到 Protectors.json...".into());
            let pj_path = ci.container_path.join("Protectors.json");
            if !pj_path.exists() {
                log.push(format!("Protectors.json 不存在: {}", pj_path.display()));
                None
            } else if let Ok(ps_str) = std::fs::read_to_string(&pj_path) {
                log.push(format!("找到 Protectors.json ({} chars)", ps_str.len()));
                match serde_json::from_str::<serde_json::Value>(&ps_str) {
                    Ok(pv) => {
                        let ec = pv.get("pin")
                            .and_then(|p| p.get("secretStore"))
                            .and_then(|s| s.get("encryptedCbor"))
                            .and_then(|e| e.as_str())
                            .map(|s| s.to_string());
                        match &ec {
                            Some(s) => { log.push(format!("OK 从 Protectors.json 取得 encryptedCbor: {} chars", s.len())); }
                            None => {
                                let pk: Vec<String> = pv.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
                                log.push(format!("Protectors 顶层: {:?}", pk));
                            }
                        }
                        ec
                    }
                    Err(e) => { log.push(format!("Protectors.json 解析失败: {}", e)); None }
                }
            } else { None }
        }
    };

    let enc_b64 = match enc_b64 {
        Some(s) => s,
        None => {
            log.push("未在任何位置找到加密数据".into());
            if let Ok(entries) = std::fs::read_dir(&ci.container_path) {
                for e in entries.flatten() {
                    let m = e.metadata().ok();
                    log.push(format!("  {} ({}B)", e.file_name().to_string_lossy(), m.map(|m| m.len()).unwrap_or(0)));
                }
            }
            unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
            return Err((NgcError::DecryptionFailed("所有位置均未找到加密数据(encryptedCbor)".into()), log));
        }
    };
    log.push(format!("加密数据: {} chars (base64)", enc_b64.len()));

    let enc_bytes = match base64::engine::general_purpose::STANDARD.decode(&enc_b64) {
        Ok(b) => b,
        Err(e) => { unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
                   return Err((NgcError::DecryptionFailed(format!("b64: {e}")), log)); }
    };
    log.push(format!("解码 payload: {} bytes", enc_bytes.len()));
    if enc_bytes.len() >= 32 { log.push(format!("Head32: {:02X?}", &enc_bytes[..32])); }

    let sha256_w: Vec<u16> = "SHA256\0".encode_utf16().collect();
    let elen = enc_bytes.len();
    let regions: Vec<(&str, usize, usize)> = vec![
        ("前256B", 0, 256.min(elen)),
        ("跳header后256B", 32, (32+256).min(elen)),
        ("尾部256B", elen.saturating_sub(256), elen),
        ("前128B", 0, 128.min(elen)),
        ("中间256B", elen/2, (elen/2+256).min(elen)),
    ];

    for (label, off, end) in &regions {
        if *off >= elen || end <= off || (*end - *off) < 16 { continue; }
        let chunk = &enc_bytes[*off..*end];
        log.push(format!("\n  --- {} offset={} len={} ---", label, off, chunk.len()));

        let oaep = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: PCWSTR::from_raw(sha256_w.as_ptr()),
            pbLabel: core::ptr::null_mut(),
            cbLabel: 0,
        };
        match unsafe { ncrypt_decrypt_call(k, chunk, Some(&oaep as *const _ as *const _), NCRYPT_FLAGS(0)) } {
            Ok(pt) => { log.push(decrypt_success_msg(&pt)); unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); } return Ok((pt, log)); }
            Err(e) => { log.push(format!("     OAEP -> 0x{:08X}", e.code().0 as u32)); }
        }

        let pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: PCWSTR::from_raw(sha256_w.as_ptr()),
        };
        match unsafe { ncrypt_decrypt_call(k, chunk, Some(&pkcs1 as *const _ as *const _), NCRYPT_FLAGS(0)) } {
            Ok(pt) => { log.push(format!("  OK PKCS1 成功! {}B", pt.len())); unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); } return Ok((pt, log)); }
            Err(e) => { log.push(format!("     PKCS1 -> 0x{:08X}", e.code().0 as u32)); }
        }

        match unsafe { ncrypt_decrypt_call(k, chunk, None, NCRYPT_FLAGS(0)) } {
            Ok(pt) => { log.push(format!("  OK RAW 成功! {}B", pt.len())); unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); } return Ok((pt, log)); }
            Err(e) => { log.push(format!("     RAW -> 0x{:08X}", e.code().0 as u32)); }
        }
    }

    unsafe { let _ = NCryptFreeObject(kh); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
    Err((
        NgcError::DecryptionFailed("所有区域均无法通过 NCryptDecrypt 解密。EncData 可能是 AES 加密(CBC/GCM)，非直接 RSA 公钥加密。".to_string()),
        log
    ))
}

// ══════════════════════════════════════════════════════════════════
//  路A 专用 phase1 入口: NCryptDecrypt 多点尝试
// ══════════════════════════════════════════════════════════════════
//
// 路A 哲学: 不导出 RSA 私钥，让 KSP 内部完成解密。
//
// 尝试 3 类数据源：
// 1. Protectors.json 的 encryptedCbor 直接用 NCryptDecrypt 各区域
// 2. Container.json 的 encryptedCbor（现代格式核心数据）
// 3. Keys/*.json 的 encryptedCbor（每个 Key 文件）
//
// 每种数据都尝试:
// - 整个 encryptedCbor (PKCS1 + OAEP + RAW)
// - 256-byte 切片 (假设 EncData 是 RSA-2048 密文位于固定偏移)
// - 16/32/64-byte 对齐的窗口 (假设 AES 密文被错误地用 NCryptDecrypt 解)
// - 跳过 NgcIsoHeader 后的多个区域

/// 路A phase1: NCrypt 原地解密链 (不依赖 RSA 私钥导出)
pub fn phase1_ncrypt_path_a(
    sid: &str,
    pin: &str,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    let mut log = Vec::new();
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    l!("=== 路A Phase 1: NCrypt 原地解密 (不导出私钥) ===");
    l!("SID: {}, PIN: {}***", sid, &pin[..pin.chars().take(2).count()]);

    // Step 1: 打开 Passport KSP + 找到 RSA uvkey
    let (k, prov, _key_name) = match open_passport_rsa_key(pin) {
        Ok(v) => v,
        Err((e, err_log)) => { for line in err_log { log.push(format!("[OpenKsp] {line}")); } return Err((e, log)); }
    };
    l!("已打开 KSP + uvkey");

    // Step 2: 找到容器
    let ci = match super::container::find_ngc_container(sid) {
        Ok(c) => c,
        Err(e) => { unsafe { let _ = windows::Win32::Security::Cryptography::NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(k.0)); let _ = windows::Win32::Security::Cryptography::NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(prov.0)); } return Err((e, log)); }
    };
    l!("容器: {}", ci.container_path.display());

    let mut all_cbor: Vec<(String, Vec<u8>)> = Vec::new();

    // 收集所有 encryptedCbor 数据源
    if let Some(cbor) = read_protectors_cbor(&ci) {
        all_cbor.push(("Protectors.encryptedCbor".to_string(), cbor));
    }
    if let Some(cbor) = read_container_cbor(&ci) {
        all_cbor.push(("Container.encryptedCbor".to_string(), cbor));
    }
    if let Some(keys_cbors) = read_all_keys_cbors(&ci) {
        for (fname, cbor) in keys_cbors {
            all_cbor.push((format!("Keys/{fname}"), cbor));
        }
    }

    l!("共收集 {} 个加密Cbor 数据源", all_cbor.len());

    // Step 3: 对每个数据源做多点 NCryptDecrypt 尝试
    let total_sources = all_cbor.len();
    for (src_name, cbor_bytes) in all_cbor {
        l!("\n--- 处理 {} ({}B) ---", src_name, cbor_bytes.len());

        match try_ncrypt_decrypt_multipoints(k, &cbor_bytes, &mut log) {
            Some((pt, label)) => {
                let s = utf16_le_to_string(&pt);
                if !s.is_empty() && is_plaintext_password(&s) {
                    l!("[路A 成功!] 来源={}, 方法={}", src_name, label);
                    l!("明文密码: [{} chars] '{}'", s.chars().count(), s);
                    unsafe {
                        let _ = windows::Win32::Security::Cryptography::NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(k.0));
                        let _ = windows::Win32::Security::Cryptography::NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(prov.0));
                    }
                    return Ok((s, log));
                }
                l!("[路A {}] {} → 非纯文本(hex前32B): {:02X?}", label, src_name, &pt[..pt.len().min(32)]);
            }
            None => { l!("[路A 失败] {} → 所有方法/区域均未解出有效数据", src_name); }
        }
    }

    unsafe {
        let _ = windows::Win32::Security::Cryptography::NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(k.0));
        let _ = windows::Win32::Security::Cryptography::NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(prov.0));
    }

    Err((
        NgcError::DecryptionFailed(format!("路A phase1 失败: 对 {} 个数据源的所有 NCryptDecrypt 尝试均未解出明文密码", total_sources)),
        log
    ))
}

/// 打开 Passport KSP + 找到 RSA uvkey + 设 PIN
fn open_passport_rsa_key(pin: &str) -> Result<(windows::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE, windows::Win32::Security::Cryptography::NCRYPT_PROV_HANDLE, String), (NgcError, Vec<String>)> {
    use windows::Win32::Security::Cryptography::*;
    use windows_core::PCWSTR;
    let mut log = Vec::new();
    let mut prov = NCRYPT_PROV_HANDLE::default();
    let open_result = unsafe {
        NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw("Microsoft Passport Key Storage Provider\0".encode_utf16().collect::<Vec<u16>>().as_ptr()), 0)
    };
    if let Err(e) = open_result {
        return Err((NgcError::DecryptionFailed(format!("OpenStorageProvider: {e}")), log));
    }

    // 枚举找 uvkey/RSA key
    let mut rsa_key_name: Option<String> = None;
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();
    loop {
        let mut kn: *mut NCryptKeyName = std::ptr::null_mut();
        match unsafe { NCryptEnumKeys(prov, PCWSTR::null(), &mut kn, &mut enum_state, NCRYPT_FLAGS(0)) } {
            Ok(()) => {
                if kn.is_null() { break; }
                unsafe {
                    let name = (*kn).pszName.to_string().unwrap_or_default();
                    if name.contains("uvkey") || (!name.contains("FIDO") && rsa_key_name.is_none()) {
                        let nw: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                        let mut tk = NCRYPT_KEY_HANDLE::default();
                        if NCryptOpenKey(prov, &mut tk, PCWSTR::from_raw(nw.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_ok() {
                            let th = NCRYPT_HANDLE(tk.0);
                            let alg = get_string_prop(th, "Algorithm Name").unwrap_or_default();
                            if alg.contains("RSA") || name.contains("uvkey") {
                                rsa_key_name = Some(name.clone());
                                let _ = NCryptFreeObject(th);
                                if rsa_key_name.as_ref().map(|s| s.contains("uvkey")).unwrap_or(false) { break; }
                            } else { let _ = NCryptFreeObject(th); }
                        }
                    }
                    let _ = NCryptFreeBuffer(kn as *mut core::ffi::c_void);
                }
            }
            Err(_) => break,
        }
    }
    if !enum_state.is_null() { unsafe { let _ = NCryptFreeBuffer(enum_state); } }

    let key_name = match rsa_key_name {
        Some(n) => n,
        None => { unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); } return Err((NgcError::ContainerNotFound, vec!["未找到 uvkey/RSA".into()])); }
    };
    log.push(format!("KSP 选中密钥: {}", key_name));

    let kw: Vec<u16> = key_name.encode_utf16().chain(Some(0)).collect();
    let mut k = NCRYPT_KEY_HANDLE::default();
    let ok_result = unsafe { NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(kw.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) };
    if let Err(e) = ok_result {
        unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
        return Err((NgcError::DecryptionFailed(format!("OpenKey: {e}")), log));
    }

    // 设 PIN
    let pin_bytes: Vec<u8> = pin.encode_utf16().chain(Some(0)).flat_map(|c| c.to_le_bytes()).collect();
    let scpin_w: Vec<u16> = "SmartcardPin\0".encode_utf16().collect();
    let pin_result = unsafe { NCryptSetProperty(NCRYPT_HANDLE(k.0), PCWSTR::from_raw(scpin_w.as_ptr()), &pin_bytes, NCRYPT_FLAGS(0)) };
    if let Err(e) = pin_result {
        unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0)); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
        return Err((NgcError::DecryptionFailed(format!("SetPin: {e}")), log));
    }

    Ok((k, prov, key_name))
}

fn read_protectors_cbor(ci: &super::NgcContainerInfo) -> Option<Vec<u8>> {
    use base64::Engine;
    let pj = ci.container_path.join("Protectors.json");
    let s = std::fs::read_to_string(&pj).ok()?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    let b64 = v.get("pin").and_then(|p| p.get("secretStore")).and_then(|s| s.get("encryptedCbor")).and_then(|e| e.as_str())?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn read_container_cbor(ci: &super::NgcContainerInfo) -> Option<Vec<u8>> {
    use base64::Engine;
    let cj = ci.container_path.join("Container.json");
    let s = std::fs::read_to_string(&cj).ok()?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    let b64 = v.get("encryptedCbor").and_then(|x| x.as_str())?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn read_all_keys_cbors(ci: &super::NgcContainerInfo) -> Option<Vec<(String, Vec<u8>)>> {
    use base64::Engine;
    let keys_dir = ci.container_path.join("Keys");
    if !keys_dir.is_dir() { return None; }
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&keys_dir) {
        for entry in entries.flatten() {
            let kf = entry.path();
            if !kf.is_file() || kf.extension().map_or(true, |e| e != "json") { continue; }
            let fname = kf.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
            if let Ok(ks) = std::fs::read_to_string(&kf) {
                if let Ok(kv) = serde_json::from_str::<serde_json::Value>(&ks) {
                    let b64 = kv.get("encrypted").and_then(|e| e.get("encryptedCbor")).and_then(|v| v.as_str())
                        .or_else(|| kv.get("encryptedCbor").and_then(|v| v.as_str()));
                    if let Some(b64) = b64 {
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                            out.push((fname, bytes));
                        }
                    }
                }
            }
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// 对给定 cbor 数据做多点 NCryptDecrypt 尝试
fn try_ncrypt_decrypt_multipoints(
    k: windows::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    cbor_bytes: &[u8],
    log: &mut Vec<String>,
) -> Option<(Vec<u8>, String)> {
    use windows::Win32::Security::Cryptography::*;
    use windows_core::PCWSTR;

    let sha256_w: Vec<u16> = "SHA256\0".encode_utf16().collect();
    let oaep = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: PCWSTR::from_raw(sha256_w.as_ptr()),
        pbLabel: core::ptr::null_mut(),
        cbLabel: 0,
    };
    let pkcs1 = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: PCWSTR::from_raw(sha256_w.as_ptr()) };

    // Helper closure: 对一段密文尝试 3 种 padding
    let try_chunk = |chunk: &[u8], tag: &str| -> Option<(Vec<u8>, String)> {
        // OAEP
        let oaep_ptr = &oaep as *const _ as *const core::ffi::c_void;
        if let Ok(pt) = unsafe { ncrypt_decrypt_call(k, chunk, Some(oaep_ptr), NCRYPT_FLAGS(0)) } {
            if !pt.is_empty() { return Some((pt, format!("{tag}-OAEP"))); }
        }
        // PKCS1
        let pkcs1_ptr = &pkcs1 as *const _ as *const core::ffi::c_void;
        if let Ok(pt) = unsafe { ncrypt_decrypt_call(k, chunk, Some(pkcs1_ptr), NCRYPT_FLAGS(0)) } {
            if !pt.is_empty() { return Some((pt, format!("{tag}-PKCS1"))); }
        }
        // RAW
        if let Ok(pt) = unsafe { ncrypt_decrypt_call(k, chunk, None, NCRYPT_FLAGS(0)) } {
            if !pt.is_empty() { return Some((pt, format!("{tag}-RAW"))); }
        }
        None
    };

    // 策略 1: 整个 cbor (RSA-2048 = 256B 整块; 大于此则跳过)
    if cbor_bytes.len() == 256 || cbor_bytes.len() == 128 {
        if let Some((pt, lbl)) = try_chunk(cbor_bytes, "full") { return Some((pt, lbl)); }
    }

    // 策略 2: 多个固定窗口 (假设 EncData 位于 NgcIsoHeader 之后)
    let offsets: &[(usize, &str)] = &[
        (0, "start-256"),
        (0x4C, "after-NgcIso-256"),
        (0x64, "after-GUID-256"),
        (0x10, "skip16-256"),
        (0x20, "skip32-256"),
        (0x40, "skip64-256"),
    ];
    for (off, label) in offsets {
        if cbor_bytes.len() < *off + 64 { continue; }
        let end = (*off + 256).min(cbor_bytes.len());
        let chunk = &cbor_bytes[*off..end];
        if let Some((pt, lbl)) = try_chunk(chunk, label) {
            log.push(format!("  [{}-{}B] 解密成功 → {}B", lbl, chunk.len(), pt.len()));
            return Some((pt, lbl));
        }
    }
    // tail-256
    if cbor_bytes.len() >= 256 {
        let start = cbor_bytes.len() - 256;
        let chunk = &cbor_bytes[start..];
        if let Some((pt, lbl)) = try_chunk(chunk, "tail-256") {
            log.push(format!("  [{}-{}B] 解密成功 → {}B", lbl, chunk.len(), pt.len()));
            return Some((pt, lbl));
        }
    }

    // 策略 3: 16/32/64/128 字节切片 (短密文/MAC/tag)
    for &sz in &[16usize, 32, 48, 64, 128] {
        if cbor_bytes.len() >= sz {
            if let Some((pt, lbl)) = try_chunk(&cbor_bytes[..sz], &format!("head{sz}")) {
                log.push(format!("  [head-{}-{}] 解密成功 → {}B", sz, lbl, pt.len()));
                return Some((pt, lbl));
            }
        }
    }

    None
}

/// NCryptDecrypt 调用封装 (windows-rs 0.59 签名)
unsafe fn ncrypt_decrypt_call(
    kh: windows::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    input: &[u8],
    pad_info: Option<*const core::ffi::c_void>,
    flags: windows::Win32::Security::Cryptography::NCRYPT_FLAGS,
) -> Result<Vec<u8>, windows_core::Error> {
    use windows::Win32::Security::Cryptography::NCryptDecrypt;

    let mut sz = 0u32;
    NCryptDecrypt(kh, Some(input), pad_info, None, &mut sz, flags)?;

    if sz == 0 || sz > 131072 { return Err(windows_core::Error::from_win32()); }

    let mut out = vec![0u8; sz as usize];
    let mut actual = 0u32;
    NCryptDecrypt(kh, Some(input), pad_info, Some(&mut out), &mut actual, flags)?;
    out.truncate(actual as usize);
    Ok(out)
}

fn decrypt_success_msg(pt: &[u8]) -> String {
    let s = utf16_le_to_string(pt);
    if !s.is_empty() { format!("  OK OK OK decrypt OK! {}B plain: {:?}", pt.len(), s) }
    else { format!("  OK OK OK decrypt OK! {}B hex: {:02X?}", pt.len(), &pt[..pt.len().min(32)]) }
}

pub fn utf16_le_to_string(bytes: &[u8]) -> String {
    let el = bytes.len() & !1;
    if el == 0 { return String::new(); }
    let u16s: Vec<u16> = bytes[..el].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&u16s).trim_matches('\0').to_string()
}

// ─── Path B: NCryptExportKey 导出 RSA 私钥 + EncData 结构分析 ──────────

/// 导出 RSA 私钥 blob（尝试多种格式）
pub fn export_rsa_key_and_decrypt(
    _sid: &str,
    pin: &str,
) -> Result<(Vec<u8>, Vec<String>), (NgcError, Vec<String>)> {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenStorageProvider, NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject,
        NCryptOpenKey, NCryptSetProperty, NCryptExportKey,
        NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE, NCryptKeyName,
        NCRYPT_FLAGS, CERT_KEY_SPEC,
    };
    use windows_core::PCWSTR;

    let mut log = Vec::new();
    let prov_wide: Vec<u16> = "Microsoft Passport Key Storage Provider".encode_utf16().chain(Some(0)).collect();
    let mut prov = NCRYPT_PROV_HANDLE::default();

    unsafe {
        if let Err(e) = NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw(prov_wide.as_ptr()), 0) {
            return Err((NgcError::DecryptionFailed(format!("NCryptOpenStorageProvider: {e}")), log));
        }
    }

    let mut key_name: Option<String> = None;
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();
    loop {
        let mut kn: *mut NCryptKeyName = std::ptr::null_mut();
        match unsafe { NCryptEnumKeys(prov, PCWSTR::null(), &mut kn, &mut enum_state, NCRYPT_FLAGS(0)) } {
            Ok(()) => {
                if kn.is_null() { break; }
                unsafe {
                    let name = (*kn).pszName.to_string().unwrap_or_default();
                    if name.contains("uvkey") || (!name.contains("FIDO") && key_name.is_none()) {
                        let nw: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                        let mut tk = NCRYPT_KEY_HANDLE::default();
                        if NCryptOpenKey(prov, &mut tk, PCWSTR::from_raw(nw.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_ok() {
                            let h = NCRYPT_HANDLE(tk.0);
                            let alg = get_string_prop(h, "Algorithm Name").unwrap_or_default();
                            if alg.contains("RSA") || name.contains("uvkey") { key_name = Some(name); }
                            let _ = NCryptFreeObject(h);
                        }
                    }
                    let _ = NCryptFreeBuffer(kn as *mut core::ffi::c_void);
                }
            }
            Err(_) => break,
        }
    }
    if !enum_state.is_null() { unsafe { let _ = NCryptFreeBuffer(enum_state); } }

    let kn = match key_name {
        Some(n) => n,
        None => { unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
               return Err((NgcError::ContainerNotFound, vec!["未找到 RSA/uvkey 密钥".into()])); }
    };
    log.push(format!("导出密钥: {}", kn));

    let kw: Vec<u16> = kn.encode_utf16().chain(Some(0)).collect();
    let mut k = NCRYPT_KEY_HANDLE::default();
    match unsafe { NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(kw.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) } {
        Ok(()) => {},
        Err(e) => { unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
                   return Err((NgcError::DecryptionFailed(format!("NCryptOpenKey: {e}")), log)); }
    };

    let pin_bytes: Vec<u8> = pin.encode_utf16().chain(Some(0)).flat_map(|c| c.to_le_bytes()).collect();
    let scpin_w: Vec<u16> = "SmartcardPin".encode_utf16().chain(Some(0)).collect();

    match unsafe { NCryptSetProperty(NCRYPT_HANDLE(k.0), PCWSTR::from_raw(scpin_w.as_ptr()), &pin_bytes, NCRYPT_FLAGS(0)) } {
        Ok(()) => log.push("PIN 设置成功".into()),
        Err(e) => {
            unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0)); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
            return Err((NgcError::DecryptionFailed(format!("SetProperty: {e}")), log));
        }
    };

    // 尝试导出多种格式
    for bname in &["RSAPRIVATEBLOB", "RSAFULLPRIVATEBLOB", "OPAQUEBLOB", "PLAINTEXTKEYBLOB"] {
        log.push(format!("尝试 Export({})...", bname));
        let bn: Vec<u16> = bname.encode_utf16().chain(Some(0)).collect();

        let mut blob_size = 0u32;
        // NCryptExportKey(hKey, hExpKey=None, pwszBlobType, pParameter, pbOutput, pcbResult, dwFlags)
        match unsafe { NCryptExportKey(k, None, PCWSTR::from_raw(bn.as_ptr()), None, None, &mut blob_size, NCRYPT_FLAGS(0)) } {
            Ok(()) => {
                if blob_size > 0 && blob_size <= 1024 * 1024 {
                    let mut buf = vec![0u8; blob_size as usize];
                    let mut actual = 0u32;
                    match unsafe { NCryptExportKey(k, None, PCWSTR::from_raw(bn.as_ptr()), None, Some(&mut buf), &mut actual, NCRYPT_FLAGS(0)) } {
                        Ok(()) => {
                            buf.truncate(actual as usize);
                            log.push(format!("  OK {} -> {} bytes", bname, actual));
                            if actual >= 4 {
                                log.push(format!("  head64: {:02X?}", &buf[..actual.saturating_sub(60) as usize]));
                            }
                            unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0)); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
                            return Ok((buf, log));
                        }
                        Err(e) => { log.push(format!("  export err=0x{:08X}", e.code().0 as u32)); }
                    }
                } else { log.push(format!("  size abnormal: {}", blob_size)); }
            }
            Err(e) => { log.push(format!("  fail: 0x{:08X} ({})", e.code().0 as u32, e)); }
        }
    }

    unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0)); let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
    Err((NgcError::DecryptionFailed("所有 ExportKey 格式均失败。KSP 可能不允许导出私钥".into()), log))
}

/// EncData 结构分析 + CyberChef 输出（不做实际解密）
pub fn decrypt_with_exported_key(
    sid: &str,
    _key_blob: &[u8],
    pin: &str,
) -> Result<(Vec<u8>, Vec<String>), (NgcError, Vec<String>)> {
    use base64::Engine;
    let mut log = Vec::new();

    let ci = match super::container::find_ngc_container(sid) {
        Ok(c) => c,
        Err(e) => { let msg = format!("容器未找到: {}", e); return Err((e, vec![msg])); }
    };
    log.push(format!("容器: {}", ci.container_path.display()));

    let pj_path = ci.container_path.join("Protectors.json");
    let ps_str = match std::fs::read_to_string(&pj_path) {
        Ok(s) => s,
        Err(e) => return Err((NgcError::IoError(e), log)),
    };
    let pv: serde_json::Value = serde_json::from_str(&ps_str).unwrap_or(serde_json::Value::Null);

    let ec_b64 = pv.get("pin")
        .and_then(|p| p.get("secretStore"))
        .and_then(|s| s.get("encryptedCbor"))
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    if ec_b64.is_empty() {
        let keys = pv.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        return Err((NgcError::DecryptionFailed(format!("无 encryptedCbor 字段: [{}]", keys)), log));
    }

    let enc_bytes = match base64::engine::general_purpose::STANDARD.decode(&ec_b64) {
        Ok(b) => b,
        Err(e) => return Err((NgcError::DecryptionFailed(format!("b64 decode: {}", e)), log)),
    };

    log.push(format!("=== EncData 分析 ==="));
    log.push(format!("总大小: {} bytes", enc_bytes.len()));
    log.push(format!("Base64: {} chars", ec_b64.len()));

    // Header dump
    let hdrlen = enc_bytes.len().min(80);
    log.push(format!(""));
    log.push(format!("--- Header hex ({} bytes) ---", hdrlen));
    for (i, chunk) in enc_bytes[..hdrlen].chunks_exact(16).enumerate() {
        log.push(format!("  {:04X}: {}", i * 16,
            chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")));
    }

    // 已知偏移解析
    if enc_bytes.len() >= 20 {
        log.push(format!(""));
        log.push(format!("Algo(@12): 0x{:08X}", u32::from_le_bytes(enc_bytes[12..16].try_into().unwrap_or([0;4]))));
        log.push(format!("KeySz(@16): {} bits", u32::from_le_bytes(enc_bytes[16..20].try_into().unwrap_or([0;4]))));
    }
    if enc_bytes.len() >= 28 {
        log.push(format!("Ver(@24):  {}", u32::from_le_bytes(enc_bytes[24..28].try_into().unwrap_or([0;4]))));
    }
    if enc_bytes.len() >= 36 {
        log.push(format!("Flg(@28):  0x{:08X}", u32::from_le_bytes(enc_bytes[28..32].try_into().unwrap_or([0;4]))));
    }
    if enc_bytes.len() >= 60 {
        log.push(format!("Salt@1C:   {:02X?}", &enc_bytes[28..60]));
    }
    if enc_bytes.len() >= 76 {
        log.push(format!("IV@3C:     {:02X?}", &enc_bytes[60..76]));
    }

    log.push(format!(""));
    log.push(format!("=== Container ==="));
    log.push(format!("salt: {} B, rounds: {}", ci.salt.len(), ci.rounds));
    log.push(format!("pin: '{}'...", &pin[..pin.chars().take(4).count()]));

    // Base64 for CyberChef
    log.push(format!(""));
    log.push(format!("=== CyberChef Base64 Input ==="));
    for chunk in ec_b64.as_bytes().chunks(100) {
        log.push(std::str::from_utf8(chunk).unwrap_or("?").to_string());
    }

    Err((
        NgcError::DecryptionFailed("EncData 需要通过正确 KDF 解密。已输出完整分析数据。".to_string()), log
    ))
}

// ══════════════════════════════════════════════════════════════════
//  Phase 1 完整链路: NCryptExportKey → RSA私钥 → 解密vault → 明文密码
// ══════════════════════════════════════════════════════════════════

/// Phase 1 完整解密链:
///
/// 1. NCryptExportKey 导出 uvkey/RSA 私钥 BLOB（多种格式尝试）
/// 2. 用导出的私钥 RSA-OAEP(SHA256) 解密 EncData → 对称密钥
/// 3. 用对称密钥 + IV 解密 EncPassword → 明文密码
///
/// 支持多种 EncData 来源（按优先级）：
///   A) Protectors.json encryptedCbor → 内含 EncData+IV+EncPassword 结构
///   B) Vault .vcrd 文件 → Policy.vpol AES key 解密后得 NgcCredential 结构
///   C) [fallback] NCryptDecrypt 原地解密 — 当 KSP 拒绝 ExportKey 时
///   D) [modern] Keys/*.json 各密钥文件的 encryptedCbor 解密
pub fn phase1_ncrypt_full_chain(
    sid: &str,
    pin: &str,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    let mut log = Vec::new();
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    // ═══ Step 1: NCryptExportKey 导出 RSA 私钥 ═══
    l!("=== Phase 1: NCryptExportKey → RSA私钥 → 解密vault ===");
    l!("SID: {}", sid);
    l!("PIN: {}***", &pin[..pin.chars().take(2).count()]);

    let export_result = export_rsa_key_and_decrypt(sid, pin);
    let key_blob_opt: Option<(Vec<u8>, Vec<String>)> = match export_result {
        Ok((blob, elog)) => {
            for line in &elog { l!("[Export] {}", line); }
            let bt = detect_key_blob_type(&blob);
            l!("导出成功: {} bytes, type={}, head32: {:02X?}", blob.len(), bt, &blob[..blob.len().min(32)]);
            Some((blob, elog))
        }
        Err((e, elog)) => {
            l!("⚠️ ExportKey 失败 ({})，将走 NCryptDecrypt fallback 路径", e);
            for line in &elog { l!("[Export] {}", line); }
            None
        }
    };

    // ═══ Step 2: 定位容器 ═══
    let ci = match super::container::find_ngc_container(sid) {
        Ok(c) => c,
        Err(e) => {
            // 即使容器定位失败，仍然可以尝试 Path C (NCryptDecrypt 不依赖容器)
            l!("容器定位失败: {}, 但仍尝试 NCryptDecrypt fallback", e);
            let (pt, decrypt_log) = try_phase1_ncrypt_decrypt_fallback(sid, pin, None)?;
            log.extend(decrypt_log);
            return Ok((pt, log));
        }
    };
    l!("容器: {}", ci.container_path.display());

    // ═══ 如果有导出的 key_blob，走标准路径 A/B/D ═══
    if let Some((ref key_blob, _)) = key_blob_opt {
        // --- 路径 A: Protectors.json encryptedCbor ---
        let result_a = try_phase1_from_protectors(key_blob, &ci, &mut log);
        if result_a.is_ok() { return result_a; }

        // --- 路径 B: Vault .vcrd 文件 (现代化: 不依赖 ci.vcrd_path) ---
        let result_b = try_phase1_from_vault_modern(key_blob, &ci, sid, &mut log);
        if result_b.is_ok() { return result_b; }

        // --- 路径 D: Keys/*.json 加密Cbor解密 ---
        let result_d = try_phase1_from_keys_dir(key_blob, &ci, &mut log);
        if result_d.is_ok() { return result_d; }
    }

    // ═══ Path C: NCryptDecrypt 原地解密 (fallback) ═══
    l!("\n--- 路径 C: NCryptDecrypt 原地解密 fallback ---");
    match try_phase1_ncrypt_decrypt_fallback(sid, pin, Some(&ci)) {
        Ok((pwd, mut decrypt_log)) => {
            log.append(&mut decrypt_log);
            return Ok((pwd, log));
        }
        Err((_e, mut decrypt_log)) => {
            log.extend(decrypt_log);
            // 继续到最终错误返回
        }
    }

    Err((NgcError::DecryptionFailed(
        "Phase 1 所有路径均失败(A/B/C/D)：无法解密出明文密码".to_string()
    ), log))
}

// ─── BLOB 类型检测 ──────────────────────────────────────────────

fn detect_key_blob_type(blob: &[u8]) -> &'static str {
    if blob.len() < 4 { return "未知(过短)" };
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    match magic {
        0x32485352 => "RSAPRIVATE_BLOB ('RSA2')", // 'R','S','A','2'
        0x33535242 => "RSAFULLPRIVATEBLOB ('BRS3')",
        0x4D424F50 => "OPAQUEBLOB ('POBM')",
        0x584B4C50 => "PLAINTEXTKEYBLOB ('PLKX')",
        0x31484B50 => "PLAINTEXTKEYBLOB (PKH1)",
        _ => format!("未知(magic=0x{:08X})", magic).leak(),
    }
}

// ─── 路径 A: 从 Protectors.json encryptedCbor 解密 ───────────

fn try_phase1_from_protectors(
    key_blob: &[u8],
    ci: &super::NgcContainerInfo,
    log: &mut Vec<String>,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    use base64::Engine;
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    l!("\n--- 路径 A: Protectors.json encryptedCbor ---");

    let pj_path = ci.container_path.join("Protectors.json");
    if !pj_path.exists() {
        l!("Protectors.json 不存在，跳过路径 A");
        return Err((NgcError::ContainerNotFound, vec![]));
    }

    let ps_str = std::fs::read_to_string(&pj_path)
        .map_err(|e| (NgcError::IoError(e), vec![]))?;
    let pv: serde_json::Value = serde_json::from_str(&ps_str)
        .map_err(|e| (NgcError::DecryptionFailed(format!("JSON: {}", e)), vec![]))?;

    let ec_b64 = pv.get("pin")
        .and_then(|p| p.get("secretStore"))
        .and_then(|s| s.get("encryptedCbor"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if ec_b64.is_empty() {
        l!("无 encryptedCbor 字段");
        return Err((NgcError::ProtectorNotFound, vec![]));
    }

    let enc_bytes = match base64::engine::general_purpose::STANDARD.decode(ec_b64) {
        Ok(b) => b,
        Err(e) => { l!("b64 decode 失败: {}", e); return Err((NgcError::DecryptionFailed(format!("b64: {}", e)), vec![])); },
    };
    l!("encryptedCbor: {} bytes", enc_bytes.len());

    // 尝试解析为 EncData+IV+EncPassword 结构
    if let Ok(pwd) = parse_and_decrypt_enc_cbor(key_blob, &enc_bytes, log) {
        Ok((pwd, vec![]))
    } else {
        l!("路径 A: EncData 结构解析/解密失败");
        Err((NgcError::InvalidPin, vec![]))
    }
}

// ─── 路径 B (现代化): 从 Vault .vcrd 解密 ───────────────────────────────
//
// 现代格式(container.rs 设 vcrd_path=空) 也尝试从 Vault 根目录枚举 .vcrd:
//   - %WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault\<schema>\
//   - 枚举所有 schema GUID 目录找 NGC 相关的 .vcrd

fn try_phase1_from_vault_modern(
    key_blob: &[u8],
    ci: &super::NgcContainerInfo,
    sid: &str,
    log: &mut Vec<String>,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    l!("\n--- 路径 B(现代化): Vault .vcrd 文件 ---");

    // 策略 1: 使用 container.rs 提供的传统 vcrd/pol 路径（如果有）
    let has_vcrd = !ci.vcrd_path.as_os_str().is_empty();
    let has_pol = !ci.pol_path.as_os_str().is_empty();

    if has_vcrd && has_pol {
        l!("使用容器自带的 vault 路径:");
        l!("  .vcrd: {}", ci.vcrd_path.display());
        l!("  .pol : {}", ci.pol_path.display());
        return try_vault_decrypt_with_paths(key_blob, &ci.vcrd_path, &ci.pol_path, log);
    }

    // 策略 2: 现代格式 — 直接从 Vault 根目录枚举
    l!("现代格式(vcrd_path为空)，尝试直接枚举 Vault 目录...");

    // 尝试多个 Vault 根目录位置
    let vault_roots: Vec<&str> = vec![
        // SYSTEM profile 下的 Vault (Unlock.exe 运行身份)
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault",
    ];

    for vault_root in &vault_roots {
        let vp = std::path::Path::new(vault_root);
        if !vp.is_dir() { l!("  Vault根不存在: {}", vault_root); continue; }
        l!("  扫描 Vault 根: {}", vault_root);

        if let Ok(entries) = std::fs::read_dir(vp) {
            for entry in entries.flatten() {
                let schema_dir = entry.path();
                if !schema_dir.is_dir() { continue; }
                let schema_name = schema_dir.file_name()
                    .and_then(|n| n.to_str()).unwrap_or("?");

                // 只检查 GUID 格式的目录 (或已知 NGC schema)
                let is_guid = schema_name.starts_with('{') && schema_name.len() == 36;
                if !is_guid { continue; }

                l!("  Schema: {}", schema_name);

                // 找 Policy.vpol 和 .vcrd
                let pol_path = schema_dir.join("Policy.vpol");
                if !pol_path.exists() { continue; }

                // 找 .vcrd 文件
                if let Ok(v_entries) = std::fs::read_dir(&schema_dir) {
                    for ve in v_entries.flatten() {
                        let vp = ve.path();
                        if vp.extension().map_or(false, |e| e == "vcrd") {
                            l!("  找到 .vcrd: {}", vp.display());
                            if let Ok(result) = try_vault_decrypt_with_paths(key_blob, &vp, &pol_path, log) {
                                return Ok(result);
                            }
                        }
                    }
                }
            }
        }
    }

    // 策略 3: 尝试按 SID 在用户 Profile 下查找 Vault
    if let Some(user_vault) = find_user_vault_by_sid(sid) {
        l!("  尝试用户专属 Vault: {}", user_vault.display());
        if let Ok(entries) = std::fs::read_dir(&user_vault) {
            for entry in entries.flatten() {
                let schema_dir = entry.path();
                if !schema_dir.is_dir() { continue; }
                let pol = schema_dir.join("Policy.vpol");
                if !pol.exists() { continue; }
                if let Ok(ves) = std::fs::read_dir(&schema_dir) {
                    for ve in ves.flatten() {
                        let vp = ve.path();
                        if vp.extension().map_or(false, |e| e == "vcrd") {
                            if let Ok(result) = try_vault_decrypt_with_paths(key_blob, &vp, &pol, log) {
                                return Ok(result);
                            }
                        }
                    }
                }
            }
        }
    }

    l!("所有 Vault 路径均未找到或解密失败");
    Err((NgcError::Unsupported("无可用 vault 路径".into()), vec![]))
}

/// 用给定路径执行完整的 vault 解密链
fn try_vault_decrypt_with_paths(
    key_blob: &[u8],
    vcrd_path: &std::path::Path,
    pol_path: &std::path::Path,
    log: &mut Vec<String>,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    if !vcrd_path.exists() { l!("  .vcrd 不存在"); return Err((NgcError::IoError(std::io::ErrorKind::NotFound.into()), vec![])); }
    if !pol_path.exists() { l!("  .pol 不存在"); return Err((NgcError::IoError(std::io::ErrorKind::NotFound.into()), vec![])); }

    match super::vault::decrypt_vault_password(key_blob, vcrd_path, pol_path) {
        Ok(password) => {
            l!("Vault 解密成功!");
            l!("密码长度: {} chars", password.chars().count());
            Ok((password, vec![]))
        }
        Err(e) => { l!("Vault 解密失败: {}", e); Err((e, vec![])) }
    }
}

// ─── 路径 C: NCryptDecrypt 原地解密 fallback ──────────────────────────
//
// 当 NCryptExportKey 被 KSP 拒绝(NTE_PERM)时，
// 改用已实现的 try_ncrypt_decrypt_vault() 直接用 NCryptDecrypt 解密 encryptedCbor 各区域。
// 私钥不离开 KSP，由 KSP 内部完成 RSA 解密操作。

fn try_phase1_ncrypt_decrypt_fallback(
    sid: &str,
    pin: &str,
    _ci: Option<&super::NgcContainerInfo>,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    let mut log = Vec::new();
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    l!("\n--- 路径 C: NCryptDecrypt 原地解密 ---");

    match try_ncrypt_decrypt_vault(sid, pin) {
        Ok((decrypted_bytes, mut decrypt_log)) => {
            l!("NCryptDecrypt 成功! {} bytes", decrypted_bytes.len());

            // 分析解密结果：是否是 UTF-16LE 密码？
            let s = utf16_le_to_string(&decrypted_bytes);
            if !s.is_empty() && is_plaintext_password(&s) {
                l!("明文密码: [{} chars] '{}'", s.chars().count(), s);
                return Ok((s, decrypt_log));
            }

            // 如果不是纯文本，可能是二进制凭据或中间密钥
            l!("解密结果非纯文本(hex前64B): {:02X?}", &decrypted_bytes[..decrypted_bytes.len().min(64)]);
            // 仍然返回——上层可能需要这个中间结果做进一步解密
            Ok((format!("<ncrypt_decrypted:{}B>", decrypted_bytes.len()), decrypt_log))
        }
        Err((e, mut err_log)) => {
            l!("NCryptDecrypt 失败: {}", e);
            Err((e, err_log))
        }
    }
}

/// 检查字符串是否像明文字符(可打印ASCII/CJK/常见符号)
fn is_plaintext_password(s: &str) -> bool {
    if s.len() < 1 { return false; }
    s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace() || ('\u{4e00}'..='\u{9fff}').contains(&c) || ('\u{3000}'..='\u{303f}').contains(&c))
}

// ─── 路径 D: Keys/*.json 加密 Cbor 解密 ──────────────────────────────
//
// 现代 NGC 容器的 Keys/ 目录下有多个 *.json 密钥文件，
// 每个 file 的 `encrypted.encryptedCbor` 字段包含 CBOR 加密的密钥数据。
// 记录这些文件的结构信息，帮助调试分析。

fn try_phase1_from_keys_dir(
    _key_blob: &[u8],
    ci: &super::NgcContainerInfo,
    log: &mut Vec<String>,
) -> Result<(String, Vec<String>), (NgcError, Vec<String>)> {
    use base64::Engine;
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    l!("\n--- 路径 D: Keys/*.json 加密Cbor 分析 ---");

    let keys_dir = ci.container_path.join("Keys");
    if !keys_dir.is_dir() {
        l!("Keys 目录不存在: {}", keys_dir.display());
        return Err((NgcError::Unsupported("Keys目录不存在".into()), vec![]));
    }

    let entries = match std::fs::read_dir(&keys_dir) {
        Ok(e) => e,
        Err(e) => { l!("无法读取 Keys 目录: {}", e); return Err((NgcError::IoError(e), vec![])); }
    };

    let mut key_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |e| e == "json") {
            key_files.push(path.clone());
        }
    }

    l!("找到 {} 个 Key JSON 文件", key_files.len());
    if key_files.is_empty() { return Err((NgcError::ProtectorNotFound, vec![])); }

    for kf in &key_files {
        let fname = kf.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        l!("\n  [Key] {}", fname);

        let json_str = match std::fs::read_to_string(kf) {
            Ok(s) => s,
            Err(e) => { l!("  读取失败: {}", e); continue; }
        };

        let key_json: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(e) => { l!("  JSON解析失败: {}", e); continue; }
        };

        // 打印文件结构概览
        if let Some(obj) = key_json.as_object() {
            let top_keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
            l!("  顶层字段: {:?}", top_keys);

            if let Some(alg) = key_json.get("alg").and_then(|v| v.as_str()) { l!("  alg={}", alg); }
            if let Some(bits) = key_json.get("bits").and_then(|v| v.as_u64()) { l!("  bits={}", bits); }
            if let Some(ct) = key_json.get("cacheType").and_then(|v| v.as_u64()) { l!("  cacheType={}", ct); }
        }

        // 提取 encrypted.encryptedCbor
        let ec_b64 = key_json.get("encrypted")
            .and_then(|e| e.get("encryptedCbor"))
            .and_then(|v| v.as_str())
            .or_else(|| key_json.get("encryptedCbor").and_then(|v| v.as_str()));

        let ec_b64 = match ec_b64 {
            Some(b) => b,
            None => { l!("  无 encryptedCbor 字段"); continue; }
        };

        l!("  encryptedCbor: {} chars(base64)", ec_b64.len());

        let enc_bytes = match base64::engine::general_purpose::STANDARD.decode(ec_b64) {
            Ok(b) => b,
            Err(e) => { l!("  base64解码失败: {}", e); continue; }
        };
        l!("  decoded: {} bytes, head32: {:02X?}", enc_bytes.len(), &enc_bytes[..enc_bytes.len().min(32)]);

        // CBOR header analysis
        if enc_bytes.len() >= 2 {
            let first_byte = enc_bytes[0];
            l!("  CBOR首字节: 0x{:02X} (type={}, arg={})", first_byte, first_byte >> 5, first_byte & 0x1F);
            // CBOR type 4=array, 5=map, 6=tag, 7=simple/primitive
        }
    }

    l!("路径 D: Keys/*.json 是密钥材料，不含明文密码");
    Err((NgcError::DecryptionFailed("Keys中的加密Cbor是密钥材料而非密码".into()), vec![]))
}

// ═══ EncData 结构解析完成 (见下方增强版) ═══

fn parse_and_decrypt_enc_cbor(
    rsa_key_blob: &[u8],
    raw_bytes: &[u8],
    log: &mut Vec<String>,
) -> Result<String, NgcError> {
    use super::dpapi::{rsa_oaep_decrypt, aes256_cbc_decrypt};
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    l!("raw_bytes 总长: {}", raw_bytes.len());

    // 可能的前置 header: 尝试跳过不同长度的头部
    for skip in 0u32..=4 {
        if (skip as usize) + 4 > raw_bytes.len() { continue; }

        let mut off = skip as usize;

        // EncData length
        let enc_data_len = u32::from_le_bytes([
            raw_bytes[off], raw_bytes[off+1], raw_bytes[off+2], raw_bytes[off+3]
        ]) as usize;
        off += 4;

        // 合理性检查
        if enc_data_len < 64 || enc_data_len > 1024 { continue; }
        if off + enc_data_len > raw_bytes.len() { continue; }

        // IV length
        let iv_area = off + enc_data_len;
        if iv_area + 4 > raw_bytes.len() { continue; }
        let iv_len = u32::from_le_bytes([
            raw_bytes[iv_area], raw_bytes[iv_area+1], raw_bytes[iv_area+2], raw_bytes[iv_area+3]
        ]) as usize;
        if iv_len != 16 && iv_len != 12 { continue; } // 16=CBC, 12=GCM nonce

        // IV data
        let iv_off = iv_area + 4;
        if iv_off + iv_len > raw_bytes.len() { continue; }

        // EncPassword length
        let pwd_len_off = iv_off + iv_len;
        if pwd_len_off + 4 > raw_bytes.len() { continue; }
        let enc_pwd_len = u32::from_le_bytes([
            raw_bytes[pwd_len_off], raw_bytes[pwd_len_off+1],
            raw_bytes[pwd_len_off+2], raw_bytes[pwd_len_off+3]
        ]) as usize;
        if enc_pwd_len == 0 || enc_pwd_len > 4096 { continue; }

        let pwd_off = pwd_len_off + 4;
        if pwd_off + enc_pwd_len > raw_bytes.len() { continue; }

        // 提取各段
        let enc_data = &raw_bytes[off..off + enc_data_len];
        let iv = &raw_bytes[iv_off..iv_off + iv_len];
        let enc_pwd = &raw_bytes[pwd_off..pwd_off + enc_pwd_len];

        l!("结构匹配! skip={}, EncData={}B, IV={}B, EncPwd={}B",
            skip, enc_data_len, iv_len, enc_pwd_len);

        // Step 1: RSA-OAEP 解密 EncData → AES 密钥
        l!("RSA-OAEP 解密 EncData ({}B)...", enc_data.len());
        let aes_key = match rsa_oaep_decrypt(rsa_key_blob, enc_data) {
            Ok(k) => { l!("RSA 解密成功: {}B (预期 32B AES-256)", k.len()); k }
            Err(e) => { l!("RSA-OAEP 失败: {}, 尝试下一个偏移...", e); continue; }
        };

        // Step 2: AES-CBC/GCM 解密 EncPassword
        l!("AES 解密 EncPassword ({}B)...", enc_pwd.len());
        let ct_aligned = if iv_len == 16 {
            // CBC 需要 16 字节对齐
            let aligned_len = enc_pwd_len & !15;
            if aligned_len < 16 { continue; }
            &enc_pwd[..aligned_len]
        } else {
            enc_pwd
        };

        if iv_len == 16 {
            match aes256_cbc_decrypt(&aes_key, iv, ct_aligned) {
                Ok(pt) => {
                    let s = utf16_le_to_string(&pt);
                    if !s.is_empty() {
                        l!("🎉🎉🎉 明文密码: [{} chars] '{}'", s.chars().count(), s);
                        return Ok(s);
                    }
                    l!("AES-CBC 解密成功但结果非 UTF-16LE 文本, hex: {:02X?}", &pt[..pt.len().min(32)]);
                    // 仍然返回——可能是二进制凭证
                    return Ok(format!("<binary:{}B>", pt.len()));
                }
                Err(e) => { l!("AES-CBC 失败: {}", e); }
            }
        } else if iv_len == 12 {
            // GCM 尝试
            match super::dpapi::aes256_gcm_decrypt(&aes_key, iv, enc_pwd) {
                Ok(pt) => {
                    let s = utf16_le_to_string(&pt);
                    l!("AES-GCM 解密成功: {}B, text='{}'", pt.len(), s);
                    return Ok(if s.is_empty() { format!("<gcm_binary:{}B>", pt.len()) } else { s });
                }
                Err(e) => { l!("AES-GCM 失败: {}", e); }
            }
        }
    }

    l!("所有偏移均未匹配 EncData+IV+EncPassword 结构");
    Err(NgcError::DecryptionFailed("encryptedCbor 结构不匹配".into()))
}

// ─── SID / Vault 辅助函数 ──────────────────────────────────────

/// 根据 SID 查找用户的 Vault 目录
fn find_user_vault_by_sid(sid: &str) -> Option<std::path::PathBuf> {
    let key = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{}", sid);
    if let Some(pp) = read_reg_sz(&key, "ProfileImagePath") {
        let vp = std::path::Path::new(&pp).join(r"AppData\Local\Microsoft\Vault");
        if vp.is_dir() { return Some(vp); }
    }
    std::env::var("LOCALAPPDATA").ok().map(|p| std::path::Path::new(&p).join("Microsoft").join("Vault"))
}

/// 读取注册表 REG_SZ
fn read_reg_sz(key_path: &str, value_name: &str) -> Option<String> {
    use windows::Win32::System::Registry::*;
    use windows_core::PCWSTR;
    unsafe {
        let kw: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
        let vw: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hk = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(kw.as_ptr()), None, KEY_READ, &mut hk).is_err() { return None; }
        let mut dl = 0u32; let mut dt = REG_SZ;
        let _ = RegQueryValueExW(hk, PCWSTR::from_raw(vw.as_ptr()), None, Some(&mut dt), None as Option<*mut u8>, Some(&mut dl));
        if dl == 0 { let _ = RegCloseKey(hk); return None; }
        let mut buf = vec![0u16; (dl/2) as usize];
        let r = RegQueryValueExW(hk, PCWSTR::from_raw(vw.as_ptr()), None, None, Some(buf.as_mut_ptr() as *mut u8), Some(&mut dl));
        let _ = RegCloseKey(hk);
        if r.is_ok() { Some(String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string()) } else { None }
    }
}
