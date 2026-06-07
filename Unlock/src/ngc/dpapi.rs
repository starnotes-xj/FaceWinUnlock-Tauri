//! Win32 DPAPI / CNG 薄封装
//!
//! Unlock.exe 以 SYSTEM 身份运行，可直接调用：
//! - `CryptUnprotectData` — DPAPI 解密（用 PIN 派生的 entropy）
//! - `BCrypt*` — CNG RSA OAEP 解密操作
//!
//! 相比于离线重写 DPAPI masterkey 解析，这里直接使用活体 SYSTEM
//! 的加密 API，无需自行推导 masterkey。
//!
//! # RSA 私钥文件
//!
//! NGC RSA 私钥以 DPAPI 加密 blob 形式存储在：
//! ```text
//! %WINDIR%\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys\<key_id>
//! ```
//!
//! 解密后得到 CNG `BCRYPT_RSAKEY_BLOB` 格式的私钥（可由
//! `BCryptImportKeyPair` 直接导入）。

use std::path::Path;

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    // DPAPI
    CryptUnprotectData, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_UI_FORBIDDEN,
    // BCrypt algorithm provider
    BCryptOpenAlgorithmProvider, BCryptCloseAlgorithmProvider,
    BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_RSA_ALGORITHM,
    // BCrypt key import
    BCryptImportKeyPair, BCryptDestroyKey,
    BCRYPT_KEY_HANDLE,
    BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAFULLPRIVATE_BLOB,
    // BCrypt OAEP decrypt
    BCryptDecrypt, BCRYPT_PAD_OAEP,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM,
};

use super::NgcError;

// ─── DPAPI decrypt ─────────────────────────────────────────────────────────────

/// 使用 DPAPI 解密密文（带 entropy）。
///
/// # Arguments
/// * `data` — DPAPI 加密的数据
/// * `entropy` — PIN 派生的 entropy（用作 DPAPI 的 optional entropy）
///
/// # Returns
/// 解密后的明文数据
pub fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };

    let entropy_blob = if entropy.is_empty() {
        None
    } else {
        Some(CRYPT_INTEGER_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        })
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // CryptUnprotectData 返回 windows_core::Result<()>
    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            None, // ppszDataDescr — 不需要描述
            entropy_blob.as_ref().map(|b| b as *const _), // pOptionalEntropy
            None, // pvReserved
            None, // pPromptStruct — 无 UI
            CRYPTPROTECT_UI_FORBIDDEN, // dwFlags — 禁止 UI 弹窗
            &mut data_out,
        )
    };

    if result.is_err() {
        return Err(NgcError::DecryptionFailed(
            "DPAPI 解密失败，PIN 可能错误".to_string(),
        ));
    }

    // 复制解密后的数据
    let plaintext = unsafe {
        if data_out.pbData.is_null() || data_out.cbData == 0 {
            return Err(NgcError::DecryptionFailed(
                "DPAPI 返回空数据".to_string(),
            ));
        }
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };

    // 释放 DPAPI 分配的内存（CryptUnprotectData 用 LocalAlloc 分配）
    unsafe {
        let _ = LocalFree(Some(HLOCAL(data_out.pbData as *mut _)));
    }

    Ok(plaintext)
}

// ─── RSA key DPAPI decrypt ─────────────────────────────────────────────────────

/// 从文件读取并 DPAPI 解密 RSA 密钥。
///
/// RSA 私钥以 DPAPI 加密 blob 形式存储在：
/// `%WINDIR%\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys\<key_id>`
///
/// # Arguments
/// * `blob_path` — 密钥 blob 文件路径
/// * `entropy` — PIN 派生的 entropy
///
/// # Returns
/// 解密后的 RSA 私钥数据（CNG `BCRYPT_RSAKEY_BLOB` 格式）
pub fn unprotect_rsa_key(blob_path: &Path, entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    let encrypted_blob = std::fs::read(blob_path)?;
    dpapi_unprotect(&encrypted_blob, entropy)
}

// ─── RSA OAEP decrypt ──────────────────────────────────────────────────────────

/// 使用 CNG `BCryptDecrypt` 进行 RSA-OAEP 解密。
///
/// # Arguments
/// * `key_blob` — DPAPI 解密后的 RSA 私钥（CNG `BCRYPT_RSAKEY_BLOB` 格式，
///   即 `BCRYPT_RSAPRIVATE_BLOB` 或 `BCRYPT_RSAFULLPRIVATE_BLOB`）
/// * `ciphertext` — OAEP 加密的密文（RSA 模长长度，2048-bit=256 字节）
///
/// # Returns
/// RSA OAEP 解密后的明文（NGC vault 中为 32 字节 AES-256 密钥）
pub fn rsa_oaep_decrypt(key_blob: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NgcError> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    // ── Step 1: 打开 RSA 算法提供程序 ────────────────────────────────────
    let mut alg_handle = BCRYPT_ALG_HANDLE::default();
    if unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_RSA_ALGORITHM,
            None, // pszImplementation — 使用系统默认实现
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
    }
    .is_err()
    {
        return Err(NgcError::DecryptionFailed(
            "BCryptOpenAlgorithmProvider 失败".to_string(),
        ));
    }

    // ── Step 2: 导入 RSA 私钥 ────────────────────────────────────────────
    // NGC 密钥可能使用 RSAPRIVATEBLOB（含私钥指数 d）或
    // RSAFULLPRIVATEBLOB（含 CRT 参数 p/q/dp/dq/inverseQ）。
    // 优先尝试标准 RSAPRIVATEBLOB，失败时回退到 RSAFULLPRIVATEBLOB。
    let mut key_handle = BCRYPT_KEY_HANDLE::default();
    let key_imported = {
        let r1 = unsafe {
            BCryptImportKeyPair(
                alg_handle,
                None, // hImportKey — 无包装密钥
                BCRYPT_RSAPRIVATE_BLOB,
                &mut key_handle,
                key_blob,
                0, // dwFlags
            )
        };
        if r1.is_ok() {
            true
        } else {
            let r2 = unsafe {
                BCryptImportKeyPair(
                    alg_handle,
                    None,
                    BCRYPT_RSAFULLPRIVATE_BLOB,
                    &mut key_handle,
                    key_blob,
                    0,
                )
            };
            r2.is_ok()
        }
    };

    if !key_imported {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
        }
        return Err(NgcError::DecryptionFailed(
            "BCryptImportKeyPair 失败：无法导入 RSA 私钥（尝试了 \
             RSAPRIVATEBLOB 和 RSAFULLPRIVATEBLOB）"
                .to_string(),
        ));
    }

    // 共用清理闭包：先销毁 key，再关闭 provider
    let cleanup = || unsafe {
        let _ = BCryptDestroyKey(key_handle);
        let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    // ── Step 3: OAEP 解密 ─────────────────────────────────────────────────
    // NGC 的 OAEP padding 使用 SHA-256 哈希算法。BCRYPT_OAEP_PADDING_INFO
    // 对应于 Win32 BCRYPT_OAEP_PADDING_INFO 结构体。
    let padding_info = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(), // 无标签（标准 OAEP 行为）
        cbLabel: 0,
    };

    // 3a: 查询输出缓冲区大小。
    //     首次调用 pbOutput=None，BCryptDecrypt 返回
    //     STATUS_BUFFER_TOO_SMALL 并通过 pcbResult 返回所需大小。
    let mut result_size = 0u32;
    let _ = unsafe {
        BCryptDecrypt(
            key_handle,
            Some(ciphertext), // pbInput — 待解密密文
            Some(&padding_info as *const _ as *const core::ffi::c_void), // pPaddingInfo
            None,  // pbIV — OAEP 无需 IV
            None,  // pbOutput — null 以查询所需大小
            &mut result_size, // pcbResult
            BCRYPT_PAD_OAEP, // dwFlags
        )
    };

    if result_size == 0 || result_size > 4096 {
        cleanup();
        return Err(NgcError::DecryptionFailed(format!(
            "BCryptDecrypt 查询输出大小失败（size={}）",
            result_size
        )));
    }

    // 3b: 实际解密
    let mut output = vec![0u8; result_size as usize];
    let mut actual_size = 0u32;
    if unsafe {
        BCryptDecrypt(
            key_handle,
            Some(ciphertext),
            Some(&padding_info as *const _ as *const core::ffi::c_void),
            None,
            Some(&mut output), // pbOutput — 解密缓冲区
            &mut actual_size,
            BCRYPT_PAD_OAEP,
        )
    }
    .is_err()
    {
        cleanup();
        return Err(NgcError::DecryptionFailed(
            "BCryptDecrypt OAEP 解密失败".to_string(),
        ));
    }

    output.truncate(actual_size as usize);

    // ── Cleanup ───────────────────────────────────────────────────────────
    cleanup();

    Ok(output)
}

// ─── AES-256-GCM decrypt (modern NgcIso) ────────────────────────────────────────

/// AES-256-GCM 解密（现代 NgcIsoHeader 格式，Win11 微软账户）。
///
/// NgcIsoHeader.iv[..12] = Nonce (GCM standard 96-bit)。
/// Tag = 密文末尾 16 bytes。
/// 解密失败= PIN 错误（GCM 认证失败）。
pub fn aes256_gcm_decrypt(key: &[u8], nonce12: &[u8], ct_with_tag: &[u8]) -> Result<Vec<u8>, NgcError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    if key.len() != 32 { return Err(NgcError::DecryptionFailed("GCM key len != 32".to_string())); }
    if nonce12.len() < 12 { return Err(NgcError::DecryptionFailed("GCM nonce < 12".to_string())); }
    if ct_with_tag.len() < 16 { return Err(NgcError::DecryptionFailed("GCM ct too short".to_string())); }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| NgcError::DecryptionFailed("Aes256Gcm init".to_string()))?;
    let nonce = Nonce::from_slice(&nonce12[..12]);
    cipher.decrypt(nonce, ct_with_tag)
        .map_err(|_| NgcError::InvalidPin)
}

// ─── AES-256-CBC decrypt ───────────────────────────────────────────────────────

/// AES-256-CBC 解密（用于 vault 数据解密）。
///
/// 使用纯 Rust `aes` + `cbc` crate 实现，避免额外 CNG 调用。
///
/// # Arguments
/// * `key` — 32 字节 AES-256 密钥
/// * `iv` — 16 字节初始向量
/// * `ciphertext` — AES-CBC 加密的密文（16 字节对齐，含 PKCS7 padding）
///
/// # Returns
/// 移除 PKCS7 padding 后的明文
pub fn aes256_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NgcError> {
    use aes::cipher::KeyIvInit;

    // ── 参数验证 ──────────────────────────────────────────────────────────
    if key.len() != 32 {
        return Err(NgcError::DecryptionFailed(format!(
            "AES-256 密钥长度不正确: {}（应为 32）",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(NgcError::DecryptionFailed(format!(
            "AES IV 长度不正确: {}（应为 16）",
            iv.len()
        )));
    }
    if ciphertext.len() < 16 || ciphertext.len() % 16 != 0 {
        return Err(NgcError::DecryptionFailed(
            "密文长度不是 16 的倍数（需要 PKCS7 padding）".to_string(),
        ));
    }

    // ── 创建解密器并逐块解密 ──────────────────────────────────────────────
    type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

    let mut decryptor = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|_| NgcError::DecryptionFailed("创建 AES 解密器失败".to_string()))?;

    let mut buf = ciphertext.to_vec();

    use aes::cipher::BlockDecryptMut;
    for chunk in buf.chunks_exact_mut(16) {
        let block = aes::cipher::Block::<aes::Aes256>::from_mut_slice(chunk);
        decryptor.decrypt_block_mut(block);
    }

    // ── 校验并移除 PKCS7 padding ───────────────────────────────────────
    // 关键：必须严格校验 padding 合法性，否则任何密钥都会"解密成功"，
    // 使 PIN 验证形同虚设。历史 bug：旧实现只读最后一字节并截断、永远返回
    // Ok，导致 --ngc-smoke-test / --ngc-keys 全是假阳性（任意 PIN 都"通过"）。
    let pad_len = *buf.last().ok_or_else(|| {
        NgcError::DecryptionFailed("解密结果为空".to_string())
    })? as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > buf.len() {
        return Err(NgcError::DecryptionFailed(format!(
            "PKCS7 padding 非法 (pad_len={pad_len})，密钥/IV/PIN 很可能错误"
        )));
    }
    if buf[buf.len() - pad_len..].iter().any(|&b| b as usize != pad_len) {
        return Err(NgcError::DecryptionFailed(
            "PKCS7 padding 校验失败（PIN 错误或格式不符）".to_string(),
        ));
    }
    buf.truncate(buf.len() - pad_len);

    Ok(buf)
}

/// AES-256-CBC 解密但**不校验/不移除** padding，返回原始解密块。
///
/// 用于格式逆向调试：当 PKCS7 校验失败时，仍可拿到原始明文块观察结构，
/// 判断是 PIN 错误、偏移错误、还是根本不是 AES-CBC+PKCS7。
pub fn aes256_cbc_decrypt_raw(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NgcError> {
    use aes::cipher::KeyIvInit;
    if key.len() != 32 || iv.len() != 16 || ciphertext.len() < 16 || ciphertext.len() % 16 != 0 {
        return Err(NgcError::DecryptionFailed("AES 参数非法".to_string()));
    }
    type Aes256Cbc = cbc::Decryptor<aes::Aes256>;
    let mut decryptor = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|_| NgcError::DecryptionFailed("创建 AES 解密器失败".to_string()))?;
    let mut buf = ciphertext.to_vec();
    use aes::cipher::BlockDecryptMut;
    for chunk in buf.chunks_exact_mut(16) {
        let block = aes::cipher::Block::<aes::Aes256>::from_mut_slice(chunk);
        decryptor.decrypt_block_mut(block);
    }
    Ok(buf)
}

// ─── CNG key enumeration (诊断) ─────────────────────────────────────────────

/// 枚举指定 CNG/KSP 提供程序下的所有密钥名与算法。
///
/// 用于确认 Windows Hello FIDO/passkey 私钥是否可经 CNG 直接访问。
/// 若 FIDO 密钥出现在 "Microsoft Passport Key Storage Provider" 或
/// "Microsoft Platform Crypto Provider" 中，则签名应走 NCrypt 原地签名
/// （NCryptOpenKey + SmartcardPin=SignPin + NCryptSignHash），
/// 而不是逆向解密文件格式。
pub fn enum_cng_keys(provider_name: &str) -> Result<Vec<(String, String)>, NgcError> {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenStorageProvider, NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject,
        NCRYPT_PROV_HANDLE, NCRYPT_HANDLE, NCryptKeyName, NCRYPT_FLAGS,
    };
    use windows_core::PCWSTR;

    let prov_wide: Vec<u16> = provider_name.encode_utf16().chain(Some(0)).collect();
    let mut prov = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw(prov_wide.as_ptr()), 0).map_err(
            |e| NgcError::DecryptionFailed(format!("NCryptOpenStorageProvider({provider_name}) 失败: {e}")),
        )?;
    }

    let mut out = Vec::new();
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();
    loop {
        let mut key_name_ptr: *mut NCryptKeyName = std::ptr::null_mut();
        let r = unsafe {
            NCryptEnumKeys(prov, PCWSTR::null(), &mut key_name_ptr, &mut enum_state, NCRYPT_FLAGS(0))
        };
        match r {
            Ok(()) => {
                if key_name_ptr.is_null() {
                    break;
                }
                unsafe {
                    let kn = &*key_name_ptr;
                    let name = kn.pszName.to_string().unwrap_or_default();
                    let alg = kn.pszAlgid.to_string().unwrap_or_default();
                    out.push((name, alg));
                    let _ = NCryptFreeBuffer(key_name_ptr as *mut core::ffi::c_void);
                }
            }
            Err(e) => {
                // NTE_NO_MORE_ITEMS = 0x8009002A → 正常结束
                if (e.code().0 as u32) == 0x8009_002A {
                    break;
                }
                unsafe {
                    if !enum_state.is_null() {
                        let _ = NCryptFreeBuffer(enum_state);
                    }
                    let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0));
                }
                return Err(NgcError::DecryptionFailed(format!("NCryptEnumKeys 失败: {e}")));
            }
        }
    }

    unsafe {
        if !enum_state.is_null() {
            let _ = NCryptFreeBuffer(enum_state);
        }
        let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0));
    }
    Ok(out)
}

// ─── NCrypt 字符串属性读取 ───────────────────────────────────────────────────

fn ncrypt_get_string_prop(
    h: windows::Win32::Security::Cryptography::NCRYPT_HANDLE,
    prop: &str,
) -> Option<String> {
    use windows::Win32::Security::Cryptography::NCryptGetProperty;
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    use windows_core::PCWSTR;
    let prop_w: Vec<u16> = prop.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut needed = 0u32;
        if NCryptGetProperty(h, PCWSTR::from_raw(prop_w.as_ptr()), None, &mut needed, OBJECT_SECURITY_INFORMATION(0)).is_err()
            || needed == 0
        {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if NCryptGetProperty(h, PCWSTR::from_raw(prop_w.as_ptr()), Some(&mut buf), &mut needed, OBJECT_SECURITY_INFORMATION(0)).is_err() {
            return None;
        }
        let u16s: Vec<u16> = buf[..needed as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string())
    }
}

fn ncrypt_get_dword_prop(
    h: windows::Win32::Security::Cryptography::NCRYPT_HANDLE,
    prop: &str,
) -> Option<u32> {
    use windows::Win32::Security::Cryptography::NCryptGetProperty;
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    use windows_core::PCWSTR;
    let pw: Vec<u16> = prop.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut buf = [0u8; 4];
        let mut needed = 0u32;
        if NCryptGetProperty(h, PCWSTR::from_raw(pw.as_ptr()), Some(&mut buf), &mut needed, OBJECT_SECURITY_INFORMATION(0)).is_err()
            || needed < 4
        {
            return None;
        }
        Some(u32::from_le_bytes(buf))
    }
}

/// 用指定算法模式 + PIN 供给策略尝试对一个密钥签名，返回结果描述行。
/// 全程使用 NCRYPT_SILENT_FLAG，避免弹出原生 Hello PIN 对话框卡住进程。
fn probe_sign(
    prov: windows::Win32::Security::Cryptography::NCRYPT_PROV_HANDLE,
    key_name_w: &[u16],
    hash: &[u8],
    label: &str,
    set_pin: Option<(&str, &[u8])>,
    ecdsa: bool,
) -> String {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenKey, NCryptSetProperty, NCryptSignHash, NCryptFreeObject,
        NCRYPT_KEY_HANDLE, NCRYPT_HANDLE, NCRYPT_FLAGS, CERT_KEY_SPEC,
        BCRYPT_PKCS1_PADDING_INFO, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_SILENT_FLAG,
    };
    use windows_core::PCWSTR;
    unsafe {
        let mut k = NCRYPT_KEY_HANDLE::default();
        if NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(key_name_w.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_err() {
            return format!("[{label}] 打开失败");
        }
        if let Some((pname, pbytes)) = set_pin {
            let pw: Vec<u16> = pname.encode_utf16().chain(Some(0)).collect();
            if let Err(e) = NCryptSetProperty(NCRYPT_HANDLE(k.0), PCWSTR::from_raw(pw.as_ptr()), pbytes, NCRYPT_FLAGS(0)) {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0));
                return format!("[{label}] SetProperty({pname}) 失败: {e}");
            }
        }
        let pad_alg: Vec<u16> = "SHA256".encode_utf16().chain(Some(0)).collect();
        let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: PCWSTR::from_raw(pad_alg.as_ptr()) };
        let pinfo: Option<*const core::ffi::c_void> =
            if ecdsa { None } else { Some(&padding as *const _ as *const core::ffi::c_void) };
        let flags = if ecdsa {
            NCRYPT_SILENT_FLAG
        } else {
            NCRYPT_FLAGS(NCRYPT_PAD_PKCS1_FLAG.0 | NCRYPT_SILENT_FLAG.0)
        };
        let mut sig_len = 0u32;
        if let Err(e) = NCryptSignHash(k, pinfo, hash, None, &mut sig_len, flags) {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0));
            return format!("[{label}] 查长度失败: {e}");
        }
        let mut sig = vec![0u8; sig_len as usize];
        let res = match NCryptSignHash(k, pinfo, hash, Some(&mut sig), &mut sig_len, flags) {
            Ok(()) => format!("[{label}] ✅ 成功 sig_len={sig_len} 前8={:02X?}", &sig[..sig_len.min(8) as usize]),
            Err(e) => format!("[{label}] ❌ 失败: {e}"),
        };
        let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0));
        res
    }
}

// ─── FIDO 签名探针（诊断 PIN 供给策略）──────────────────────────────────────

/// 探测：在 Passport KSP 中按 rpId 找到 FIDO passkey，尝试多种 PIN 供给
/// 策略进行签名，报告密钥算法与每种策略的结果。
///
/// 用于确定 Phase 2 的最终签名路径（PIN 如何无 UI 地授权 Passport KSP 密钥）。
pub fn ncrypt_sign_probe(rp_id: &str, pin: &str) -> Vec<String> {
    use windows::Win32::Security::Cryptography::{
        NCryptOpenStorageProvider, NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject,
        NCryptOpenKey, NCryptSetProperty, NCryptSignHash,
        NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE, NCryptKeyName,
        NCRYPT_FLAGS, CERT_KEY_SPEC, BCRYPT_PKCS1_PADDING_INFO, NCRYPT_PAD_PKCS1_FLAG,
    };
    use windows_core::PCWSTR;
    use sha2::{Digest, Sha256};

    let mut log: Vec<String> = Vec::new();
    macro_rules! l { ($($a:tt)*) => { log.push(format!($($a)*)) } }

    let provider = "Microsoft Passport Key Storage Provider";
    let prov_w: Vec<u16> = provider.encode_utf16().chain(Some(0)).collect();
    let mut prov = NCRYPT_PROV_HANDLE::default();
    if let Err(e) = unsafe { NCryptOpenStorageProvider(&mut prov, PCWSTR::from_raw(prov_w.as_ptr()), 0) } {
        l!("打开 Passport KSP 失败: {e}");
        return log;
    }

    let rp_hash: String = {
        let h = Sha256::digest(rp_id.as_bytes());
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    l!("rpId = {rp_id}");
    l!("SHA256(rpId) = {rp_hash}");

    // 枚举找 FIDO key（优先匹配 rpIdHash，否则取第一个 FIDO key）
    let mut target: Option<String> = None;
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();
    loop {
        let mut kn: *mut NCryptKeyName = std::ptr::null_mut();
        match unsafe { NCryptEnumKeys(prov, PCWSTR::null(), &mut kn, &mut enum_state, NCRYPT_FLAGS(0)) } {
            Ok(()) => {
                if kn.is_null() { break; }
                unsafe {
                    let name = (*kn).pszName.to_string().unwrap_or_default();
                    let _ = NCryptFreeBuffer(kn as *mut core::ffi::c_void);
                    if name.contains("FIDO_AUTHENTICATOR") {
                        if name.to_lowercase().contains(&rp_hash) { target = Some(name); break; }
                        if target.is_none() { target = Some(name); }
                    }
                }
            }
            Err(e) => { if (e.code().0 as u32) == 0x8009_002A { break; } l!("枚举出错: {e}"); break; }
        }
    }
    if !enum_state.is_null() { unsafe { let _ = NCryptFreeBuffer(enum_state); } }

    let key_name = match target {
        Some(n) => n,
        None => { l!("未找到 FIDO_AUTHENTICATOR 密钥"); unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); } return log; }
    };
    l!("选中密钥: {key_name}");
    let matched = key_name.to_lowercase().contains(&rp_hash);
    l!("rpIdHash 是否命中该密钥名: {}", if matched { "是" } else { "否（用的第一个 FIDO key）" });
    let key_name_w: Vec<u16> = key_name.encode_utf16().chain(Some(0)).collect();

    // 读密钥属性（Length 一锤定音 RSA-2048 vs ECDSA-256）
    {
        let mut k = NCRYPT_KEY_HANDLE::default();
        if unsafe { NCryptOpenKey(prov, &mut k, PCWSTR::from_raw(key_name_w.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) }.is_ok() {
            let h = NCRYPT_HANDLE(k.0);
            l!("Algorithm Group = {}", ncrypt_get_string_prop(h, "Algorithm Group").unwrap_or_default());
            l!("Algorithm Name  = {}", ncrypt_get_string_prop(h, "Algorithm Name").unwrap_or_default());
            l!("Length (bits)   = {}", ncrypt_get_dword_prop(h, "Length").map(|v| v.to_string()).unwrap_or_else(|| "?".into()));
            l!("Export Policy   = {}", ncrypt_get_dword_prop(h, "Export Policy").map(|v| format!("0x{v:X}")).unwrap_or_else(|| "?".into()));
            unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(k.0)); }
        }
    }

    let hash = Sha256::digest(b"FaceWinUnlock probe").to_vec();
    let raw_pin_bytes: Vec<u8> = pin.encode_utf16().chain(Some(0)).flat_map(|c| c.to_le_bytes()).collect();
    let hex_pin: String = pin.as_bytes().iter().map(|b| format!("{:02X}", b)).collect();
    let hex_pin_bytes: Vec<u8> = hex_pin.encode_utf16().chain(Some(0)).flat_map(|c| c.to_le_bytes()).collect();

    l!("--- 签名矩阵（算法 × PIN 策略，全 silent）---");
    // 基线：silent 无 PIN（观察授权门错误码）
    l!("{}", probe_sign(prov, &key_name_w, &hash, "ECDSA 无PIN", None, true));
    l!("{}", probe_sign(prov, &key_name_w, &hash, "RSA   无PIN", None, false));
    // SmartcardPin 策略
    l!("{}", probe_sign(prov, &key_name_w, &hash, "ECDSA SmartcardPin=raw", Some(("SmartcardPin", &raw_pin_bytes)), true));
    l!("{}", probe_sign(prov, &key_name_w, &hash, "ECDSA SmartcardPin=hex", Some(("SmartcardPin", &hex_pin_bytes)), true));
    l!("{}", probe_sign(prov, &key_name_w, &hash, "RSA   SmartcardPin=raw", Some(("SmartcardPin", &raw_pin_bytes)), false));
    l!("{}", probe_sign(prov, &key_name_w, &hash, "RSA   SmartcardPin=hex", Some(("SmartcardPin", &hex_pin_bytes)), false));

    unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0)); }
    log
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── dpapi_unprotect ───────────────────────────────────────────────────

    /// DPAPI 解密需要 SYSTEM 上下文（Unlock.exe 以 SYSTEM 运行）。
    /// 此测试仅在安装了 DPAPI 加密测试数据的环境中有意义。
    #[test]
    fn test_dpapi_unprotect_empty_data() {
        // 空数据或空 entropy 不应 panic
        let data: &[u8] = &[];
        let entropy: &[u8] = &[];
        let result = dpapi_unprotect(data, entropy);
        // 预期失败（空数据无法解密），而非 panic
        assert!(result.is_err());
    }

    // ─── rsa_oaep_decrypt ──────────────────────────────────────────────────

    #[test]
    fn test_rsa_oaep_decrypt_empty_ciphertext() {
        let key_blob = b"\x52\x53\x41\x32"; // fake "RSA2" magic
        let result = rsa_oaep_decrypt(key_blob, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_rsa_oaep_decrypt_empty_key() {
        let ciphertext = b"some encrypted data that is long enough 1234";
        let result = rsa_oaep_decrypt(&[], ciphertext);
        assert!(result.is_err());
    }

    // ─── aes256_cbc_decrypt ────────────────────────────────────────────────

    #[test]
    fn test_aes256_cbc_decrypt_bad_key_len() {
        let short_key = b"too short";
        let iv = [0u8; 16];
        let ct = [0u8; 32];
        assert!(aes256_cbc_decrypt(short_key, &iv, &ct).is_err());
    }

    #[test]
    fn test_aes256_cbc_decrypt_bad_iv_len() {
        let key = [0u8; 32];
        let short_iv = b"short";
        let ct = [0u8; 32];
        assert!(aes256_cbc_decrypt(&key, short_iv, &ct).is_err());
    }

    #[test]
    fn test_aes256_cbc_decrypt_unaligned() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let ct = b"not a multiple of 16 bytes!";
        assert!(aes256_cbc_decrypt(&key, &iv, ct).is_err());
    }

    /// Round-trip: AES-256-CBC encrypt then decrypt with known key/IV/PKCS7.
    #[test]
    fn test_aes256_cbc_roundtrip() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        use cbc::Encryptor;

        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let iv = b"1234567890abcdef"; // 16 bytes
        let plaintext = b"Hello, NGC vault!";

        // PKCS7 pad to 16-byte boundary
        let padded_len = ((plaintext.len() / 16) + 1) * 16;
        let pad_byte = (padded_len - plaintext.len()) as u8;
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat(pad_byte).take(pad_byte as usize));

        // Encrypt
        let mut encryptor =
            Encryptor::<aes::Aes256>::new_from_slices(key, iv).unwrap();
        for chunk in padded.chunks_exact_mut(16) {
            let block = aes::cipher::Block::<aes::Aes256>::from_mut_slice(chunk);
            encryptor.encrypt_block_mut(block);
        }

        // Decrypt — our function under test
        let decrypted = aes256_cbc_decrypt(key, iv, &padded).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&decrypted),
            String::from_utf8_lossy(plaintext),
        );
    }
}
