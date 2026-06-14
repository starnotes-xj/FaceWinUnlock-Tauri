//! NGC (Next Generation Credential) 解密模块
//!
//! 以 SYSTEM 身份，用用户输入的 Windows Hello PIN 复刻 NGC 解密链，
//! 解出本地账户的明文密码。
//!
//! 解密链：
//!   PIN → PBKDF2+SHA512+固定熵 → DPAPI entropy
//!     → 解密 NGC RSA 私钥
//!     → 解密 Vault → 解出明文密码
//!
//! 参考：DEF CON 32 "Abusing Windows Hello Without a Severed Hand" (Shwmae)
//!
//! ════════════════════════════════════════════════════════════════════
//!  Phase 1 解密路线图 (2026-06 更新)
//! ════════════════════════════════════════════════════════════════════
//!
//! 【历史背景】
//! - 旧格式 (Win10 pre-1903 本地账户): pin.rs 的 PBKDF2+SHA512 是正确实现，
//!   因为旧格式直接用 DPAPI 保护 RSA 私钥 → 解密 Vault → 出明文密码。
//!
//! - 现代格式 (Win10 1903+/Win11 微软账户/NgcIso GUID 46FEE803-...):
//!   GCM 认证全部失败（7 种密钥派生方式均错误）→
//!   旧 PBKDF2+SHA512 派生出的 AES 密钥与现代 NgcIso 实际使用的不一致。
//!
//! 【现代 NgcIso KDF 假设 (路B 需逆向)】
//!
//! 假设1: CNG KSP 内部 KDF
//!   - Windows NGC KSP 内部管理 SRK，PBKDF2 派生仅是 KSP 验证 PIN 的"前菜"
//!   - 实际 AES 密钥由 KSP 内部用 CNG BCryptSecretAgreement + TPM/VBS 派生
//!   - 即使我们知道了 PIN，也复刻不出 KSP 内部 KDF
//!
//! 假设2: VBS / TPM 绑定
//!   - 即使没有 TPM，KSP 也可能用机器特定的 secret (NTDLL 内部 LSA 密钥)
//!   - 派生参数包含机器 ID/SID/NgcIso GUID 共同输入
//!
//! 假设3: 不同的 KDF 算法
//!   - 可能是 HKDF+SHA512 而非 PBKDF2
//!   - 可能是 Argon2 / scrypt / bcrypt
//!   - 可能是 CNG BCryptDeriveKey 内部 API
//!
//! 【双路并行策略】
//!
//! 路A (NCrypt API - 委托 KSP 解密):
//!   优势: 走系统加密, 不需要逆向 KDF
//!   现状: NCryptOpenKey + SmartcardPin(PIN) + NCryptDecrypt 已实现
//!   测试: `FaceWinUnlock-Server --ngc-phase1-path-a <user> <pin>`
//!
//! 路B (逆向 KDF - 直接派生 AES 密钥):
//!   优势: 拿到原始 AES 密钥, 可离线处理任何加密 blob
//!   难度: 需逆向 CNG BCryptSecretAgreement 调用链
//!   状态: 工具待开发 (CBOR deep dump 已就绪, 等路A 失败再深入)
//!
//! 【诊断工具矩阵】
//! --ngc-cbor-deep-dump <user>     深度解析所有加密 Cbor 结构 (路B 关键诊断)
//! --ngc-dump-enc <user>            导出 Protectors.encryptedCbor 供 CyberChef 分析
//! --ngc-ncrypt-export <user> <pin> NCryptExportKey 导出 RSA 私钥 (KSP 可能拒绝)
//! --ngc-ncrypt-vault <user> <pin>  NCrypt KSP PIN 验证 + NCryptDecrypt 尝试
//! --ngc-phase1-path-a <user> <pin> 路A 完整链: NCryptDecrypt 多点 + 明文检测
//! --ngc-phase1 <user> <pin>        4路径融合: A(Protectors) + B(Vault) + C(NCryptDecrypt fallback) + D(Keys)

use std::fmt;
use std::path::PathBuf;

pub mod container;
pub mod pin;
pub mod dpapi;
pub mod ncrypt;
pub mod cbor;
pub mod pin_store;
mod vault;

// ─── Error type ────────────────────────────────────────────────────────────

/// NGC 解密过程中的错误类型
#[derive(Debug)]
pub enum NgcError {
    /// 未找到 NGC 容器（用户可能未设置 Hello PIN）
    ContainerNotFound,
    /// 未找到 PIN protector
    ProtectorNotFound,
    /// PIN 错误（解密失败）
    InvalidPin,
    /// 解密失败（带描述）
    DecryptionFailed(String),
    /// 文件/IO 错误
    IoError(std::io::Error),
    /// 不支持的操作（如非本地账户）
    Unsupported(String),
}

impl fmt::Display for NgcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NgcError::ContainerNotFound => write!(f, "未找到 NGC 容器，用户可能未设置 Windows Hello PIN"),
            NgcError::ProtectorNotFound => write!(f, "未找到 PIN protector"),
            NgcError::InvalidPin => write!(f, "PIN 错误"),
            NgcError::DecryptionFailed(msg) => write!(f, "解密失败: {msg}"),
            NgcError::IoError(e) => write!(f, "IO 错误: {e}"),
            NgcError::Unsupported(msg) => write!(f, "不支持: {msg}"),
        }
    }
}

impl From<std::io::Error> for NgcError {
    fn from(e: std::io::Error) -> Self {
        NgcError::IoError(e)
    }
}

impl From<String> for NgcError {
    fn from(s: String) -> Self {
        NgcError::DecryptionFailed(s)
    }
}

// ─── Types ─────────────────────────────────────────────────────────────────

/// NGC 容器信息
#[derive(Debug, Clone)]
pub struct NgcContainerInfo {
    /// Windows 用户名
    pub username: String,
    /// 用户 SID
    pub sid: String,
    /// NGC 容器目录路径
    pub container_path: PathBuf,
    /// PBKDF2 salt（来自 protector）
    pub salt: Vec<u8>,
    /// PBKDF2 迭代次数
    pub rounds: u32,
    /// RSA 密钥 blob 文件路径（在 Crypto\Keys 下）
    pub key_blob_path: PathBuf,
    /// Vault .vcrd 凭据文件路径
    pub vcrd_path: PathBuf,
    /// Vault policy 文件路径
    pub pol_path: PathBuf,
}

/// Protector 文件中提取的数据
#[derive(Debug, Clone)]
struct ProtectorData {
    salt: Vec<u8>,
    rounds: u32,
    /// 关联的 RSA 密钥 GUID
    key_id: String,
}

// ─── Public API ────────────────────────────────────────────────────────────

/// 通过 Windows API LookupAccountNameW 直接查找用户名对应的 SID。
/// 这是最可靠的方式，不依赖注册表扫描。
pub fn lookup_sid_by_username(username: &str) -> Result<String, NgcError> {
    use windows::Win32::Security::{
        LookupAccountNameW, SID_NAME_USE, PSID,
    };
    use windows_core::PCWSTR;

    let name_wide: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut sid_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type = SID_NAME_USE::default();

        // 先查询大小
        let _ = LookupAccountNameW(
            None,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            &mut sid_size,
            None,
            &mut domain_size,
            &mut sid_type,
        );

        if sid_size == 0 {
            return Err(NgcError::Unsupported(format!("LookupAccountNameW 查询 SID 大小失败（用户: {username}）")));
        }

        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];

        if LookupAccountNameW(
            None,
            PCWSTR::from_raw(name_wide.as_ptr()),
            Some(PSID(sid_buf.as_mut_ptr() as *mut std::ffi::c_void)),
            &mut sid_size,
            Some(windows_core::PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_size,
            &mut sid_type,
        )
        .is_err()
        {
            return Err(NgcError::Unsupported(format!("LookupAccountNameW 失败（用户: {username}）")));
        }

        // 手动构建 SID 字符串（windows-rs 0.59 未导出 ConvertSidToStringSidW）
        let sid_str = sid_to_string(&sid_buf[..sid_size as usize])?;
        Ok(sid_str)
    }
}

/// 根据用户名查找对应的 SID
///
/// 先尝试 Win32 `LookupAccountNameW`（最快最准），
/// 失败时回退到注册表扫描 `ProfileList`。
pub fn find_sid_by_username(username: &str) -> Result<String, NgcError> {
    // 先尝试 Win32 API（最快最准，处理中文等 Unicode 用户名无问题）
    if let Ok(sid) = lookup_sid_by_username(username) {
        return Ok(sid);
    }

    // 回退到注册表扫描
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, RegCloseKey, RegEnumKeyExW,
        HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };
    use windows_core::PCWSTR;

    let profile_list: Vec<u16> = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let val_name: Vec<u16> = "ProfileImagePath"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hkey = std::mem::zeroed();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(profile_list.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
        .is_err()
        {
            return Err(NgcError::Unsupported(
                "无法打开 ProfileList 注册表".to_string(),
            ));
        }

        let username_lower = username.to_lowercase();

        // 枚举所有子键（SID）
        for idx in 0u32.. {
            let mut sid_buf = vec![0u16; 128];
            let mut sid_len = (sid_buf.len() * 2) as u32; // 字节长度
            let result = RegEnumKeyExW(
                hkey,
                idx,
                Some(windows_core::PWSTR(sid_buf.as_mut_ptr())),
                &mut sid_len,
                None,
                None,
                None,
                None,
            );
            if result.is_err() {
                break; // 枚举结束
            }

            let char_len = (sid_len as usize) / 2; // 字节长度 → 字符长度
            let sid_str = String::from_utf16_lossy(&sid_buf[..char_len.min(sid_buf.len())]);

            // 只检查 SID 格式的子键（以 "S-1-" 开头）
            if !sid_str.starts_with("S-1-") {
                continue;
            }

            // 打开该 SID 的子键读取 ProfileImagePath
            let subkey_path: Vec<u16> = format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{}", sid_str)
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut sub_hkey = std::mem::zeroed();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(subkey_path.as_ptr()),
                None,
                KEY_READ,
                &mut sub_hkey,
            )
            .is_err()
            {
                continue;
            }

            let mut data_type = REG_SZ;
            let mut data_len = 0u32;
            let _ = RegQueryValueExW(
                sub_hkey,
                PCWSTR::from_raw(val_name.as_ptr()),
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_len),
            );

            if data_len > 0 {
                let mut buf = vec![0u16; (data_len / 2) as usize];
                if RegQueryValueExW(
                    sub_hkey,
                    PCWSTR::from_raw(val_name.as_ptr()),
                    None,
                    None,
                    Some(buf.as_mut_ptr() as *mut u8),
                    Some(&mut data_len),
                )
                .is_ok()
                {
                    let path = String::from_utf16_lossy(&buf)
                        .trim_end_matches('\0')
                        .to_string();
                    // 从路径提取用户名
                    if let Some(folder_name) = path.rsplit('\\').next() {
                        if folder_name.to_lowercase() == username_lower {
                            let _ = RegCloseKey(sub_hkey);
                            let _ = RegCloseKey(hkey);
                            return Ok(sid_str);
                        }
                    }
                }
            }
            let _ = RegCloseKey(sub_hkey);
        }
        let _ = RegCloseKey(hkey);
    }

    Err(NgcError::Unsupported(format!(
        "未找到用户 {username} 的 SID。请确保该用户为本地账户且已设置 Windows Hello PIN"
    )))
}

/// 将二进制 SID 转换为 "S-1-5-21-..." 字符串格式
fn sid_to_string(sid: &[u8]) -> Result<String, NgcError> {
    if sid.len() < 8 {
        return Err(NgcError::Unsupported("SID 数据过短".to_string()));
    }

    let revision = sid[0];
    let sub_count = sid[1] as usize;
    // IdentifierAuthority: 6 bytes, big-endian
    let id_auth = ((sid[2] as u64) << 40)
        | ((sid[3] as u64) << 32)
        | ((sid[4] as u64) << 24)
        | ((sid[5] as u64) << 16)
        | ((sid[6] as u64) << 8)
        | (sid[7] as u64);

    if sid.len() < 8 + sub_count * 4 {
        return Err(NgcError::Unsupported("SID 数据不完整".to_string()));
    }

    let mut s = format!("S-{}-{}", revision, id_auth);
    for i in 0..sub_count {
        let offset = 8 + i * 4;
        let sub_auth = u32::from_le_bytes([
            sid[offset], sid[offset + 1], sid[offset + 2], sid[offset + 3],
        ]);
        s.push_str(&format!("-{}", sub_auth));
    }

    Ok(s)
}

/// 用 Windows Hello PIN 恢复本地账户的明文密码。
///
/// # Arguments
/// * `sid` - 用户的 SID 字符串（如 "S-1-5-21-...-1001"）
/// * `pin` - 用户输入的 Windows Hello PIN
///
/// # Returns
/// `Ok((username, password, domain))` 成功时返回用户名、明文密码和域（本地账户为 "."）
pub fn recover_password(sid: &str, pin: &str) -> Result<(String, String, String), NgcError> {
    // Step 1: 定位 NGC 容器
    let container_info = container::find_ngc_container(sid)?;

    // Step 2: PIN → entropy
    let entropy = pin::derive_entropy(pin, &container_info.salt, container_info.rounds)?;

    // 检测容器格式：旧格式（key_blob_path 和 vcrd_path 非空）vs 新格式
    let is_modern = container_info.key_blob_path.as_os_str().is_empty()
        && container_info.vcrd_path.as_os_str().is_empty();

    if is_modern {
        // ── 现代格式（微软账户 / Win10 1903+）────────────────
        let protector_payload = verify_pin_modern(&container_info.container_path, &entropy)?;
        // PIN 正确，protector 已解密。
        // 微软账户无缓存密码，返回空密码。
        // protector_payload 包含 SRK，可用于后续密钥解密。
        drop(protector_payload); // 暂不使用，后续 Phase 2 会用
        Ok((container_info.username, String::new(), ".".to_string()))
    } else {
        // ── 旧格式（本地账户 / Win10 pre-1903）──────────────
        // Step 3: DPAPI 解密 RSA 私钥
        let rsa_key_blob = dpapi::unprotect_rsa_key(
            &container_info.key_blob_path,
            &entropy,
        ).map_err(|e| {
            if matches!(e, NgcError::DecryptionFailed(_)) {
                NgcError::InvalidPin
            } else {
                e
            }
        })?;

        // Step 4: 解密 vault → 获取明文密码
        let password = vault::decrypt_vault_password(
            &rsa_key_blob,
            &container_info.vcrd_path,
            &container_info.pol_path,
        )?;

        Ok((container_info.username, password, ".".to_string()))
    }
}

/// 公开接口：解密 NGC protector，返回解密后的 payload bytes。
///
/// 封装了容器定位、entropy 派生和 protector 解密的完整流程。
pub fn decrypt_protector(sid: &str, pin: &str) -> Result<Vec<u8>, NgcError> {
    let container_info = container::find_ngc_container(sid)?;
    let entropy = pin::derive_entropy(pin, &container_info.salt, container_info.rounds)?;
    verify_pin_modern(&container_info.container_path, &entropy)
}

/// 使用 SRK（Storage Root Key）解密单个 NGC 密钥。
///
/// # Arguments
/// * `container_path` — NGC 容器目录路径（如 `%LOCALAPPDATA%\Microsoft\Ngc\{GUID}`）
/// * `protector_plaintext` — `decrypt_protector`/`verify_pin_modern` 返回的 protector payload
/// * `key_filename` — Keys 目录下的 JSON 文件名（如 `"{GUID}.json"`）
///
/// SRK = protector payload 前 32 字节。
/// Key JSON 中的 encryptedCbor 用 SRK 做 AES-256-CBC 解密。
///
/// # Returns
/// 解密后的密钥明文 bytes。
pub fn decrypt_ngc_key(
    container_path: &std::path::Path,
    protector_plaintext: &[u8],
    key_filename: &str,
) -> Result<Vec<u8>, NgcError> {
    if protector_plaintext.len() < 32 {
        return Err(NgcError::DecryptionFailed(
            "protector payload too short to extract SRK (need >= 32 bytes)".to_string(),
        ));
    }
    let srk = &protector_plaintext[..32];

    let key_path = container_path.join("Keys").join(key_filename);
    let json_str = std::fs::read_to_string(&key_path)?;
    let key_json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| NgcError::DecryptionFailed(format!("Key JSON parse error: {}", e)))?;

    let cbor_b64 = key_json
        .get("encrypted")
        .and_then(|e| e.get("encryptedCbor"))
        .and_then(|v| v.as_str())
        .ok_or(NgcError::DecryptionFailed(
            "encryptedCbor not found in key JSON".to_string(),
        ))?;

    let cbor_bytes = base64_decode(cbor_b64)
        .map_err(|e| NgcError::DecryptionFailed(format!("base64 decode error: {}", e)))?;

    let header = container::parse_ngciso_header(&cbor_bytes)?;

    let ciphertext = &cbor_bytes[header.payload_offset..];
    let ct = align_16(ciphertext);

    dpapi::aes256_cbc_decrypt(srk, &header.iv, ct)
}

/// 现代 NGC 格式：PIN 验证 + protector 解密
fn verify_pin_modern(container_path: &std::path::Path, entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    let (cbor_bytes, header) = read_protector_encrypted_cbor(container_path)?;
    let ciphertext = &cbor_bytes[header.payload_offset..];

    // 尝试多种密钥派生方式
    if let Some((desc, pt)) = try_multiple_key_derivations(entropy, &header.iv, ciphertext) {
        // 成功！但我们不打印 desc（CLI 模式外无输出）
        let _ = desc;
        return Ok(pt);
    }

    Err(NgcError::InvalidPin)
}

/// 提取 AES-256 密钥 (SHA-512 哈希前 32 bytes，跳过 18-byte 固定前缀)
fn extract_aes_key(entropy: &[u8]) -> Result<&[u8], NgcError> {
    if entropy.len() < 50 {
        return Err(NgcError::DecryptionFailed("entropy too short".to_string()));
    }
    Ok(&entropy[18..50])
}

/// 读取并解析 Protectors.json 中的 encryptedCbor
fn read_protector_encrypted_cbor(container_path: &std::path::Path)
    -> Result<(Vec<u8>, container::NgcIsoHeader), NgcError>
{
    let pj = container_path.join("Protectors.json");
    let json_str = std::fs::read_to_string(&pj)?;
    let root: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| NgcError::DecryptionFailed(format!("Protectors.json: {}", e)))?;

    let cbor_b64 = root.get("pin")
        .and_then(|p| p.get("secretStore"))
        .and_then(|s| s.get("encryptedCbor"))
        .and_then(|v| v.as_str())
        .ok_or(NgcError::ProtectorNotFound)?;

    let cbor_bytes = base64_decode(cbor_b64)
        .map_err(|e| NgcError::DecryptionFailed(format!("eCbor base64: {}", e)))?;

    let header = container::parse_ngciso_header(&cbor_bytes)?;
    Ok((cbor_bytes, header))
}

fn align_16(data: &[u8]) -> &[u8] {
    if data.len() % 16 != 0 { &data[..data.len() - (data.len() % 16)] } else { data }
}

/// 尝试多种 AES 密钥派生方式解密，返回第一个成功的 (描述, 明文)
/// Path B: 用 DPAPI 解 Container.json 的 SRK
///
/// SRK base64 解码后是 DPAPI blob，用 PIN entropy 做 entropy 解密。
/// 解密后应为 32 bytes AES-256 key。
fn try_dpapi_unwrap_srk(entropy: &[u8]) -> Option<(String, Vec<u8>)> {
    use base64::Engine;
    // 读 Container.json 找到 SRK
    let ngc_root = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
    if let Ok(entries) = std::fs::read_dir(ngc_root) {
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_dir() || p.file_name().and_then(|n| n.to_str()).map_or(true, |n| !n.starts_with('{')) { continue; }
            let cj = p.join("Container.json");
            if let Ok(js) = std::fs::read_to_string(&cj) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&js) {
                    if let Some(srk_b64) = v.get("srk").and_then(|s| s.as_str()) {
                        if let Ok(srk_blob) = base64::engine::general_purpose::STANDARD.decode(srk_b64) {
                            // DPAPI 用 entropy 解密 SRK
                            if let Ok(key) = dpapi::dpapi_unprotect(&srk_blob, entropy) {
                                if key.len() >= 32 {
                                    return Some((
                                        "SRK[DPAPI]".to_string(),
                                        key[..32].to_vec(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            break; // 只处理第一个容器
        }
    }
    None
}

pub fn try_multiple_key_derivations(
    entropy: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Option<(String, Vec<u8>)> {
    // ── Path B: DPAPI-unwrap SRK from Container.json ──────────────
    if let Some((srk_desc, srk_key)) = try_dpapi_unwrap_srk(entropy) {
        if let Ok(pt) = dpapi::aes256_gcm_decrypt(&srk_key, iv, ciphertext) {
            return Some((srk_desc, pt));
        }
        let ct16 = align_16(ciphertext);
        if ct16.len() >= 16 {
            if let Ok(pt) = dpapi::aes256_cbc_decrypt(&srk_key, iv, ct16) {
                return Some((format!("{srk_desc}(CBC)"), pt));
            }
        }
        // ── SRK-derived keys (HKDF from SRK) ───────────────────
        if srk_key.len() >= 32 {
            for (hkdf_desc, hkdf_key) in srk_hkdf_candidates(&srk_key[..32]) {
                if let Ok(pt) = dpapi::aes256_gcm_decrypt(&hkdf_key, iv, ciphertext) {
                    return Some((format!("SRK+{hkdf_desc}"), pt));
                }
                let ct16 = align_16(ciphertext);
                if ct16.len() >= 16 {
                    if let Ok(pt) = dpapi::aes256_cbc_decrypt(&hkdf_key, iv, ct16) {
                        return Some((format!("SRK+{hkdf_desc}(CBC)"), pt));
                    }
                }
            }
        }
    }

    // ── PBKDF2 entropy 候选 (旧格式) ───────────────────────
    if entropy.len() >= 82 {
        let sha512 = &entropy[18..82];
        let old_candidates: Vec<(&str, Vec<u8>)> = vec![
            ("SHA512[0..32]", sha512[..32].to_vec()),
            ("SHA512[16..48]", sha512[16..48].to_vec()),
            ("SHA512[32..64]", sha512[32..64].to_vec()),
            ("entropy[0..32]", entropy[..32].to_vec()),
            ("entropy[18..50]", entropy[18..50].to_vec()),
            ("entropy[32..64]", entropy[32..64].to_vec()),
            ("entropy[50..82]", entropy[50..82].to_vec()),
        ];
        for (desc, key) in &old_candidates {
            if let Ok(pt) = dpapi::aes256_gcm_decrypt(key, iv, ciphertext) {
                return Some((desc.to_string(), pt));
            }
        }
        for (desc, key) in &old_candidates {
            let ct16 = align_16(ciphertext);
            if ct16.len() >= 16 {
                if let Ok(pt) = dpapi::aes256_cbc_decrypt(key, iv, ct16) {
                    return Some((format!("{desc}(CBC)"), pt));
                }
            }
        }
    }

    // ── HKDF from PIN entropy (现代格式可能用 HKDF) ───────────
    for (hkdf_desc, hkdf_key) in entropy_hkdf_candidates(entropy) {
        if let Ok(pt) = dpapi::aes256_gcm_decrypt(&hkdf_key, iv, ciphertext) {
            return Some((hkdf_desc, pt));
        }
        let ct16 = align_16(ciphertext);
        if ct16.len() >= 16 {
            if let Ok(pt) = dpapi::aes256_cbc_decrypt(&hkdf_key, iv, ct16) {
                return Some((format!("{hkdf_desc}(CBC)"), pt));
            }
        }
    }

    // ── Raw PIN bytes as key (last resort) ───────────────────
    if entropy.len() >= 32 {
        let raw = &entropy[..32];
        if let Ok(pt) = dpapi::aes256_gcm_decrypt(raw, iv, ciphertext) {
            return Some(("raw_entropy[0..32]".to_string(), pt));
        }
        if let Ok(pt) = dpapi::aes256_cbc_decrypt(raw, iv, align_16(ciphertext)) {
            return Some(("raw_entropy[0..32](CBC)".to_string(), pt));
        }
    }

    // ── Direct PBKDF2 output as AES key (server-side KDF: no SHA-512 post-processing) ──
    // The server FUN_180048c08 does PBKDF2 → uses raw output → no hex/SHA512 step
    // Try using the 18-byte prefix + first 14 bytes of SHA-512 = raw PBKDF2 output approximation
    // Actually, the fixed entropy prefix IS the DPAPI entropy marker.
    // Let's try the SHA-512 hash DIRECTLY (without prefix) as key material
    if entropy.len() >= 64 {
        let hash_only = &entropy[..64]; // 64 bytes SHA-512
        for start in [0, 32] {
            let key = &hash_only[start..start+32];
            if let Ok(pt) = dpapi::aes256_gcm_decrypt(key, iv, ciphertext) {
                return Some((format!("SHA512_direct[{}..{}+32]", start, start), pt));
            }
            if let Ok(pt) = dpapi::aes256_cbc_decrypt(key, iv, align_16(ciphertext)) {
                return Some((format!("SHA512_direct[{}..{}+32](CBC)", start, start), pt));
            }
        }
    }

    // ── Try just the PBKDF2 raw output part (prefix bytes) as AES key ──
    // The prefix "xT5rZW5qVVbrvpuA\0" (18 bytes) is specific to DPAPI entropy
    // Maybe the AES key is just a subsequence of the 82-byte blob
    for start in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
        if entropy.len() >= start + 32 {
            let key = &entropy[start..start+32];
            if let Ok(pt) = dpapi::aes256_gcm_decrypt(key, iv, ciphertext) {
                return Some((format!("entropy_byte[{}..{}+32]", start, start), pt));
            }
            if let Ok(pt) = dpapi::aes256_cbc_decrypt(key, iv, align_16(ciphertext)) {
                return Some((format!("entropy_byte[{}..{}+32](CBC)", start, start), pt));
            }
        }
    }

    None
}

/// 从 PIN entropy 派生的 HKDF 候选密钥
fn entropy_hkdf_candidates(entropy: &[u8]) -> Vec<(String, Vec<u8>)> {
    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut out = Vec::new();
    let ikm = if entropy.len() >= 32 { &entropy[..32] } else { entropy };

    // HKDF-Extract: PRK = HMAC-SHA256(salt=zeros, ikm)
    let salt = [0u8; 32];
    if let Ok(mut mac) = HmacSha256::new_from_slice(&salt) {
        mac.update(ikm);
        let prk = mac.finalize().into_bytes();

        // HKDF-Expand round 1: HMAC-SHA256(PRK, info || 0x01)
        let info_labels: &[&[u8]] = &[b"NGC_KEY", b"NGC_AES", b"NgcIso", b"WinHelo", b"", b"KEY"];
        for info_label in info_labels {
            if let Ok(mut mac2) = HmacSha256::new_from_slice(&prk) {
                mac2.update(info_label);
                mac2.update(&[1u8]);
                let okm = mac2.finalize().into_bytes();
                out.push((format!("HKDF(info={})", String::from_utf8_lossy(info_label)), okm[..32].to_vec()));
            }
        }
    }

    // 简单 SHA256 派生
    use sha2::Digest;
    let sha_ikm = Sha256::digest(ikm).to_vec();
    out.push(("SHA256(entropy[..32])".to_string(), sha_ikm));

    out
}

/// 从 SRK 派生的 HKDF 候选密钥
fn srk_hkdf_candidates(srk: &[u8]) -> Vec<(String, Vec<u8>)> {
    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    use sha2::Digest;

    let mut out = Vec::new();

    // SHA256(SRK) as key
    let sha_srk = Sha256::digest(srk).to_vec();
    out.push(("SHA256(SRK)".to_string(), sha_srk));

    // SHA256(SRK || zeros) as key
    let mut hasher = Sha256::new();
    hasher.update(srk);
    hasher.update(&[0u8; 32]);
    out.push(("SHA256(SRK||0)".to_string(), hasher.finalize().to_vec()));

    // HKDF from SRK
    let salt = [0u8; 32];
    if let Ok(mut mac) = HmacSha256::new_from_slice(&salt) {
        mac.update(srk);
        let prk = mac.finalize().into_bytes();
        let info_labels: &[&[u8]] = &[b"KEY_WRAP", b"AES_KEY", b""];
        for info in info_labels {
            if let Ok(mut mac2) = HmacSha256::new_from_slice(&prk) {
                mac2.update(info);
                mac2.update(&[1u8]);
                out.push((format!("HKDF_SRK(info={})", String::from_utf8_lossy(info)), mac2.finalize().into_bytes()[..32].to_vec()));
            }
        }
    }

    // 尝试 SRK 自身（对现代格式，SRK 可能直接当 AES key）
    if srk.len() >= 32 {
        out.push(("SRK_raw".to_string(), srk[..32].to_vec()));
    }

    out
}

/// NGC 密钥信息（从 Keys/ 目录解密后）
#[derive(Debug)]
pub struct NgcKeyInfo {
    pub filename: String,
    pub alg: String,
    pub bits: u32,
    pub cache_type: u32,
    pub decrypted: bool,
    pub key_size: usize,
    /// 解密所用方法："GCM(认证✓)" = 密码学铁证；"CBC(无认证)" = ~1/256 假阳性风险；"" = 未解出。
    pub method: String,
}

/// 用 PIN 解密 NGC 容器中的所有密钥
///
/// 返回解密后的密钥列表及其元数据。
pub fn decrypt_ngc_keys(sid: &str, pin: &str) -> Result<Vec<NgcKeyInfo>, NgcError> {
    let container_info = container::find_ngc_container(sid)?;
    let entropy = pin::derive_entropy(pin, &container_info.salt, container_info.rounds)?;
    let _protector_payload = verify_pin_modern(&container_info.container_path, &entropy)?;
    let aes_key = extract_aes_key(&entropy)?;

    let keys_dir = container_info.container_path.join("Keys");
    if !keys_dir.is_dir() {
        return Err(NgcError::DecryptionFailed("Keys 目录不存在".to_string()));
    }

    let mut results = Vec::new();
    for entry in std::fs::read_dir(&keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().map_or(true, |e| e != "json") { continue; }

        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
        let json_str = std::fs::read_to_string(&path)?;
        let key_json: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|_| NgcError::DecryptionFailed(format!("Key JSON: {}", fname)))?;

        let alg = key_json.get("alg").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let bits = key_json.get("bits").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let cache_type = key_json.get("cacheType").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        // 尝试解密 key——优先 AES-GCM（带认证标签，验过即铁证），失败才回退 CBC（无认证，存疑）。
        // 记录所用方法，让上层能区分「真解开（GCM）」与「可能假阳性（CBC）」。
        let (decrypted, method) = if let Some(cbor_b64) = key_json.get("encrypted")
            .and_then(|e| e.get("encryptedCbor"))
            .and_then(|v| v.as_str())
        {
            if let Ok(key_bytes) = base64_decode(cbor_b64) {
                if let Ok(hdr) = container::parse_ngciso_header(&key_bytes) {
                    let ct = align_16(&key_bytes[hdr.payload_offset..]);
                    if dpapi::aes256_gcm_decrypt(aes_key, &hdr.iv, ct).is_ok() {
                        (true, "GCM(认证✓)".to_string())
                    } else if dpapi::aes256_cbc_decrypt(aes_key, &hdr.iv, ct).is_ok() {
                        (true, "CBC(无认证)".to_string())
                    } else {
                        (false, String::new())
                    }
                } else { (false, String::new()) }
            } else { (false, String::new()) }
        } else { (false, String::new()) };

        results.push(NgcKeyInfo {
            filename: fname,
            alg,
            bits,
            cache_type,
            decrypted,
            key_size: 0,
            method,
        });
    }

    Ok(results)
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64: {}", e))
}
