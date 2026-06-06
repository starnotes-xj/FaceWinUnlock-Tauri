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

use std::fmt;
use std::path::PathBuf;

pub mod container;
mod pin;
mod dpapi;
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

/// 现代 NGC 格式：PIN 验证 + protector 解密
///
/// 返回解密后的 protector payload (CBOR 结构，包含 SRK 等)。
/// 解密成功 = PIN 正确。
fn verify_pin_modern(container_path: &std::path::Path, entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    let aes_key = extract_aes_key(entropy)?;
    let (cbor_bytes, header) = read_protector_encrypted_cbor(container_path)?;

    let ciphertext = &cbor_bytes[header.payload_offset..];
    let ct = align_16(ciphertext);

    // AES-256-CBC 解密
    if let Ok(pt) = dpapi::aes256_cbc_decrypt(aes_key, &header.iv, ct) {
        if !pt.is_empty() { return Ok(pt); }
    }
    // 偏移调整重试
    for adj in 0..4 {
        let ct2 = align_16(&ciphertext[adj..]);
        if ct2.len() < 16 { continue; }
        if let Ok(pt) = dpapi::aes256_cbc_decrypt(aes_key, &header.iv, ct2) {
            if !pt.is_empty() { return Ok(pt); }
        }
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

/// NGC 密钥信息（从 Keys/ 目录解密后）
#[derive(Debug)]
pub struct NgcKeyInfo {
    pub filename: String,
    pub alg: String,
    pub bits: u32,
    pub cache_type: u32,
    pub decrypted: bool,
    pub key_size: usize,
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

        // 尝试解密 key
        let decrypted = if let Some(cbor_b64) = key_json.get("encrypted")
            .and_then(|e| e.get("encryptedCbor"))
            .and_then(|v| v.as_str())
        {
            if let Ok(key_bytes) = base64_decode(cbor_b64) {
                if let Ok(hdr) = container::parse_ngciso_header(&key_bytes) {
                    let ct = align_16(&key_bytes[hdr.payload_offset..]);
                    dpapi::aes256_cbc_decrypt(aes_key, &hdr.iv, ct).is_ok()
                } else { false }
            } else { false }
        } else { false };

        results.push(NgcKeyInfo {
            filename: fname,
            alg,
            bits,
            cache_type,
            decrypted,
            key_size: 0,
        });
    }

    Ok(results)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64: {}", e))
}
