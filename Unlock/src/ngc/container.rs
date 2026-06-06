//! NGC 容器发现与 PIN protector 定位
//!
//! 支持两种 NGC 容器格式：
//! - **旧格式**（本地账户，Win10 pre-1903）：`protectors/` 二进制目录
//! - **新格式**（微软账户/现代本地账户，Win10 1903+）：JSON + CBOR

use std::fs;
use std::path::{Path, PathBuf};

use super::{NgcContainerInfo, NgcError, ProtectorData};

const NGC_ROOT: &str =
    r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
const CRYPTO_KEYS_DIR: &str =
    r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys";
const VAULT_ROOT: &str =
    r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault";
const NGC_SCHEMA: &str = "1d4350a3-330d-4af9-b3ff-a927a45998ac";

// ─── Public API ──────────────────────────────────────────────────────────

/// 查找用户的 NGC 容器
///
/// 先尝试新 JSON 格式，失败回退旧二进制格式。
pub fn find_ngc_container(sid: &str) -> Result<NgcContainerInfo, NgcError> {
    let ngc_dir = Path::new(NGC_ROOT);
    if !ngc_dir.is_dir() {
        return Err(NgcError::ContainerNotFound);
    }
    if fs::read_dir(ngc_dir).is_err() {
        return Err(NgcError::Unsupported(
            "Cannot enumerate NGC directory -- process must run as SYSTEM".into(),
        ));
    }

    // 遍历容器
    for entry in fs::read_dir(ngc_dir)? {
        let entry = entry?;
        let container_path = entry.path();
        if !container_path.is_dir() { continue; }

        let container_guid = container_path
            .file_name().and_then(|n| n.to_str()).unwrap_or("");

        // 跳过系统预生成池
        if container_guid == "PregenPool" { continue; }

        // 检查容器是否属于该 SID
        let cj = container_path.join("Container.json");
        if cj.is_file() {
            if let Ok(json_str) = fs::read_to_string(&cj) {
                // 快速检查 SID 匹配
                let sid_matches = json_str.contains(&format!("\"sid\":\"{}\"", sid))
                    || json_str.contains(&format!("\"sid\": \"{}\"", sid));
                if !sid_matches { continue; }
            }
        }

        // 尝试读取用户名
        let username = get_username_from_sid(sid)?;

        // 尝试新 JSON 格式
        let pj = container_path.join("Protectors.json");
        if pj.is_file() {
            if let Ok(data) = find_json_protector(&container_path, sid) {
                return Ok(NgcContainerInfo {
                    username,
                    sid: sid.to_string(),
                    container_path,
                    salt: data.salt,
                    rounds: data.rounds,
                    key_blob_path: PathBuf::new(), // JSON 格式密钥在容器内
                    vcrd_path: PathBuf::new(),      // 新格式无 Vault
                    pol_path: PathBuf::new(),
                });
            }
        }

        // 回退旧二进制格式
        let protectors_dir = container_path.join("protectors");
        if protectors_dir.is_dir() {
            if let Ok(data) = find_pin_protector(&protectors_dir) {
                let key_blob_path = find_key_blob(&data.key_id)?;
                let (vcrd_path, pol_path) = find_vault_files()?;
                return Ok(NgcContainerInfo {
                    username,
                    sid: sid.to_string(),
                    container_path,
                    salt: data.salt,
                    rounds: data.rounds,
                    key_blob_path,
                    vcrd_path,
                    pol_path,
                });
            }
        }
    }

    Err(NgcError::ContainerNotFound)
}

// ─── JSON 格式（现代 NGC / 微软账户）─────────────────────────────────

/// 从现代 JSON 格式的 NGC 容器中提取 PIN protector 参数
fn find_json_protector(container_path: &Path, _sid: &str) -> Result<ProtectorData, NgcError> {
    let pj = container_path.join("Protectors.json");
    let json_str = fs::read_to_string(&pj)?;
    let root: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| NgcError::DecryptionFailed(format!("Protectors.json 解析失败: {}", e)))?;

    let pin = root.get("pin")
        .ok_or(NgcError::ProtectorNotFound)?;

    let encrypted_cbor = pin.get("secretStore")
        .and_then(|s| s.get("encryptedCbor"))
        .and_then(|v| v.as_str())
        .ok_or(NgcError::ProtectorNotFound)?;

    // 解码 base64 → 二进制 → 解析 NgcIsoHeader
    let cbor_bytes = base64_decode(encrypted_cbor)
        .map_err(|e| NgcError::DecryptionFailed(format!("encryptedCbor base64 解码失败: {}", e)))?;

    let header = parse_ngciso_header(&cbor_bytes)?;

    Ok(ProtectorData {
        salt: header.salt,
        rounds: header.rounds,
        key_id: String::new(), // JSON 格式不需要 key_id
    })
}

/// NgcIsoHeader — 从 encryptedCbor 二进制 blob 的前若干字节中提取
#[derive(Debug)]
pub struct NgcIsoHeader {
    pub salt: Vec<u8>,
    pub rounds: u32,
    pub iv: Vec<u8>,
    pub payload_offset: usize,
}

/// 解析 NgcIsoHeader
///
/// encryptedCbor 是一个 CBOR 编码的加密数据结构，头部包含：
/// - Magic/Version 字段
/// - Salt (32 bytes)
/// - Rounds (u32 LE)
/// - IV (12 bytes for GCM, 16 bytes for CBC)
/// - 然后是加密的 payload
///
/// 使用启发式扫描定位这些字段（格式随 Windows 版本可能略有变化）。
pub fn parse_ngciso_header(data: &[u8]) -> Result<NgcIsoHeader, NgcError> {
    if data.len() < 128 {
        return Err(NgcError::DecryptionFailed("encryptedCbor too short".to_string()));
    }
    // Fixed offsets from Win11 24H2 hex dump:
    // 0x00: Magic(0E1E) 0x04:Reserved 0x08:Algo=50 0x0C:KeySz=100
    // 0x10:Version=1 0x14:Flags 0x18:Count=2
    // 0x1C: Salt (32 bytes)
    // 0x3C: IV (16 bytes, AES-256-CBC)
    // 0x4C-0x63: Metadata (count, flags, payload length etc.)
    // 0x64+: "NgcIsoHeader_<GUID>" null-terminated string + CBOR payload
    let salt = data[0x1C..0x1C+32].to_vec();
    let iv = data[0x3C..0x3C+16].to_vec();
    // Find payload: scan past "NgcIsoHeader_<GUID>" to first null or CBOR byte
    let mut payload_offset = 0x64;
    for i in 0x64..data.len().min(256) {
        if data[i] == 0 && i > 0x64 + 36 { payload_offset = i + 1; break; }
        if data[i] >= 0xA0 && i > 0x64 + 36 { payload_offset = i; break; }
    }
    Ok(NgcIsoHeader { salt, rounds: 10_000, iv, payload_offset })
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64: {}", e))
}

// ─── 旧格式（二进制 protector）────────────────────────────────────────

fn find_pin_protector(protectors_dir: &Path) -> Result<ProtectorData, NgcError> {
    for entry in fs::read_dir(protectors_dir)? {
        let entry = entry?;
        let dir = entry.path();
        if !dir.is_dir() { continue; }
        if let Some(data) = read_protector_file(&dir)? {
            return Ok(data);
        }
    }
    Err(NgcError::ProtectorNotFound)
}

fn read_protector_file(protector_dir: &Path) -> Result<Option<ProtectorData>, NgcError> {
    for entry in fs::read_dir(protector_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() { continue; }
        let data = fs::read(&path)?;
        if data.is_empty() { continue; }
        if let Some(pd) = parse_protector_binary(&data) {
            return Ok(Some(pd));
        }
    }
    Ok(None)
}

fn parse_protector_binary(data: &[u8]) -> Option<ProtectorData> {
    if data.len() < 128 { return None; }
    let salt = extract_salt(data)?;
    let rounds = extract_rounds(data);
    let key_id = extract_key_guid(data)?;
    Some(ProtectorData { salt, rounds, key_id })
}

fn extract_salt(data: &[u8]) -> Option<Vec<u8>> {
    const OFFSETS: &[usize] = &[0x58, 0x60, 0x68, 0x50, 0x78, 0x48, 0x70, 0x80];
    for &off in OFFSETS {
        if off + 32 > data.len() { continue; }
        let candidate = &data[off..off + 32];
        let nonzero = candidate.iter().filter(|&&b| b != 0).count();
        if !candidate.iter().all(|&b| b == 0) && !candidate.iter().all(|&b| b == 0xFF) && nonzero > 8 {
            return Some(candidate.to_vec());
        }
    }
    None
}

fn extract_rounds(data: &[u8]) -> u32 {
    const OFFSETS: &[usize] = &[0x38, 0x3C, 0x40, 0x34, 0x44, 0x30, 0x4C];
    for &off in OFFSETS {
        if off + 4 > data.len() { continue; }
        let bytes: [u8; 4] = match data[off..off + 4].try_into() { Ok(b) => b, Err(_) => continue };
        let v = u32::from_le_bytes(bytes);
        if v > 0 && v <= 200_000 { return v; }
    }
    10_000
}

fn extract_key_guid(data: &[u8]) -> Option<String> {
    for window in data.windows(36) {
        if let Ok(s) = std::str::from_utf8(window) {
            if is_guid_string(s) { return Some(s.to_ascii_lowercase()); }
        }
    }
    for i in 0..data.len().saturating_sub(16) {
        let chunk = &data[i..i + 16];
        if (chunk[6] >> 4) == 0x4 && (chunk[8] >> 6) >= 0x2 {
            return Some(format_guid_bytes(chunk));
        }
    }
    None
}

fn is_guid_string(s: &str) -> bool {
    if s.len() != 36 { return false; }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 { return false; }
    let lens = [8, 4, 4, 4, 12];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != lens[i] || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

fn format_guid_bytes(bytes: &[u8]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let d4 = u16::from_be_bytes([bytes[8], bytes[9]]);
    format!("{d1:08x}-{d2:04x}-{d3:04x}-{d4:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])
}

// ─── 公共 ──────────────────────────────────────────────────────────────

fn get_username_from_sid(sid: &str) -> Result<String, NgcError> {
    // 用 registry ProfileImagePath
    let key = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{}", sid);
    if let Ok(path) = read_profile_image_path(&key) {
        if let Some(name) = path.rsplit('\\').next() {
            if !name.is_empty() { return Ok(name.to_string()); }
        }
    }

    // 回退：找 C:\Users
    if let Ok(entries) = fs::read_dir(r"C:\Users") {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if !["Public", "Default", "Default User", "All Users"].contains(&name)
                        && !name.starts_with('.')
                    {
                        return Ok(name.to_string());
                    }
                }
            }
        }
    }

    Err(NgcError::Unsupported(format!("无法从 SID {sid} 获取用户名")))
}

fn find_key_blob(key_id: &str) -> Result<PathBuf, NgcError> {
    let keys_dir = Path::new(CRYPTO_KEYS_DIR);
    if !keys_dir.is_dir() {
        return Err(NgcError::DecryptionFailed(format!("Crypto Keys 目录不存在: {CRYPTO_KEYS_DIR}")));
    }
    let clean_id = key_id.trim_matches(|c| c == '{' || c == '}');
    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.contains(clean_id) { return Ok(path); }
            }
        }
    }
    Err(NgcError::DecryptionFailed(format!("未找到密钥文件: {key_id}")))
}

fn read_profile_image_path(key_path: &str) -> Result<String, NgcError> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };
    use windows_core::PCWSTR;

    let key_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
    let val_wide: Vec<u16> = "ProfileImagePath".encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut hkey = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(key_wide.as_ptr()), None, KEY_READ, &mut hkey).is_err() {
            return Err(NgcError::DecryptionFailed("无法打开 ProfileList".to_string()));
        }
        let mut data_len = 0u32;
        let mut data_type = REG_SZ;
        let _ = RegQueryValueExW(hkey, PCWSTR::from_raw(val_wide.as_ptr()), None, Some(&mut data_type), None, Some(&mut data_len));
        if data_len == 0 { let _ = RegCloseKey(hkey); return Err(NgcError::DecryptionFailed("ProfileImagePath 为空".to_string())); }
        let mut buf = vec![0u16; (data_len / 2) as usize];
        let result = RegQueryValueExW(hkey, PCWSTR::from_raw(val_wide.as_ptr()), None, None, Some(buf.as_mut_ptr() as *mut u8), Some(&mut data_len));
        let _ = RegCloseKey(hkey);
        if result.is_err() { return Err(NgcError::DecryptionFailed("读取失败".to_string())); }
        let s = String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string();
        if s.is_empty() { Err(NgcError::DecryptionFailed("空值".to_string())) } else { Ok(s) }
    }
}

fn find_vault_files() -> Result<(PathBuf, PathBuf), NgcError> {
    let schema_dir = Path::new(VAULT_ROOT).join(NGC_SCHEMA);
    if !schema_dir.is_dir() {
        return Err(NgcError::DecryptionFailed(format!("Vault schema 目录不存在: {}", schema_dir.display())));
    }
    let pol_path = schema_dir.join("Policy.vpol");
    if !pol_path.is_file() {
        return Err(NgcError::DecryptionFailed("Vault policy 文件不存在".to_string()));
    }
    for entry in fs::read_dir(&schema_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |e| e == "vcrd") {
            return Ok((path, pol_path));
        }
    }
    Err(NgcError::DecryptionFailed("未找到 .vcrd 文件".to_string()))
}
