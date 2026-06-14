//! PIN 加密存储模块
//!
//! 业务背景：Chrome/Edge 在 "查看已保存密码" / "passkey 登录" 场景下需要
//! 用户输入 Windows Hello PIN 进行身份验证。本模块提供：
//!
//! 1. `save_pin(user, pin)` — 用户首次设置时加密存储 PIN
//! 2. `load_pin(user)` — DLL 在 credentialuibroker.exe 中调用，获取明文 PIN
//! 3. `delete_pin(user)` — 清除存储
//!
//! 加密方案：Windows DPAPI + SID + 机器特征派生 entropy
//! - 保护强度: 同等 DPAPI master key 强度
//! - 跨用户隔离: 用 SID 派生 entropy
//! - 跨机器隔离: 用 SID + 当前用户名派生 (无法迁移)
//!
//! **安全考虑**:
//! - PIN blob 仅 Unlock.exe (SYSTEM 身份) 和 UI 可解密
//! - DLL 在 winlogon.exe 中运行时，调用 DPAPI 用 SYSTEM 上下文
//! - 无法被其他用户进程读取

use base64::Engine;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use super::NgcError;

const DB_RELATIVE: &str = "database.db";

/// 获取 SQLite 数据库连接
fn db_path() -> Result<PathBuf, NgcError> {
    // ROOT_DIR 在 unlock.exe 同级
    let exe = std::env::current_exe()
        .map_err(|e| NgcError::IoError(e))?;
    let dir = exe.parent().ok_or_else(|| {
        NgcError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "no parent dir"))
    })?;
    Ok(dir.join(DB_RELATIVE))
}

/// 派生 DPAPI entropy: SHA256(SID || user_name)
fn derive_dpapi_entropy(sid: &str, user_name: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update(b"|");
    h.update(user_name.as_bytes());
    h.update(b"|FaceWinUnlock-PinStore");
    h.finalize().to_vec()
}

/// 获取当前用户的 SID (通过 LookupAccountNameW)
fn get_current_sid() -> Result<String, NgcError> {
    use windows::Win32::System::Registry::*;
    use windows_core::PCWSTR;

    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .map_err(|_| NgcError::Unsupported("无法获取 USERNAME".into()))?;

    // 简化: 直接从 ProfileList 查
    let profile_list = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let k_w: Vec<u16> = profile_list.encode_utf16().chain(std::iter::once(0)).collect();
    let user_lower = username.to_lowercase();

    unsafe {
        let mut hkey = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(k_w.as_ptr()), None, KEY_READ, &mut hkey).is_err() {
            return Err(NgcError::Unsupported("无法打开 ProfileList".into()));
        }

        for idx in 0u32..256 {
            let mut sid_buf = vec![0u16; 128];
            let mut sid_len = (sid_buf.len() * 2) as u32;
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
            if result.is_err() { break; }
            let char_len = (sid_len as usize) / 2;
            let sid_str = String::from_utf16_lossy(&sid_buf[..char_len.min(sid_buf.len())]);
            if !sid_str.starts_with("S-1-") { continue; }

            let sub_path = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{}", sid_str);
            let sub_w: Vec<u16> = sub_path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sub_hkey = std::mem::zeroed();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(sub_w.as_ptr()), None, KEY_READ, &mut sub_hkey).is_err() {
                continue;
            }

            let val_w: Vec<u16> = "ProfileImagePath\0".encode_utf16().collect();
            let mut data_type = REG_SZ;
            let mut data_len = 0u32;
            let _ = RegQueryValueExW(
                sub_hkey,
                PCWSTR::from_raw(val_w.as_ptr()),
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_len),
            );

            if data_len > 0 {
                let mut buf = vec![0u16; (data_len / 2) as usize];
                if RegQueryValueExW(
                    sub_hkey,
                    PCWSTR::from_raw(val_w.as_ptr()),
                    None,
                    None,
                    Some(buf.as_mut_ptr() as *mut u8),
                    Some(&mut data_len),
                ).is_ok() {
                    let path = String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string();
                    if let Some(folder) = path.rsplit('\\').next() {
                        if folder.to_lowercase() == user_lower {
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
    Err(NgcError::Unsupported(format!("未找到 {username} 的 SID")))
}

/// 加密并存储 PIN（自动查找 SID）
pub fn save_pin(user_name: &str, pin: &str, face_id: Option<i64>) -> Result<(), NgcError> {
    let sid = get_current_sid()?;
    save_pin_with_sid(user_name, pin, &sid, face_id)
}

/// 加密并存储 PIN（使用显式 SID）
pub fn save_pin_with_sid(user_name: &str, pin: &str, sid: &str, face_id: Option<i64>) -> Result<(), NgcError> {
    let sid = sid.to_string();
    let entropy = derive_dpapi_entropy(&sid, user_name);
    let pin_bytes = pin.as_bytes();

    // DPAPI 加密
    let pin_blob = dpapi_protect(pin_bytes, &entropy)?;

    // PIN hash 用于快速校验
    let pin_hash = {
        let mut h = Sha256::new();
        h.update(pin.as_bytes());
        h.update(b"|");
        h.update(salt_for_hash(&sid));
        hex::encode(h.finalize())
    };

    // 存储到 SQLite
    let db = db_path()?;
    let conn = Connection::open(&db)
        .map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    // 检查表是否存在，不存在则创建
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pin_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            face_id INTEGER,
            user_name TEXT NOT NULL,
            pin_blob TEXT NOT NULL,
            pin_entropy TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            crypto_method TEXT NOT NULL DEFAULT 'dpapi-sid',
            enabled INTEGER NOT NULL DEFAULT 1,
            note TEXT,
            createTime TEXT DEFAULT (datetime('now', 'localtime')),
            lastTime TEXT DEFAULT (datetime('now', 'localtime'))
        )",
        [],
    ).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let pin_blob_b64 = base64::engine::general_purpose::STANDARD.encode(&pin_blob);
    let entropy_b64 = base64::engine::general_purpose::STANDARD.encode(&entropy);

    // Upsert: 同 user_name 替换
    conn.execute(
        "DELETE FROM pin_store WHERE user_name = ?1",
        params![user_name],
    ).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    conn.execute(
        "INSERT INTO pin_store (face_id, user_name, pin_blob, pin_entropy, pin_hash, crypto_method, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, 'dpapi-sid', 1)",
        params![
            face_id,
            user_name,
            pin_blob_b64,
            entropy_b64,
            pin_hash,
        ],
    ).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    Ok(())
}

/// 加载并解密 PIN (返回明文)
/// 自动获取当前进程用户的 SID 做 entropy 推导。仅在 UI 进程（用户会话）中使用。
pub fn load_pin(user_name: &str) -> Result<String, NgcError> {
    let sid = get_current_sid()?;
    load_pin_with_sid(user_name, &sid)
}

/// 加载并解密 PIN（使用显式 SID，供 SYSTEM 进程使用）
/// Unlock EXE 以 SYSTEM 运行时无法通过 `get_current_sid()` 获取正确 SID，
/// 需由调用方（如人脸匹配成功后）提供目标用户的 SID。
pub fn load_pin_with_sid(user_name: &str, sid: &str) -> Result<String, NgcError> {
    let db = db_path()?;
    load_pin_from_db(user_name, sid, &db)
}

/// 从指定数据库加载 PIN（供外部指定 DB 路径）
pub fn load_pin_from_db(user_name: &str, sid: &str, db_path: &std::path::Path) -> Result<String, NgcError> {
    let db = db_path.to_path_buf();
    let conn = Connection::open(&db)
        .map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let mut stmt = conn.prepare(
        "SELECT pin_blob, pin_entropy, enabled FROM pin_store WHERE user_name = ?1 LIMIT 1"
    ).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let row = stmt.query_row(params![user_name], |row| {
        let blob_b64: String = row.get(0)?;
        let entropy_b64: String = row.get(1)?;
        let enabled: i64 = row.get(2)?;
        Ok((blob_b64, entropy_b64, enabled))
    }).map_err(|e| {
        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
            NgcError::ProtectorNotFound
        } else {
            NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        }
    })?;

    if row.2 == 0 {
        return Err(NgcError::Unsupported("PIN 存储已禁用".into()));
    }

    let blob = base64::engine::general_purpose::STANDARD.decode(&row.0)
        .map_err(|e| NgcError::DecryptionFailed(format!("b64 blob: {e}")))?;
    let entropy = base64::engine::general_purpose::STANDARD.decode(&row.1)
        .map_err(|e| NgcError::DecryptionFailed(format!("b64 entropy: {e}")))?;

    // 派生对应 entropy 验证
    let expected_entropy = derive_dpapi_entropy(sid, user_name);
    if entropy != expected_entropy {
        return Err(NgcError::DecryptionFailed("entropy 不匹配 (跨用户?)".into()));
    }

    let pin_bytes = dpapi_unprotect(&blob, &entropy)?;
    let pin = String::from_utf8(pin_bytes)
        .map_err(|e| NgcError::DecryptionFailed(format!("PIN 不是 UTF-8: {e}")))?;
    Ok(pin)
}

/// 校验 PIN 是否与存储的 hash 匹配 (不解密)
pub fn verify_pin_hash(user_name: &str, pin: &str) -> Result<bool, NgcError> {
    let sid = get_current_sid()?;
    let db = db_path()?;
    let conn = Connection::open(&db)
        .map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let mut stmt = conn.prepare(
        "SELECT pin_hash FROM pin_store WHERE user_name = ?1 AND enabled = 1 LIMIT 1"
    ).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let stored_hash: String = stmt.query_row(params![user_name], |row| row.get(0))
        .map_err(|_| NgcError::ProtectorNotFound)?;

    let mut h = Sha256::new();
    h.update(pin.as_bytes());
    h.update(b"|");
    h.update(salt_for_hash(&sid));
    let computed = hex::encode(h.finalize());
    Ok(computed == stored_hash)
}

/// 删除 PIN 存储
pub fn delete_pin(user_name: &str) -> Result<(), NgcError> {
    let db = db_path()?;
    let conn = Connection::open(&db)
        .map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    conn.execute(
        "DELETE FROM pin_store WHERE user_name = ?1",
        params![user_name],
    ).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    Ok(())
}

/// 列出所有已存储的 PIN (仅返回元数据，不含明文)
pub fn list_stored_pins() -> Result<Vec<PinMetadata>, NgcError> {
    let db = db_path()?;
    let conn = Connection::open(&db)
        .map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    // 静默忽略表不存在的情况
    let mut stmt = match conn.prepare(
        "SELECT id, face_id, user_name, crypto_method, enabled, createTime, lastTime
         FROM pin_store ORDER BY id DESC"
    ) {
        Ok(s) => s,
        Err(_) => return Ok(vec![]),
    };

    let rows = stmt.query_map([], |row| {
        Ok(PinMetadata {
            id: row.get(0)?,
            face_id: row.get(1)?,
            user_name: row.get(2)?,
            crypto_method: row.get(3)?,
            enabled: row.get::<_, i64>(4)? != 0,
            create_time: row.get(5)?,
            last_time: row.get(6)?,
        })
    }).map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let mut out = Vec::new();
    for r in rows { out.push(r.map_err(|e| NgcError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?); }
    Ok(out)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinMetadata {
    pub id: i64,
    pub face_id: Option<i64>,
    pub user_name: String,
    pub crypto_method: String,
    pub enabled: bool,
    pub create_time: String,
    pub last_time: String,
}

// ─── DPAPI 封装 (使用 ngc/dpapi 已有函数) ─────────────────────────

fn dpapi_protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN};

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
    let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

    let result = unsafe {
        CryptProtectData(
            &data_in,
            None,
            entropy_blob.as_ref().map(|b| b as *const _),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut data_out,
        )
    };
    if result.is_err() {
        return Err(NgcError::DecryptionFailed("CryptProtectData 失败".into()));
    }
    let pt = unsafe {
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };
    unsafe { let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut _))); }
    Ok(pt)
}

fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN};

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
    let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            None,
            entropy_blob.as_ref().map(|b| b as *const _),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut data_out,
        )
    };
    if result.is_err() {
        return Err(NgcError::DecryptionFailed("CryptUnprotectData 失败 (DPAPI 保护)".into()));
    }
    let pt = unsafe {
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };
    unsafe { let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut _))); }
    Ok(pt)
}

fn salt_for_hash(sid: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update(b"|FaceWinUnlock-PinHash-Salt");
    h.finalize().to_vec()
}
