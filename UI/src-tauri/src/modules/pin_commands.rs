//! PIN 加密存储 — Tauri 命令
//!
//! 提供 `encrypt_pin` 命令供前端调用。前端负责 SQLite 存储（用 tauri-plugin-sql），
//! 后端仅处理 DPAPI 加密（使用 CRYPTPROTECT_LOCAL_MACHINE 确保 SYSTEM 进程可解密）。
//!
//! 与 Unlock EXE 的 pin_store.rs 共用 `database.db` 和 `pin_store` 表。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 加密后的 PIN 数据，前端存入 SQLite
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedPin {
    pub blob_b64: String,
    pub entropy_b64: String,
    pub pin_hash: String,
}

/// 用 DPAPI (CRYPTPROTECT_LOCAL_MACHINE) + SID 派生 entropy 加密 PIN。
/// 返回的 blob/entropy/hash 由前端存入 `pin_store` 表。
#[tauri::command]
pub fn encrypt_pin(user_name: String, pin: String) -> Result<EncryptedPin, String> {
    let sid = find_current_user_sid(&user_name)?;
    let entropy = derive_dpapi_entropy(&sid, &user_name);
    let pin_bytes = pin.as_bytes();

    let pin_blob = dpapi_protect(pin_bytes, &entropy)?;

    let pin_hash = {
        let mut h = Sha256::new();
        h.update(pin.as_bytes());
        h.update(b"|");
        h.update(salt_for_hash(&sid));
        hex::encode(h.finalize())
    };

    use base64::Engine;
    Ok(EncryptedPin {
        blob_b64: base64::engine::general_purpose::STANDARD.encode(&pin_blob),
        entropy_b64: base64::engine::general_purpose::STANDARD.encode(&entropy),
        pin_hash,
    })
}

/// 验证 PIN 是否与存储的 hash 匹配（不解密，前端快速验证）
#[tauri::command]
pub fn verify_pin_hash_stored(pin: String, stored_hash: String, user_name: String) -> Result<bool, String> {
    let sid = find_current_user_sid(&user_name)?;
    let mut h = Sha256::new();
    h.update(pin.as_bytes());
    h.update(b"|");
    h.update(salt_for_hash(&sid));
    let computed = hex::encode(h.finalize());
    Ok(computed == stored_hash)
}

/// 查找当前用户的 SID
#[tauri::command]
pub fn get_user_sid(user_name: String) -> Result<String, String> {
    find_current_user_sid(&user_name)
}

// ─── Internal ────────────────────────────────────────────────────────

fn derive_dpapi_entropy(sid: &str, user_name: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update(b"|");
    h.update(user_name.as_bytes());
    h.update(b"|FaceWinUnlock-PinStore");
    h.finalize().to_vec()
}

fn salt_for_hash(sid: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update(b"|FaceWinUnlock-PinHash-Salt");
    h.finalize().to_vec()
}

fn find_current_user_sid(username: &str) -> Result<String, String> {
    use windows::Win32::Security::{LookupAccountNameW, SID_NAME_USE, PSID};
    use windows_core::PCWSTR;

    let name_wide: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut sid_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type = SID_NAME_USE::default();

        // 第一次调用获取缓冲区大小
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
            return Err(format!("LookupAccountNameW 查询 SID 大小失败（用户: {username}）"));
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
            return Err(format!("LookupAccountNameW 失败（用户: {username}）"));
        }

        // 手动构建 SID 字符串 "S-R-I-S-S..."
        sid_to_string(&sid_buf[..sid_size as usize])
    }
}

/// 将二进制 SID 转换为 "S-1-5-21-..." 字符串格式
fn sid_to_string(sid: &[u8]) -> Result<String, String> {
    if sid.len() < 8 {
        return Err("SID 数据过短".to_string());
    }

    let revision = sid[0];
    let sub_count = sid[1] as usize;
    let id_auth = ((sid[2] as u64) << 40)
        | ((sid[3] as u64) << 32)
        | ((sid[4] as u64) << 24)
        | ((sid[5] as u64) << 16)
        | ((sid[6] as u64) << 8)
        | (sid[7] as u64);

    if sid.len() < 8 + sub_count * 4 {
        return Err("SID 数据不完整".to_string());
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

fn dpapi_protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB,
        CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    };

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
        return Err("CryptProtectData 失败".into());
    }
    let pt = unsafe {
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(
            Some(windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut _)),
        );
    }
    Ok(pt)
}
