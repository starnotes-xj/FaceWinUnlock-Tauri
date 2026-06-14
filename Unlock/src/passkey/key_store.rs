//! 已捕获 ECDSA 私钥的密钥存储
//!
//! 读取 `{exe_dir}/passkey_keys.json` 映射文件，加载 key_capture 模块
//! 捕获的 32-byte ECDSA_P256 私钥 d（原始标量），直接用于签名，
//! 跳过 NGC PIN 解密流程。
//!
//! 映射文件格式:
//! ```json
//! [{
//!   "credential_id": "GOOGLE_ACCOUNT:...",
//!   "rp_id": "google.com",
//!   "key_file": "C:/FaceWinUnlock/captured_keys/ngc_....bin"
//! }]
//! ```
//!
//! 每个 `.bin` 文件存放 32 字节原始 ECDSA 私钥 d（大端整数）。

use std::path::Path;

/// 加载匹配的已捕获私钥
///
/// 在 `passkey_keys.json` 中查找同时匹配 `credential_id` 和 `rp_id` 的条目。
/// 如果找到，读取对应的 `.bin` 文件，返回 32 字节原始私钥 d。
/// 未找到则返回 `None`。
pub fn load_key(credential_id: &str, rp_id: &str, exe_dir: &Path) -> Option<Vec<u8>> {
    let mapping_path = exe_dir.join("passkey_keys.json");
    let json_str = std::fs::read_to_string(&mapping_path).ok()?;

    let entries: Vec<KeyEntry> = serde_json::from_str(&json_str).ok()?;

    // 过滤空条目和注释条目
    let entries: Vec<&KeyEntry> = entries.iter()
        .filter(|e| !e.credential_id.is_empty() && !e.rp_id.is_empty() && !e.key_file.is_empty())
        .collect();

    // 查找同时匹配 credential_id 和 rp_id 的条目
    let entry = entries.iter().find(|e| {
        e.credential_id == credential_id && e.rp_id == rp_id
    })?;

    // 读取 .bin 文件
    let key_bytes = std::fs::read(&entry.key_file).ok()?;

    // 验证长度：期望 32 字节 ECDSA_P256 私钥 d
    if key_bytes.len() != 32 {
        log_skip(&mapping_path, credential_id, rp_id, &format!(
            "key_file 大小 {} 字节，期望 32", key_bytes.len()
        ));
        return None;
    }

    Some(key_bytes)
}

/// 增量保存新捕获的密钥到 key_store
///
/// 如果该 (credential_id, rp_id) 组合已存在，直接返回不重复写。
/// 否则将 32 字节私钥写入 `captured_keys/{hash}.bin` 并追加到 passkey_keys.json。
pub fn save_key(credential_id: &str, rp_id: &str, key_bytes: &[u8], exe_dir: &Path) -> Result<(), String> {
    if key_bytes.len() != 32 {
        return Err(format!("期望 32 字节私钥，实际 {}", key_bytes.len()));
    }

    let mapping_path = exe_dir.join("passkey_keys.json");
    let mut entries: Vec<serde_json::Value> = if mapping_path.exists() {
        let js = std::fs::read_to_string(&mapping_path).map_err(|e| format!("读取: {e}"))?;
        serde_json::from_str(&js).unwrap_or_default()
    } else {
        Vec::new()
    };

    // 过滤有效条目，检查是否已存在
    let exists = entries.iter().any(|e| {
        e.get("credential_id").and_then(|v| v.as_str()).unwrap_or("") == credential_id
        && e.get("rp_id").and_then(|v| v.as_str()).unwrap_or("") == rp_id
    });

    if exists {
        return Ok(()); // 已存在，无需重复保存
    }

    // 保存 32 字节私钥到 captured_keys/
    let out_dir = Path::new(r"C:\FaceWinUnlock\captured_keys");
    let _ = std::fs::create_dir_all(out_dir);
    let hash = {
        use sha2::{Sha256, Digest};
        let h = Sha256::digest(credential_id.as_bytes());
        hex::encode(&h[..8])
    };
    let key_file = out_dir.join(format!("incr_{}.bin", hash));
    std::fs::write(&key_file, key_bytes).map_err(|e| format!("写入密钥文件: {e}"))?;

    // 追加新条目到 JSON
    entries.push(serde_json::json!({
        "credential_id": credential_id,
        "rp_id": rp_id,
        "key_file": key_file.to_string_lossy().to_string(),
    }));

    let json_str = serde_json::to_string_pretty(&entries).map_err(|e| format!("序列化: {e}"))?;
    std::fs::write(&mapping_path, json_str.as_bytes()).map_err(|e| format!("写入: {e}"))?;

    eprintln!("key_store 增量保存: credential_id={credential_id}, rp_id={rp_id} → {}", key_file.display());
    Ok(())
}

/// passkey_keys.json 中的单条映射条目
#[derive(serde::Deserialize)]
struct KeyEntry {
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    rp_id: String,
    #[serde(default)]
    key_file: String,
    /// 说明性注释条目（跳过）
    #[serde(default, rename = "_comment")]
    _comment: String,
    #[serde(default, rename = "_comment2")]
    _comment2: String,
    #[serde(default, rename = "_comment3")]
    _comment3: String,
    #[serde(default, rename = "_comment4")]
    _comment4: String,
}

/// 记录跳过 key_store 的原因（不阻塞后续 NGC 回退）
fn log_skip(mapping_path: &Path, credential_id: &str, rp_id: &str, reason: &str) {
    let msg = format!(
        "key_store 跳过 credential_id={}, rp_id={}: {} [{}]",
        credential_id, rp_id, reason, mapping_path.display()
    );
    // 写入 stderr（被 Unlock EXE 日志捕获）
    eprintln!("{}", msg);
}
