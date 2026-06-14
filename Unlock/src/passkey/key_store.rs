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
