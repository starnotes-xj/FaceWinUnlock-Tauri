//! FIDO2 WebAuthn assertion 构造
//!
//! 参考：Shwmae `Fido2/AuthenticatorData.cs`, `AuthenticatorAssertionResponse.cs`
//!
//! 仅实现 `navigator.credentials.get`（登录断言），
//! 不实现 `create`（注册，需要 attestation）。

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// RP 传来的 WebAuthn assertion 请求
#[derive(Debug, Deserialize)]
pub struct AssertionRequest {
    /// RP ID（如 "login.example.com"）
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Base64url 编码的 challenge
    pub challenge: String,
    /// 允许的凭据 ID 列表
    #[serde(rename = "allowCredentials", default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    /// 来源 origin
    pub origin: String,
    /// 超时（毫秒）
    #[serde(default = "default_timeout")]
    pub timeout: u32,
}

fn default_timeout() -> u32 { 60_000 }

#[derive(Debug, Deserialize)]
pub struct CredentialDescriptor {
    pub id: String,   // Base64url 凭据 ID
    #[serde(rename = "type", default = "default_cred_type")]
    pub cred_type: String,
}

fn default_cred_type() -> String { "public-key".to_string() }

/// 构造的 assertion 响应
#[derive(Debug, Serialize)]
pub struct AssertionResponse {
    /// Base64url 凭据 ID
    pub id: String,
    /// Base64url rawId
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Base64url authenticatorData
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Base64url clientDataJSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url 签名
    pub signature: String,
    /// Base64url userHandle（可选）
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    /// 凭据类型
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// clientDataJSON 的内容（在签名前序列化为 JSON）
#[derive(Debug, Serialize)]
struct ClientData {
    #[serde(rename = "type")]
    pub typ: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin", skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,
}

/// 构造 authenticatorData 字节数组
///
/// 格式：
/// - rpIdHash (32 bytes) — SHA-256(rpId)
/// - flags (1 byte) — 0x05 (UP=1, UV=1, AT=0, ED=0)
/// - signCount (4 bytes, big-endian u32)
///
/// 注意：NGC FIDO2 凭据没有 AT (Attested Credential Data) 标志，
/// 因此不包含 AAGUID、credentialIdLength、credentialId、credentialPublicKey。
pub fn build_authenticator_data(rp_id: &str, sign_count: u32) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());

    let flags: u8 = 0x05; // UP (bit 0) + UV (bit 2)

    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&rp_id_hash);          // 32 bytes
    data.push(flags);                              // 1 byte
    data.extend_from_slice(&sign_count.to_be_bytes()); // 4 bytes

    data
}

/// 构造 clientDataJSON
pub fn build_client_data_json(challenge: &str, origin: &str) -> String {
    let client_data = ClientData {
        typ: "webauthn.get".to_string(),
        challenge: challenge.to_string(),
        origin: origin.to_string(),
        cross_origin: Some(false),
    };
    serde_json::to_string(&client_data).unwrap_or_default()
}

/// 计算待签名的数据：authenticatorData ‖ SHA-256(clientDataJSON)
pub fn build_to_be_signed(authenticator_data: &[u8], client_data_json: &str) -> Vec<u8> {
    let client_hash = Sha256::digest(client_data_json.as_bytes());
    let mut data = Vec::with_capacity(authenticator_data.len() + 32);
    data.extend_from_slice(authenticator_data);
    data.extend_from_slice(&client_hash);
    data
}

/// Base64url 编码（无 padding，WebAuthn 格式）
pub fn base64url(data: &[u8]) -> String {
    base64_url(&data)
}

/// Base64url 解码
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64_url_decode(s)
}

// Base64url helpers (no external dependency needed)
fn base64_url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    // Add padding if needed
    let padded = match s.len() % 4 {
        2 => format!("{}==", s),
        3 => format!("{}=", s),
        _ => s.to_string(),
    };
    base64::engine::general_purpose::URL_SAFE
        .decode(&padded)
        .map_err(|e| format!("base64url decode error: {}", e))
}
