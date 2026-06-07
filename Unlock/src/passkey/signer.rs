//! FIDO2 assertion 签名器
//!
//! 使用 `crate::ngc` 模块解密 NGC Keys/ 中的 ECDSA_P256 FIDO2 私钥，
//! 通过 CNG BCryptSignHash 签名 assertion。

use crate::ngc;
use super::fido2;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct FidoCredential {
    pub credential_id: String,
    pub key_filename: String,
    pub user_name: String,
    pub container_path: std::path::PathBuf,
}

/// 对 assertion 请求生成签名
pub fn sign_assertion(
    pin: &str,
    request: &fido2::AssertionRequest,
    credential_id: &str,
    sign_count: u32,
    ngc_root: &Path,
) -> Result<fido2::AssertionResponse, String> {
    let cred = find_fido_credential(ngc_root, credential_id)?;
    let ecdsa_key = decrypt_ecdsa_key(pin, &cred.container_path, &cred.key_filename)?;
    let auth_data = fido2::build_authenticator_data(&request.rp_id, sign_count);
    let client_json_str = fido2::build_client_data_json(&request.challenge, &request.origin);
    let to_sign = fido2::build_to_be_signed(&auth_data, &client_json_str);
    let der_sig = ecdsa_sign(&ecdsa_key, &to_sign).map_err(|e| {
        let magic = if ecdsa_key.len() >= 4 { u32::from_le_bytes([ecdsa_key[0],ecdsa_key[1],ecdsa_key[2],ecdsa_key[3]]) } else { 0 };
        let hex8: String = ecdsa_key.iter().take(16).map(|b| format!("{:02X}",b)).collect::<Vec<_>>().join(" ");
        format!("{} [key: {}B, magic=0x{:08X}, first16={}]", e, ecdsa_key.len(), magic, hex8)
    })?;

    Ok(fido2::AssertionResponse {
        id: credential_id.to_string(),
        raw_id: credential_id.to_string(),
        authenticator_data: fido2::base64url(&auth_data),
        client_data_json: fido2::base64url(client_json_str.as_bytes()),
        signature: fido2::base64url(&der_sig),
        user_handle: None,
        cred_type: "public-key".to_string(),
    })
}

/// 在 NGC 根目录下查找匹配的 FIDO2 凭据
fn find_fido_credential(ngc_root: &Path, credential_id: &str) -> Result<FidoCredential, String> {
    for entry in std::fs::read_dir(ngc_root).map_err(|e| format!("NGC: {}", e))? {
        let entry = entry.map_err(|e| format!("entry: {}", e))?;
        let container = entry.path();
        if !container.is_dir() { continue; }
        if container.file_name().and_then(|n| n.to_str()).map_or(false, |n| n == "PregenPool") { continue; }

        let keys_dir = container.join("Keys");
        if !keys_dir.is_dir() { continue; }

        for key_entry in std::fs::read_dir(&keys_dir).map_err(|e| format!("Keys: {}", e))? {
            let key_entry = key_entry.map_err(|e| format!("key_entry: {}", e))?;
            let path = key_entry.path();
            if !path.is_file() { continue; }
            let fname = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with(".json") => n.to_string(),
                _ => continue,
            };

            let js = std::fs::read_to_string(&path).map_err(|e| format!("read: {}", e))?;
            let key: serde_json::Value = serde_json::from_str(&js).map_err(|e| format!("json: {}", e))?;
            let ct = key.get("cacheType").and_then(|v| v.as_u64()).unwrap_or(0);
            let alg = key.get("alg").and_then(|v| v.as_str()).unwrap_or("");
            if ct == 4 && alg == "ECDSA_P256" {
                let cid = fname.trim_end_matches(".json").to_string();
                if cid == credential_id || credential_id.is_empty() {
                    return Ok(FidoCredential {
                        credential_id: cid,
                        key_filename: fname,
                        user_name: String::new(),
                        container_path: container.clone(),
                    });
                }
            }
        }
    }
    Err(format!("未找到 FIDO2 凭据: {}", credential_id))
}

/// 用 PIN 解密 ECDSA_P256 私钥
///
/// 每个 Key 用自己的 NgcIsoHeader salt 独立加密，
/// 密钥 = PIN entropy 的 SHA-512 前 32 bytes。
fn decrypt_ecdsa_key(pin: &str, container_path: &Path, key_filename: &str) -> Result<Vec<u8>, String> {
    let key_path = container_path.join("Keys").join(key_filename);
    let js = std::fs::read_to_string(&key_path).map_err(|e| format!("key: {}", e))?;
    let key: serde_json::Value = serde_json::from_str(&js).map_err(|e| format!("json: {}", e))?;
    let cbor_b64 = key.get("encrypted").and_then(|e| e.get("encryptedCbor"))
        .and_then(|v| v.as_str()).ok_or("缺少 encryptedCbor")?;

    use base64::Engine;
    let cbor_bytes = base64::engine::general_purpose::STANDARD.decode(cbor_b64)
        .map_err(|e| format!("b64: {}", e))?;
    let header = ngc::container::parse_ngciso_header(&cbor_bytes)
        .map_err(|e| format!("hdr: {}", e))?;

    // 用 KEY 自己的 salt 派生 entropy (不是 protector 的 salt)
    let entropy = ngc::pin::derive_entropy(pin, &header.salt, header.rounds)
        .map_err(|_| "entropy failed".to_string())?;
    if entropy.len() < 50 { return Err("entropy short".to_string()); }
    let aes_key = &entropy[18..50];

    let ct = &cbor_bytes[header.payload_offset..];
    let ct = if ct.len() % 16 != 0 { &ct[..ct.len() - (ct.len() % 16)] } else { ct };

    // Try AES-GCM first (modern NgcIso), fall back to CBC
    ngc::dpapi::aes256_gcm_decrypt(aes_key, &header.iv, ct)
        .or_else(|_| ngc::dpapi::aes256_cbc_decrypt(aes_key, &header.iv, ct))
        .map_err(|e| format!("key decrypt: {}", e))
}

fn get_protector_params(container_path: &Path) -> Result<(Vec<u8>, u32), String> {
    let pj = container_path.join("Protectors.json");
    let js = std::fs::read_to_string(&pj).map_err(|e| format!("protector: {}", e))?;
    let root: serde_json::Value = serde_json::from_str(&js).map_err(|e| format!("json: {}", e))?;
    let cbor_b64 = root.get("pin").and_then(|p| p.get("secretStore"))
        .and_then(|s| s.get("encryptedCbor")).and_then(|v| v.as_str()).ok_or("no cbor")?;
    use base64::Engine;
    let cbor_bytes = base64::engine::general_purpose::STANDARD.decode(cbor_b64).map_err(|e| format!("b64: {}", e))?;
    let header = ngc::container::parse_ngciso_header(&cbor_bytes).map_err(|e| format!("hdr: {}", e))?;
    Ok((header.salt, header.rounds))
}

/// ECDSA_P256 签名 → ASN.1 DER 编码
fn ecdsa_sign(key_blob: &[u8], hash: &[u8]) -> Result<Vec<u8>, String> {
    // Try raw 32-byte key first (NGC may output raw d)
    if key_blob.len() == 32 {
        return raw_ecdsa_sign(key_blob, hash);
    }
    // Try PKCS#8 EC private key (DER: 0x30...)
    if key_blob.len() > 8 && key_blob[0] == 0x30 {
        return pkcs8_ecdsa_sign(key_blob, hash);
    }
    // Try CNG ECCPRIVATEBLOB
    cng_ecc_sign(key_blob, hash)
}

/// Raw 32-byte ECDSA P256 private key d
fn raw_ecdsa_sign(d: &[u8], hash: &[u8]) -> Result<Vec<u8>, String> {
    // Build BCRYPT_ECCPRIVATE_BLOB manually
    // Header: dwMagic(4) + cbKey(4) + curve magic + P256 public key X(32) + Y(32) + d(32)
    // dwMagic for ECDSA P256 private: 0x32434345 ("ECC2")
    // Need to compute Q = d * G
    // For now, return error with info
    Err(format!("raw P256 key: {} bytes, need pubkey derivation", d.len()))
}

/// PKCS#8 DER-encoded EC private key
fn pkcs8_ecdsa_sign(der: &[u8], _hash: &[u8]) -> Result<Vec<u8>, String> {
    Err(format!("PKCS#8 key: {} bytes, need DER parsing", der.len()))
}

/// CNG ECCPRIVATEBLOB
fn cng_ecc_sign(key_blob: &[u8], hash: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::{
        BCryptOpenAlgorithmProvider, BCryptImportKeyPair, BCryptSignHash,
        BCryptDestroyKey, BCryptCloseAlgorithmProvider,
        BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECCPRIVATE_BLOB,
        BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_FLAGS,
    };

    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        if BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_ECDSA_P256_ALGORITHM, None, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0)).is_err() {
            return Err("BCryptOpenAlgorithmProvider(ECDSA_P256) failed".to_string());
        }

        let mut key = BCRYPT_KEY_HANDLE::default();
        if BCryptImportKeyPair(alg, None, BCRYPT_ECCPRIVATE_BLOB, &mut key, key_blob, 0).is_err() {
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return Err("BCryptImportKeyPair(ECC) failed".to_string());
        }

        let mut sig_size = 0u32;
        let _ = BCryptSignHash(key, None, hash, None, &mut sig_size, BCRYPT_FLAGS(0));
        if sig_size == 0 || sig_size > 1024 {
            let _ = BCryptDestroyKey(key); let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return Err(format!("sig size: {}", sig_size));
        }

        let mut sig = vec![0u8; sig_size as usize];
        if BCryptSignHash(key, None, hash, Some(&mut sig), &mut sig_size, BCRYPT_FLAGS(0)).is_err() {
            let _ = BCryptDestroyKey(key); let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return Err("sign failed".to_string());
        }
        sig.truncate(sig_size as usize);
        let _ = BCryptDestroyKey(key);
        let _ = BCryptCloseAlgorithmProvider(alg, 0);
        Ok(raw_ecdsa_to_der(&sig))
    }
}

fn raw_ecdsa_to_der(raw: &[u8]) -> Vec<u8> {
    let half = raw.len() / 2;
    let (r, s) = (&raw[..half], &raw[half..]);
    let (r, s) = (strip_leading_zeros(r), strip_leading_zeros(s));
    let total = 2 + r.len() + 2 + s.len();
    let mut der = Vec::with_capacity(2 + total);
    der.push(0x30); der.push(total as u8);
    der.push(0x02); der.push(r.len() as u8); der.extend_from_slice(&r);
    der.push(0x02); der.push(s.len() as u8); der.extend_from_slice(&s);
    der
}

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
    let result = &bytes[start..];
    if result.is_empty() { return vec![0x00]; }
    if result[0] >= 0x80 {
        let mut v = Vec::with_capacity(result.len() + 1);
        v.push(0x00); v.extend_from_slice(result); v
    } else {
        result.to_vec()
    }
}
