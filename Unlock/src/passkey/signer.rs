//! FIDO2 assertion 签名器
//!
//! 使用 `crate::ngc` 模块解密 NGC Keys/ 中的 ECDSA_P256 FIDO2 私钥，
//! 通过 CNG BCryptSignHash 签名 assertion。

use crate::ngc;
use super::fido2;
use super::key_store;
use std::path::Path;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct FidoCredential {
    pub credential_id: String,
    pub key_filename: String,
    pub user_name: String,
    pub container_path: std::path::PathBuf,
}

/// 对 assertion 请求生成签名
///
/// 签名策略（按优先级）:
/// 1. 首选 `key_store::load_key`（已捕获的 ECDSA 私钥，无需 PIN）
/// 2. 回退到 NGC 解密（需要用户输入 PIN）
pub fn sign_assertion(
    pin: &str,
    request: &fido2::AssertionRequest,
    credential_id: &str,
    sign_count: u32,
    ngc_root: &Path,
    exe_dir: &Path,
) -> Result<fido2::AssertionResponse, String> {
    let auth_data = fido2::build_authenticator_data(&request.rp_id, sign_count);
    let client_json_str = fido2::build_client_data_json(&request.challenge, &request.origin);
    let to_sign = fido2::build_to_be_signed(&auth_data, &client_json_str);

    let effective_pin = if !pin.is_empty() {
        Some(pin.to_string())
    } else {
        try_load_pin_from_db(exe_dir)
    };

    // 策略 1: 使用 Passport KSP 中的真实不可导出 FIDO 密钥。
    let mut passport_ksp_error = None;
    if let Some(ref effective_pin) = effective_pin {
        let digest = Sha256::digest(&to_sign);
        match ngc::ncrypt::sign_fido_assertion_hash(
            &request.rp_id,
            effective_pin,
            &digest,
        ) {
            Ok((signature, key_name)) => {
                log_key_source(exe_dir, credential_id, "passport_ksp");
                log_ksp_key(exe_dir, &key_name);
                return Ok(build_response(
                    credential_id,
                    &auth_data,
                    &client_json_str,
                    signature,
                ));
            }
            Err(error) => {
                log_ksp_failure(exe_dir, &request.rp_id, &error);
                passport_ksp_error = Some(error);
            }
        }
    }

    // 策略 2: 测试/兼容回退，使用已捕获的 ECDSA 私钥。
    let ecdsa_key_opt = key_store::load_key(credential_id, &request.rp_id, exe_dir);
    let ecdsa_key = match ecdsa_key_opt {
        Some(key) => {
            log_key_source(exe_dir, credential_id, "captured_key_store");
            key
        }
        None => {
            // 策略 3: 旧版 NGC 文件解密
            log_key_source(exe_dir, credential_id, "ngc_decrypt");

            let effective_pin = effective_pin.ok_or("PIN required")?;

            let cred = match find_fido_credential(ngc_root, credential_id) {
                Ok(credential) => credential,
                Err(error) => {
                    return Err(native_fallback_error(
                        passport_ksp_error.as_deref(),
                        &error,
                    ));
                }
            };
            let key = decrypt_ecdsa_key(&effective_pin, &cred.container_path, &cred.key_filename)
                .map_err(|e| {
                    // PIN 错误时提示用户重新输入
                    format!("NGC 解密失败: {e}（PIN 可能已变更，请在浏览器弹框中输入当前 PIN）")
                })?;
            // ★ 增量更新：解密成功后自动保存到 key_store，下次无需 PIN
            let _ = key_store::save_key(credential_id, &request.rp_id, &key, exe_dir);
            key
        }
    };

    let der_sig = ecdsa_sign(&ecdsa_key, &to_sign).map_err(|e| {
        let magic = if ecdsa_key.len() >= 4 { u32::from_le_bytes([ecdsa_key[0],ecdsa_key[1],ecdsa_key[2],ecdsa_key[3]]) } else { 0 };
        let hex8: String = ecdsa_key.iter().take(16).map(|b| format!("{:02X}",b)).collect::<Vec<_>>().join(" ");
        format!("{} [key: {}B, magic=0x{:08X}, first16={}]", e, ecdsa_key.len(), magic, hex8)
    })?;

    Ok(build_response(
        credential_id,
        &auth_data,
        &client_json_str,
        der_sig,
    ))
}

fn native_fallback_error(passport_error: Option<&str>, legacy_error: &str) -> String {
    match passport_error {
        Some(passport_error) => {
            format!("NATIVE_FALLBACK:{passport_error}; legacy={legacy_error}")
        }
        None => legacy_error.to_string(),
    }
}

pub(super) fn start_native_pin_autofill(exe_dir: &Path) -> Result<(), String> {
    let pin = try_load_pin_from_db(exe_dir)
        .ok_or_else(|| "stored Windows Hello PIN is unavailable".to_string())?;
    let log_dir = exe_dir.to_path_buf();
    std::thread::spawn(move || {
        log_passkey(&log_dir, "INFO", "waiting for native passkey PIN dialog");
        match crate::uia::autofill_pin(&pin, 20) {
            Ok(message) => {
                log_passkey(&log_dir, "INFO", &format!("native PIN autofill: {message}"));
            }
            Err(error) => {
                log_passkey(
                    &log_dir,
                    "WARN",
                    &format!("native PIN autofill failed: {error}"),
                );
            }
        }
    });
    Ok(())
}

fn build_response(
    credential_id: &str,
    auth_data: &[u8],
    client_json_str: &str,
    signature: Vec<u8>,
) -> fido2::AssertionResponse {
    fido2::AssertionResponse {
        id: credential_id.to_string(),
        raw_id: credential_id.to_string(),
        authenticator_data: fido2::base64url(&auth_data),
        client_data_json: fido2::base64url(client_json_str.as_bytes()),
        signature: fido2::base64url(&signature),
        user_handle: None,
        cred_type: "public-key".to_string(),
    }
}

/// 记录实际使用的密钥来源
fn log_key_source(exe_dir: &Path, credential_id: &str, source: &str) {
    let log_path = exe_dir.join("logs").join("unlock.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        use std::io::Write;
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seconds = elapsed % 86_400;
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        let _ = writeln!(
            file,
            "{:02}:{:02}:{:02} [INFO] passkey: sign_assertion credential_id={} source={}",
            hour, minute, second, credential_id, source
        );
    }
}

fn log_ksp_key(exe_dir: &Path, key_name: &str) {
    log_passkey(exe_dir, "INFO", &format!("Passport KSP key={key_name}"));
}

fn log_ksp_failure(exe_dir: &Path, rp_id: &str, error: &str) {
    log_passkey(
        exe_dir,
        "WARN",
        &format!("Passport KSP signing unavailable for rpId={rp_id}: {error}"),
    );
}

fn log_passkey(exe_dir: &Path, level: &str, message: &str) {
    let log_path = exe_dir.join("logs").join("unlock.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        use std::io::Write;
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seconds = elapsed % 86_400;
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        let _ = writeln!(
            file,
            "{:02}:{:02}:{:02} [{}] passkey: {}",
            hour, minute, second, level, message
        );
    }
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
/// NgcIso 加密的 key；尝试多种密钥派生方式。
fn decrypt_ecdsa_key(pin: &str, container_path: &Path, key_filename: &str) -> Result<Vec<u8>, String> {
    // 1. 读取 key 的 encryptedCbor
    let key_path = container_path.join("Keys").join(key_filename);
    let js = std::fs::read_to_string(&key_path).map_err(|e| format!("key: {}", e))?;
    let key: serde_json::Value = serde_json::from_str(&js).map_err(|e| format!("json: {}", e))?;
    let cbor_b64 = key.get("encrypted").and_then(|e| e.get("encryptedCbor"))
        .and_then(|v| v.as_str()).ok_or("缺少 encryptedCbor")?;

    use base64::Engine;
    let cbor_bytes = base64::engine::general_purpose::STANDARD.decode(cbor_b64)
        .map_err(|e| format!("b64: {}", e))?;
    let key_hdr = ngc::container::parse_ngciso_header(&cbor_bytes)
        .map_err(|e| format!("hdr: {}", e))?;

    let ct = &cbor_bytes[key_hdr.payload_offset..];
    let iv = &key_hdr.iv;

    // 2. 尝试多种 PIN 编码 × 两种 salt
    let prot_params = get_protector_params(container_path).ok();
    let mut all_entropies: Vec<(String, Vec<u8>)> = Vec::new();

    // 用 key 自己的 salt
    for (enc_name, ent) in ngc::pin::derive_entropy_all_variants(pin, &key_hdr.salt, key_hdr.rounds) {
        all_entropies.push((format!("key_salt+{enc_name}"), ent));
    }
    // 用 protector 的 salt
    if let Some((ref prot_salt, prot_rounds)) = &prot_params {
        for (enc_name, ent) in ngc::pin::derive_entropy_all_variants(pin, prot_salt, *prot_rounds) {
            all_entropies.push((format!("prot_salt+{enc_name}"), ent));
        }
    }

    for (variant, entropy) in &all_entropies {
        if let Some((_method, pt)) = ngc::try_multiple_key_derivations(entropy, iv, ct) {
            return Ok(pt);
        }
    }

    let prot_salt_hex = prot_params.as_ref()
        .map(|(s,_)| format!("{:02X?}", s.iter().take(8).collect::<Vec<_>>()))
        .unwrap_or_else(|| "none".to_string());
    Err(format!("key decrypt: all derivations failed [key_salt={:02X?}.. prot_salt={}.. iv={:02X?}.. ct_len={}]",
        &key_hdr.salt.iter().take(8).collect::<Vec<_>>(),
        prot_salt_hex,
        &iv.iter().take(8).collect::<Vec<_>>(),
        ct.len()))
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
    // p256 crate 原生签名（BCryptImportKeyPair 在 25H2/windows-rs 0.59 有兼容问题）
    use p256::SecretKey;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    let sk = SecretKey::from_bytes(d.into())
        .map_err(|e| format!("invalid P256 private key: {e}"))?;
    let signing_key: SigningKey = sk.into();
    use p256::ecdsa::Signature;
    let sig: Signature = signing_key.sign(hash);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// 将 raw 32-byte P256 私钥转换为 BCRYPT_ECCPRIVATE_BLOB
fn raw_d_to_ecc_private_blob(d: &[u8]) -> Result<Vec<u8>, String> {
    use p256::{
        elliptic_curve::sec1::ToEncodedPoint,
        SecretKey,
    };

    if d.len() != 32 {
        return Err(format!("raw P256 key: expected 32 bytes, got {}", d.len()));
    }

    let sk = SecretKey::from_bytes(d.into())
        .map_err(|e| format!("invalid P256 private key: {e}"))?;
    let pub_key = sk.public_key();
    let point = pub_key.to_encoded_point(false);
    let x = point.x().ok_or("no x coordinate")?;
    let y = point.y().ok_or("no y coordinate")?;

    // BCRYPT_ECCPRIVATE_BLOB 格式:
    // dwMagic (4) = BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32434345 ("ECC2")
    // cbKey   (4) = 32
    // X       (32)
    // Y       (32)
    // d       (32)
    // Total:  104 bytes
    let mut blob = Vec::with_capacity(104);
    blob.extend_from_slice(&0x32434345u32.to_le_bytes()); // dwMagic
    blob.extend_from_slice(&32u32.to_le_bytes());          // cbKey
    blob.extend_from_slice(x.as_slice());                   // X
    blob.extend_from_slice(y.as_slice());                   // Y
    blob.extend_from_slice(d);                              // d
    Ok(blob)
}

/// PKCS#8 DER-encoded EC private key → sign
fn pkcs8_ecdsa_sign(der: &[u8], hash: &[u8]) -> Result<Vec<u8>, String> {
    // 用 BCrypt 导入 PKCS#8 格式并签名
    use windows::Win32::Security::Cryptography::{
        BCryptOpenAlgorithmProvider, BCryptImportKeyPair, BCryptSignHash,
        BCryptDestroyKey, BCryptCloseAlgorithmProvider,
        BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECCPRIVATE_BLOB,
        BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_FLAGS,
    };

    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        if BCryptOpenAlgorithmProvider(
            &mut alg, BCRYPT_ECDSA_P256_ALGORITHM, None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        ).is_err() {
            return Err("BCryptOpenAlgorithmProvider(ECDSA_P256) failed".to_string());
        }

        let mut key = BCRYPT_KEY_HANDLE::default();
        let import_result = BCryptImportKeyPair(
            alg, None, BCRYPT_ECCPRIVATE_BLOB, &mut key, der, 0,
        );
        if import_result.is_err() {
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return Err(format!("BCryptImportKeyPair(PKCS#8) failed: {import_result:?}"));
        }

        let mut sig_size = 0u32;
        let _ = BCryptSignHash(key, None, hash, None, &mut sig_size, BCRYPT_FLAGS(0));
        if sig_size == 0 || sig_size > 1024 {
            let _ = BCryptDestroyKey(key);
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return Err(format!("BCryptSignHash size query: {sig_size}"));
        }

        let mut sig = vec![0u8; sig_size as usize];
        if BCryptSignHash(key, None, hash, Some(&mut sig), &mut sig_size, BCRYPT_FLAGS(0)).is_err() {
            let _ = BCryptDestroyKey(key);
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return Err("BCryptSignHash failed".to_string());
        }
        sig.truncate(sig_size as usize);
        let _ = BCryptDestroyKey(key);
        let _ = BCryptCloseAlgorithmProvider(alg, 0);
        Ok(raw_ecdsa_to_der(&sig))
    }
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

/// 尝试从 pin_store 数据库加载存储的 PIN（用于自动解密新凭据）
fn try_load_pin_from_db(exe_dir: &Path) -> Option<String> {
    let db_path = exe_dir.join("database.db");
    let conn = rusqlite::Connection::open(&db_path).ok()?;

    let mut stmt = conn
        .prepare("SELECT pin_blob, pin_entropy FROM pin_store WHERE enabled = 1 LIMIT 1")
        .ok()?;

    let (blob_b64, entropy_b64): (String, String) = stmt
        .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
        .ok()?;

    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(&blob_b64).ok()?;
    let entropy = base64::engine::general_purpose::STANDARD.decode(&entropy_b64).ok()?;

    // DPAPI 解密（SYSTEM 上下文，LOCAL_MACHINE 标志）
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
        CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let ent = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

    unsafe {
        let r = CryptUnprotectData(
            &data_in, None, Some(&ent as *const _), None, None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut data_out,
        );
        if r.is_err() || data_out.pbData.is_null() { return None; }
        let pin = String::from_utf8(
            std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
        ).ok()?;
        let _ = windows::Win32::Foundation::LocalFree(Some(
            windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut std::ffi::c_void)
        ));
        Some(pin)
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
