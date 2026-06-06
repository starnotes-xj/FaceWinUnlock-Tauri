//! FIDO2 assertion 签名器
//!
//! 复用 Phase 1 的 `ngc` 模块：
//! 1. 用 PIN 解出 NGC RSA 私钥（ngc::recover_password 同款 DPAPI 链路）
//! 2. 枚举 NGC 容器中的 FIDO_AUTHENTICATOR 凭据
//! 3. 用 CNG BCrypt 签名 assertion

use crate::ngc;
use super::fido2;

/// 可用的 FIDO2 凭据信息
#[derive(Debug, Clone)]
pub struct FidoCredential {
    /// Base64url 凭据 ID（WebAuthn credential ID）
    pub credential_id: String,
    /// NGC 容器中对应的私钥名称
    pub key_name: String,
    /// 关联的用户名
    pub user_name: String,
    /// 关联的用户 SID
    pub user_sid: String,
    /// NGC 容器 GUID
    pub container_guid: String,
}

/// 对 assertion 请求生成签名
///
/// # Arguments
/// * `pin` — 用户输入的 Windows Hello PIN
/// * `request` — 浏览器传来的 assertion 请求
/// * `credential_id` — 选定的凭据 ID
/// * `sign_count` — 当前签名计数器
/// * `db_path` — 数据库路径（用于持久化 signCount）
///
/// # Returns
/// 构造好的 AssertionResponse
pub fn sign_assertion(
    pin: &str,
    request: &fido2::AssertionRequest,
    credential_id: &str,
    sign_count: u32,
) -> Result<fido2::AssertionResponse, String> {
    // 1. 枚举 NGC 中的 FIDO 凭据，找到匹配的 credential_id
    let credentials = enumerate_fido_credentials()?;
    let cred = credentials
        .iter()
        .find(|c| c.credential_id == credential_id)
        .ok_or_else(|| format!("未找到凭据: {}", credential_id))?;

    // 2. 用 PIN 解密 FIDO 私钥
    let fido_key = extract_fido_key(pin, &cred.user_sid, &cred.key_name)?;

    // 3. 构造 authenticatorData
    let auth_data = fido2::build_authenticator_data(&request.rp_id, sign_count);

    // 4. 构造 clientDataJSON
    let client_json = fido2::build_client_data_json(&request.challenge, &request.origin);

    // 5. 计算待签名数据
    let to_sign = fido2::build_to_be_signed(&auth_data, &client_json);

    // 6. 用 CNG 签名
    let signature = sign_with_cng(&fido_key, &to_sign)?;

    // 7. Base64url 编码各字段
    Ok(fido2::AssertionResponse {
        id: credential_id.to_string(),
        raw_id: credential_id.to_string(),
        authenticator_data: fido2::base64url(&auth_data),
        client_data_json: fido2::base64url(client_json.as_bytes()),
        signature: fido2::base64url(&signature),
        user_handle: None,
        cred_type: "public-key".to_string(),
    })
}

/// 枚举 NGC 容器中的 FIDO2 凭据
///
/// NGC 容器中 FIDO2 密钥以 `FIDO_AUTHENTICATOR//<rpId>//<credId>` 格式命名。
/// 对应 Shwmae 中的 FIDO key enumeration 逻辑。
pub fn enumerate_fido_credentials() -> Result<Vec<FidoCredential>, String> {
    use std::fs;
    use std::path::Path;

    let ngc_root = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
    let ngc_dir = Path::new(ngc_root);
    if !ngc_dir.is_dir() {
        return Err("NGC 目录不可访问，请以 SYSTEM 权限运行".to_string());
    }

    let mut credentials = Vec::new();

    for entry in fs::read_dir(ngc_dir).map_err(|e| format!("读取 NGC 目录失败: {}", e))? {
        let entry = entry.map_err(|e| format!("目录条目错误: {}", e))?;
        let container = entry.path();
        if !container.is_dir() {
            continue;
        }

        let container_guid = container
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        // 查找容器对应的用户名和 SID
        let (user_name, user_sid) = match resolve_container_owner(&container_guid) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // 扫描 NGC 容器中的 FIDO 密钥
        let protectors_dir = container.join("protectors");
        if !protectors_dir.is_dir() {
            continue;
        }

        // TODO: 枚举 FIDO_AUTHENTICATOR 密钥
        // 实际的 FIDO key 信息存储在 NGC 容器的 protectors 或单独的
        // key 存储中。具体格式需要在实际 NGC 测试机上验证。
        //
        // Shwmae 的做法：
        // - 遍历容器中所有 key
        // - 筛选名称以 "FIDO_AUTHENTICATOR//" 开头的
        // - 从 key 名称中解析 rpId 和 credentialId
    }

    Ok(credentials)
}

/// 解析 NGC 容器对应的用户名和 SID
fn resolve_container_owner(_container_guid: &str) -> Result<(String, String), String> {
    // TODO: 通过 NGC 容器属性或注册表反查容器所有者
    // 实现方式：
    // 1. 读取容器中的 metadata 文件
    // 2. 或遍历 ProfileList 查找匹配的 SID
    Err("容器所有者解析暂未实现".to_string())
}

/// 用 PIN 解密 NGC 中的 FIDO2 私钥
fn extract_fido_key(pin: &str, sid: &str, key_name: &str) -> Result<Vec<u8>, String> {
    // 复用 ngc 模块的 DPAPI 解密链路
    // 1. 定位 NGC 容器
    // 2. 用 PIN 派生 entropy
    // 3. DPAPI 解密 FIDO key blob

    let (_username, _password, _domain) = ngc::recover_password(sid, pin)
        .map_err(|e| format!("NGC 解密失败: {}", e))?;

    // FIDO2 私钥解密路径需要单独实现——它和账户密码使用
    // 不同的 NGC protector（FIDO 密钥而非密码加密密钥）。
    Err(format!("FIDO 密钥提取暂未实现（key: {}）", key_name))
}

/// 使用 CNG BCrypt 对数据进行 RSA 签名
///
/// windows-rs 0.59: BCryptSignHash 的 pbInput 接受 `&[u8]`（非 Option）。
#[allow(dead_code)]
fn sign_with_cng(key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::{
        BCryptOpenAlgorithmProvider, BCryptImportKeyPair, BCryptSignHash,
        BCryptDestroyKey, BCryptCloseAlgorithmProvider,
        BCRYPT_RSA_ALGORITHM, BCRYPT_RSAPRIVATE_BLOB,
        BCRYPT_PAD_PKCS1, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    };

    unsafe {
        // Step 1: 打开 RSA 算法提供程序
        let mut alg_handle = BCRYPT_ALG_HANDLE::default();
        if BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_RSA_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
        .is_err()
        {
            return Err("BCryptOpenAlgorithmProvider 失败".to_string());
        }

        // Step 2: 导入私钥
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        if BCryptImportKeyPair(
            alg_handle,
            None,
            BCRYPT_RSAPRIVATE_BLOB,
            &mut key_handle,
            key_blob,
            0,
        )
        .is_err()
        {
            let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err("BCryptImportKeyPair 失败".to_string());
        }

        // Step 3: 签名（windows-rs 0.59: pbInput is &[u8], not Option）
        let mut sig_size = 0u32;
        let _ = BCryptSignHash(
            key_handle,
            None,
            data,            // &[u8] — not Option<&[u8]>
            None,
            &mut sig_size,
            BCRYPT_PAD_PKCS1,
        );

        if sig_size == 0 || sig_size > 4096 {
            let _ = BCryptDestroyKey(key_handle);
            let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err(format!("BCryptSignHash 查询大小异常: {}", sig_size));
        }

        let mut signature = vec![0u8; sig_size as usize];
        if BCryptSignHash(
            key_handle,
            None,
            data,                       // &[u8]
            Some(&mut signature),
            &mut sig_size,
            BCRYPT_PAD_PKCS1,
        )
        .is_err()
        {
            let _ = BCryptDestroyKey(key_handle);
            let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err("BCryptSignHash 签名失败".to_string());
        }

        signature.truncate(sig_size as usize);

        let _ = BCryptDestroyKey(key_handle);
        let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);

        Ok(signature)
    }
}
