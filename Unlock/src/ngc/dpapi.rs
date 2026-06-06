//! Win32 DPAPI / CNG 薄封装
//!
//! Unlock.exe 以 SYSTEM 身份运行，可直接调用：
//! - `CryptUnprotectData` — DPAPI 解密（用 PIN 派生的 entropy）
//! - `BCrypt*` — CNG RSA OAEP 解密操作
//!
//! 相比于离线重写 DPAPI masterkey 解析，这里直接使用活体 SYSTEM
//! 的加密 API，无需自行推导 masterkey。
//!
//! # RSA 私钥文件
//!
//! NGC RSA 私钥以 DPAPI 加密 blob 形式存储在：
//! ```text
//! %WINDIR%\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys\<key_id>
//! ```
//!
//! 解密后得到 CNG `BCRYPT_RSAKEY_BLOB` 格式的私钥（可由
//! `BCryptImportKeyPair` 直接导入）。

use std::path::Path;

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    // DPAPI
    CryptUnprotectData, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_UI_FORBIDDEN,
    // BCrypt algorithm provider
    BCryptOpenAlgorithmProvider, BCryptCloseAlgorithmProvider,
    BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_RSA_ALGORITHM,
    // BCrypt key import
    BCryptImportKeyPair, BCryptDestroyKey,
    BCRYPT_KEY_HANDLE,
    BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAFULLPRIVATE_BLOB,
    // BCrypt OAEP decrypt
    BCryptDecrypt, BCRYPT_PAD_OAEP,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM,
};

use super::NgcError;

// ─── DPAPI decrypt ─────────────────────────────────────────────────────────────

/// 使用 DPAPI 解密密文（带 entropy）。
///
/// # Arguments
/// * `data` — DPAPI 加密的数据
/// * `entropy` — PIN 派生的 entropy（用作 DPAPI 的 optional entropy）
///
/// # Returns
/// 解密后的明文数据
pub fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
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

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // CryptUnprotectData 返回 windows_core::Result<()>
    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            None, // ppszDataDescr — 不需要描述
            entropy_blob.as_ref().map(|b| b as *const _), // pOptionalEntropy
            None, // pvReserved
            None, // pPromptStruct — 无 UI
            CRYPTPROTECT_UI_FORBIDDEN, // dwFlags — 禁止 UI 弹窗
            &mut data_out,
        )
    };

    if result.is_err() {
        return Err(NgcError::DecryptionFailed(
            "DPAPI 解密失败，PIN 可能错误".to_string(),
        ));
    }

    // 复制解密后的数据
    let plaintext = unsafe {
        if data_out.pbData.is_null() || data_out.cbData == 0 {
            return Err(NgcError::DecryptionFailed(
                "DPAPI 返回空数据".to_string(),
            ));
        }
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };

    // 释放 DPAPI 分配的内存（CryptUnprotectData 用 LocalAlloc 分配）
    unsafe {
        let _ = LocalFree(Some(HLOCAL(data_out.pbData as *mut _)));
    }

    Ok(plaintext)
}

// ─── RSA key DPAPI decrypt ─────────────────────────────────────────────────────

/// 从文件读取并 DPAPI 解密 RSA 密钥。
///
/// RSA 私钥以 DPAPI 加密 blob 形式存储在：
/// `%WINDIR%\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys\<key_id>`
///
/// # Arguments
/// * `blob_path` — 密钥 blob 文件路径
/// * `entropy` — PIN 派生的 entropy
///
/// # Returns
/// 解密后的 RSA 私钥数据（CNG `BCRYPT_RSAKEY_BLOB` 格式）
pub fn unprotect_rsa_key(blob_path: &Path, entropy: &[u8]) -> Result<Vec<u8>, NgcError> {
    let encrypted_blob = std::fs::read(blob_path)?;
    dpapi_unprotect(&encrypted_blob, entropy)
}

// ─── RSA OAEP decrypt ──────────────────────────────────────────────────────────

/// 使用 CNG `BCryptDecrypt` 进行 RSA-OAEP 解密。
///
/// # Arguments
/// * `key_blob` — DPAPI 解密后的 RSA 私钥（CNG `BCRYPT_RSAKEY_BLOB` 格式，
///   即 `BCRYPT_RSAPRIVATE_BLOB` 或 `BCRYPT_RSAFULLPRIVATE_BLOB`）
/// * `ciphertext` — OAEP 加密的密文（RSA 模长长度，2048-bit=256 字节）
///
/// # Returns
/// RSA OAEP 解密后的明文（NGC vault 中为 32 字节 AES-256 密钥）
pub fn rsa_oaep_decrypt(key_blob: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NgcError> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    // ── Step 1: 打开 RSA 算法提供程序 ────────────────────────────────────
    let mut alg_handle = BCRYPT_ALG_HANDLE::default();
    if unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_RSA_ALGORITHM,
            None, // pszImplementation — 使用系统默认实现
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
    }
    .is_err()
    {
        return Err(NgcError::DecryptionFailed(
            "BCryptOpenAlgorithmProvider 失败".to_string(),
        ));
    }

    // ── Step 2: 导入 RSA 私钥 ────────────────────────────────────────────
    // NGC 密钥可能使用 RSAPRIVATEBLOB（含私钥指数 d）或
    // RSAFULLPRIVATEBLOB（含 CRT 参数 p/q/dp/dq/inverseQ）。
    // 优先尝试标准 RSAPRIVATEBLOB，失败时回退到 RSAFULLPRIVATEBLOB。
    let mut key_handle = BCRYPT_KEY_HANDLE::default();
    let key_imported = {
        let r1 = unsafe {
            BCryptImportKeyPair(
                alg_handle,
                None, // hImportKey — 无包装密钥
                BCRYPT_RSAPRIVATE_BLOB,
                &mut key_handle,
                key_blob,
                0, // dwFlags
            )
        };
        if r1.is_ok() {
            true
        } else {
            let r2 = unsafe {
                BCryptImportKeyPair(
                    alg_handle,
                    None,
                    BCRYPT_RSAFULLPRIVATE_BLOB,
                    &mut key_handle,
                    key_blob,
                    0,
                )
            };
            r2.is_ok()
        }
    };

    if !key_imported {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
        }
        return Err(NgcError::DecryptionFailed(
            "BCryptImportKeyPair 失败：无法导入 RSA 私钥（尝试了 \
             RSAPRIVATEBLOB 和 RSAFULLPRIVATEBLOB）"
                .to_string(),
        ));
    }

    // 共用清理闭包：先销毁 key，再关闭 provider
    let cleanup = || unsafe {
        let _ = BCryptDestroyKey(key_handle);
        let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    // ── Step 3: OAEP 解密 ─────────────────────────────────────────────────
    // NGC 的 OAEP padding 使用 SHA-256 哈希算法。BCRYPT_OAEP_PADDING_INFO
    // 对应于 Win32 BCRYPT_OAEP_PADDING_INFO 结构体。
    let padding_info = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(), // 无标签（标准 OAEP 行为）
        cbLabel: 0,
    };

    // 3a: 查询输出缓冲区大小。
    //     首次调用 pbOutput=None，BCryptDecrypt 返回
    //     STATUS_BUFFER_TOO_SMALL 并通过 pcbResult 返回所需大小。
    let mut result_size = 0u32;
    let _ = unsafe {
        BCryptDecrypt(
            key_handle,
            Some(ciphertext), // pbInput — 待解密密文
            Some(&padding_info as *const _ as *const core::ffi::c_void), // pPaddingInfo
            None,  // pbIV — OAEP 无需 IV
            None,  // pbOutput — null 以查询所需大小
            &mut result_size, // pcbResult
            BCRYPT_PAD_OAEP, // dwFlags
        )
    };

    if result_size == 0 || result_size > 4096 {
        cleanup();
        return Err(NgcError::DecryptionFailed(format!(
            "BCryptDecrypt 查询输出大小失败（size={}）",
            result_size
        )));
    }

    // 3b: 实际解密
    let mut output = vec![0u8; result_size as usize];
    let mut actual_size = 0u32;
    if unsafe {
        BCryptDecrypt(
            key_handle,
            Some(ciphertext),
            Some(&padding_info as *const _ as *const core::ffi::c_void),
            None,
            Some(&mut output), // pbOutput — 解密缓冲区
            &mut actual_size,
            BCRYPT_PAD_OAEP,
        )
    }
    .is_err()
    {
        cleanup();
        return Err(NgcError::DecryptionFailed(
            "BCryptDecrypt OAEP 解密失败".to_string(),
        ));
    }

    output.truncate(actual_size as usize);

    // ── Cleanup ───────────────────────────────────────────────────────────
    cleanup();

    Ok(output)
}

// ─── AES-256-CBC decrypt ───────────────────────────────────────────────────────

/// AES-256-CBC 解密（用于 vault 数据解密）。
///
/// 使用纯 Rust `aes` + `cbc` crate 实现，避免额外 CNG 调用。
///
/// # Arguments
/// * `key` — 32 字节 AES-256 密钥
/// * `iv` — 16 字节初始向量
/// * `ciphertext` — AES-CBC 加密的密文（16 字节对齐，含 PKCS7 padding）
///
/// # Returns
/// 移除 PKCS7 padding 后的明文
pub fn aes256_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NgcError> {
    use aes::cipher::KeyIvInit;

    // ── 参数验证 ──────────────────────────────────────────────────────────
    if key.len() != 32 {
        return Err(NgcError::DecryptionFailed(format!(
            "AES-256 密钥长度不正确: {}（应为 32）",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(NgcError::DecryptionFailed(format!(
            "AES IV 长度不正确: {}（应为 16）",
            iv.len()
        )));
    }
    if ciphertext.len() < 16 || ciphertext.len() % 16 != 0 {
        return Err(NgcError::DecryptionFailed(
            "密文长度不是 16 的倍数（需要 PKCS7 padding）".to_string(),
        ));
    }

    // ── 创建解密器并逐块解密 ──────────────────────────────────────────────
    type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

    let mut decryptor = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|_| NgcError::DecryptionFailed("创建 AES 解密器失败".to_string()))?;

    let mut buf = ciphertext.to_vec();

    use aes::cipher::BlockDecryptMut;
    for chunk in buf.chunks_exact_mut(16) {
        let block = aes::cipher::Block::<aes::Aes256>::from_mut_slice(chunk);
        decryptor.decrypt_block_mut(block);
    }

    // ── 移除 PKCS7 padding ───────────────────────────────────────────────
    let pad_len = *buf.last().unwrap_or(&0) as usize;
    if pad_len > 0 && pad_len <= 16 {
        buf.truncate(buf.len() - pad_len);
    }

    Ok(buf)
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── dpapi_unprotect ───────────────────────────────────────────────────

    /// DPAPI 解密需要 SYSTEM 上下文（Unlock.exe 以 SYSTEM 运行）。
    /// 此测试仅在安装了 DPAPI 加密测试数据的环境中有意义。
    #[test]
    fn test_dpapi_unprotect_empty_data() {
        // 空数据或空 entropy 不应 panic
        let data: &[u8] = &[];
        let entropy: &[u8] = &[];
        let result = dpapi_unprotect(data, entropy);
        // 预期失败（空数据无法解密），而非 panic
        assert!(result.is_err());
    }

    // ─── rsa_oaep_decrypt ──────────────────────────────────────────────────

    #[test]
    fn test_rsa_oaep_decrypt_empty_ciphertext() {
        let key_blob = b"\x52\x53\x41\x32"; // fake "RSA2" magic
        let result = rsa_oaep_decrypt(key_blob, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_rsa_oaep_decrypt_empty_key() {
        let ciphertext = b"some encrypted data that is long enough 1234";
        let result = rsa_oaep_decrypt(&[], ciphertext);
        assert!(result.is_err());
    }

    // ─── aes256_cbc_decrypt ────────────────────────────────────────────────

    #[test]
    fn test_aes256_cbc_decrypt_bad_key_len() {
        let short_key = b"too short";
        let iv = [0u8; 16];
        let ct = [0u8; 32];
        assert!(aes256_cbc_decrypt(short_key, &iv, &ct).is_err());
    }

    #[test]
    fn test_aes256_cbc_decrypt_bad_iv_len() {
        let key = [0u8; 32];
        let short_iv = b"short";
        let ct = [0u8; 32];
        assert!(aes256_cbc_decrypt(&key, short_iv, &ct).is_err());
    }

    #[test]
    fn test_aes256_cbc_decrypt_unaligned() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let ct = b"not a multiple of 16 bytes!";
        assert!(aes256_cbc_decrypt(&key, &iv, ct).is_err());
    }

    /// Round-trip: AES-256-CBC encrypt then decrypt with known key/IV/PKCS7.
    #[test]
    fn test_aes256_cbc_roundtrip() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        use cbc::Encryptor;

        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let iv = b"1234567890abcdef"; // 16 bytes
        let plaintext = b"Hello, NGC vault!";

        // PKCS7 pad to 16-byte boundary
        let padded_len = ((plaintext.len() / 16) + 1) * 16;
        let pad_byte = (padded_len - plaintext.len()) as u8;
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat(pad_byte).take(pad_byte as usize));

        // Encrypt
        let mut encryptor =
            Encryptor::<aes::Aes256>::new_from_slices(key, iv).unwrap();
        for chunk in padded.chunks_exact_mut(16) {
            let block = aes::cipher::Block::<aes::Aes256>::from_mut_slice(chunk);
            encryptor.encrypt_block_mut(block);
        }

        // Decrypt — our function under test
        let decrypted = aes256_cbc_decrypt(key, iv, &padded).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&decrypted),
            String::from_utf8_lossy(plaintext),
        );
    }
}
