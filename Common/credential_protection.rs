use std::slice;

use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation::{LocalFree, BOOL, ERROR_FILE_NOT_FOUND, HLOCAL, WIN32_ERROR},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_REGISTRY_KEY,
            },
            Cryptography::{
                BCryptGenRandom, CryptProtectData, CryptUnprotectData,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG, CRYPTPROTECT_LOCAL_MACHINE,
                CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
            },
            GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
        System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
            HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WOW64_64KEY, REG_BINARY,
            REG_OPTION_NON_VOLATILE, REG_VALUE_TYPE,
        },
    },
};

pub const CREDENTIAL_PREFIX: &str = "FWDP1:";
const REGISTRY_KEY_PATH: &str = r"SOFTWARE\facewinunlock-tauri\CredentialProtection";
const REGISTRY_SECURITY_PATH: &str = r"MACHINE\SOFTWARE\facewinunlock-tauri\CredentialProtection";
const ENTROPY_LENGTH: usize = 32;

pub fn is_protected_credential(value: &str) -> bool {
    value.starts_with(CREDENTIAL_PREFIX)
}

pub fn load_credential_entropy(create_if_missing: bool) -> Result<Option<Vec<u8>>, String> {
    let mut key = HKEY::default();
    let access = if create_if_missing {
        KEY_ALL_ACCESS | KEY_WOW64_64KEY
    } else {
        KEY_READ | KEY_WOW64_64KEY
    };
    let key_path: Vec<u16> = REGISTRY_KEY_PATH
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let status = unsafe {
        if create_if_missing {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(key_path.as_ptr()),
                None,
                w!(""),
                REG_OPTION_NON_VOLATILE,
                access,
                None,
                &mut key,
                None,
            )
        } else {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(key_path.as_ptr()),
                None,
                access,
                &mut key,
            )
        }
    };
    if status == ERROR_FILE_NOT_FOUND && !create_if_missing {
        return Ok(None);
    }
    if status != WIN32_ERROR(0) {
        return Err(format!("打开凭据密钥注册表项失败: 0x{:08X}", status.0));
    }
    let key_guard = RegistryKey(key);

    if create_if_missing {
        protect_registry_key()?;
    }

    let mut value_type = REG_VALUE_TYPE(0);
    let mut value_length = 0u32;
    let query_status = unsafe {
        RegQueryValueExW(
            key_guard.0,
            w!("Entropy"),
            None,
            Some(&mut value_type),
            None,
            Some(&mut value_length),
        )
    };
    if query_status == ERROR_FILE_NOT_FOUND && create_if_missing {
        let mut entropy = vec![0u8; ENTROPY_LENGTH];
        let random_status =
            unsafe { BCryptGenRandom(None, &mut entropy, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if random_status.0 < 0 {
            return Err(format!(
                "生成凭据密钥失败: 0x{:08X}",
                random_status.0 as u32
            ));
        }
        let write_status =
            unsafe { RegSetValueExW(key_guard.0, w!("Entropy"), None, REG_BINARY, Some(&entropy)) };
        if write_status != WIN32_ERROR(0) {
            return Err(format!("保存凭据密钥失败: 0x{:08X}", write_status.0));
        }
        return Ok(Some(entropy));
    }
    if query_status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if query_status != WIN32_ERROR(0) {
        return Err(format!("读取凭据密钥失败: 0x{:08X}", query_status.0));
    }
    if value_type != REG_BINARY || value_length as usize != ENTROPY_LENGTH {
        return Err("凭据密钥注册表值格式无效".to_string());
    }

    let mut entropy = vec![0u8; value_length as usize];
    let read_status = unsafe {
        RegQueryValueExW(
            key_guard.0,
            w!("Entropy"),
            None,
            Some(&mut value_type),
            Some(entropy.as_mut_ptr()),
            Some(&mut value_length),
        )
    };
    if read_status != WIN32_ERROR(0)
        || value_type != REG_BINARY
        || value_length as usize != ENTROPY_LENGTH
    {
        return Err(format!("读取凭据密钥失败: 0x{:08X}", read_status.0));
    }
    Ok(Some(entropy))
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

fn protect_registry_key() -> Result<(), String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;;KA;;;SY)(A;;KA;;;BA)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|error| format!("创建凭据密钥 ACL 失败: {error}"))?;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut dacl_present = BOOL::from(false);
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut dacl_defaulted = BOOL::from(false);
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
        .map_err(|error| format!("读取凭据密钥 ACL 失败: {error}"))?;
    }
    if !dacl_present.as_bool() || dacl.is_null() {
        return Err("凭据密钥 ACL 不包含有效 DACL".to_string());
    }

    let path: Vec<u16> = REGISTRY_SECURITY_PATH
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if result != WIN32_ERROR(0) {
        return Err(format!("限制凭据密钥注册表权限失败: 0x{:08X}", result.0));
    }
    Ok(())
}

pub fn unprotect_stored_credential(value: &str) -> Result<String, String> {
    let encoded = value
        .strip_prefix(CREDENTIAL_PREFIX)
        .ok_or_else(|| "凭据不是受保护格式".to_string())?;
    let mut entropy =
        load_credential_entropy(false)?.ok_or_else(|| "凭据密钥不可用".to_string())?;
    let result = unprotect_with_entropy(encoded, &entropy);
    crate::zeroization::zeroize_bytes(&mut entropy);
    result
}

pub fn protect_with_entropy(plaintext: &str, entropy: &[u8]) -> Result<String, String> {
    let payload_length = plaintext
        .len()
        .checked_add(1)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| "凭据长度超出限制".to_string())?;
    let entropy_length =
        u32::try_from(entropy.len()).map_err(|_| "密钥熵长度超出限制".to_string())?;
    let mut payload = Vec::with_capacity(payload_length as usize);
    payload.push(1); // Version marker also gives empty Windows passwords a non-empty DPAPI input.
    payload.extend_from_slice(plaintext.as_bytes());
    let input = CRYPT_INTEGER_BLOB {
        cbData: payload_length,
        pbData: payload.as_ptr() as *mut u8,
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_length,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let protect_result = unsafe {
        CryptProtectData(
            &input,
            w!("FaceWinUnlock Windows credential"),
            Some(&entropy_blob),
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    crate::zeroization::zeroize_bytes(&mut payload);
    protect_result.map_err(|error| format!("保护 Windows 凭据失败: {error}"))?;
    let encrypted = if output.cbData == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }
    };
    let encoded = format!("{CREDENTIAL_PREFIX}{}", encode_hex(encrypted));
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
    }
    Ok(encoded)
}

pub fn unprotect_with_entropy(encoded: &str, entropy: &[u8]) -> Result<String, String> {
    let encrypted = decode_hex(encoded)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(encrypted.len()).map_err(|_| "密文长度超出限制")?,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(entropy.len()).map_err(|_| "密钥熵长度超出限制")?,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy_blob),
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|error| format!("解封 Windows 凭据失败: {error}"))?;
    }
    let mut payload = if output.cbData == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec()
    };
    unsafe {
        if !output.pbData.is_null() && output.cbData > 0 {
            crate::zeroization::zeroize_bytes(slice::from_raw_parts_mut(
                output.pbData,
                output.cbData as usize,
            ));
        }
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
    }
    let result = match payload.strip_prefix(&[1]) {
        Some(plaintext) => match String::from_utf8(plaintext.to_vec()) {
            Ok(plaintext) => Ok(plaintext),
            Err(error) => {
                let mut invalid = error.into_bytes();
                crate::zeroization::zeroize_bytes(&mut invalid);
                Err("解封后的凭据不是有效 UTF-8".to_string())
            }
        },
        None => Err("解封后的凭据版本无效".to_string()),
    };
    crate::zeroization::zeroize_bytes(&mut payload);
    result
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err("凭据密文格式无效".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| "凭据密文格式无效".to_string())?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| "凭据密文格式无效".to_string())?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ENTROPY: &[u8] = b"FaceWinUnlock test entropy";

    #[test]
    fn dpapi_credentials_round_trip_and_reject_corruption() {
        for password in ["not-a-real-windows-password", ""] {
            let protected = protect_with_entropy(password, TEST_ENTROPY).unwrap();
            assert!(is_protected_credential(&protected));
            assert!(!protected.contains("not-a-real-windows-password"));
            let encoded = protected.strip_prefix(CREDENTIAL_PREFIX).unwrap();
            assert_eq!(
                unprotect_with_entropy(encoded, TEST_ENTROPY).unwrap(),
                password
            );
            assert!(unprotect_with_entropy(encoded, b"wrong entropy").is_err());
        }
    }
}
