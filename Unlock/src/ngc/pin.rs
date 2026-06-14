//! Windows Hello PIN → DPAPI entropy 派生
//!
//! 参考 Shwmae `Ngc/NgcPin.cs` 的实现：
//! 1. PIN → ASCII 字节 → 大写十六进制字符串 → UTF-16LE
//! 2. PBKDF2-HMAC-SHA256 派生 32 字节
//! 3. 结果 → 十六进制小写字符串 → UTF-16LE
//! 4. SHA-512 哈希
//! 5. 前置固定熵 "xT5rZW5qVVbrvpuA\0"

use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512, Digest};

use super::NgcError;

/// Windows Hello PIN 的固定熵前缀（null-terminated）
const FIXED_ENTROPY_PREFIX: &[u8] = b"xT5rZW5qVVbrvpuA\0";

/// 从明文 PIN 和 protector 参数派生 DPAPI entropy（Shwmae 原始方法）
pub fn derive_entropy(pin: &str, salt: &[u8], rounds: u32) -> Result<Vec<u8>, NgcError> {
    derive_with_pin_encoding(pin, salt, rounds, PinEncoding::HexUtf16)
}

/// PIN 编码变体——KDF 差异的关键
#[derive(Clone, Copy)]
pub enum PinEncoding {
    HexUtf16,   // hex(PIN) → UTF-16LE (Shwmae 原始方法)
    RawUtf16,   // PIN → UTF-16LE 直接
    RawBytes,   // PIN → 原始 ASCII 字节
    HexLower,   // hex(PIN, lowercase) → UTF-16LE
}

/// 用指定的 PIN 编码方式派生 DPAPI entropy
fn derive_with_pin_encoding(
    pin: &str, salt: &[u8], rounds: u32, encoding: PinEncoding
) -> Result<Vec<u8>, NgcError> {
    let pbkdf2_input = match encoding {
        PinEncoding::HexUtf16 => {
            let pin_hex: String = pin.as_bytes().iter().map(|b| format!("{:02X}", b)).collect();
            to_utf16le_bytes(&pin_hex)
        }
        PinEncoding::RawUtf16 => to_utf16le_bytes(pin),
        PinEncoding::RawBytes => pin.as_bytes().to_vec(),
        PinEncoding::HexLower => {
            let pin_hex: String = pin.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
            to_utf16le_bytes(&pin_hex)
        }
    };

    // PBKDF2-HMAC-SHA256 → 32 bytes
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&pbkdf2_input, salt, rounds, &mut derived);

    // derived → hex UPPERCASE → UTF-16LE → SHA-512
    let derived_hex: String = derived.iter().map(|b| format!("{:02X}", b)).collect();
    let derived_utf16le = to_utf16le_bytes(&derived_hex);
    let mut hasher = Sha512::new();
    hasher.update(&derived_utf16le);
    let hash = hasher.finalize();

    // 前置固定熵 "xT5rZW5qVVbrvpuA\0"
    let mut entropy = Vec::with_capacity(FIXED_ENTROPY_PREFIX.len() + hash.len());
    entropy.extend_from_slice(FIXED_ENTROPY_PREFIX);
    entropy.extend_from_slice(&hash);
    Ok(entropy)
}

/// 尝试所有 PIN 编码方式，返回所有成功派生的 entropy 变体
pub fn derive_entropy_all_variants(
    pin: &str, salt: &[u8], rounds: u32
) -> Vec<(String, Vec<u8>)> {
    use PinEncoding::*;
    let encodings = [
        ("HexUtf16", HexUtf16),
        ("RawUtf16", RawUtf16),
        ("RawBytes", RawBytes),
        ("HexLower", HexLower),
    ];
    encodings.iter().filter_map(|(name, enc)| {
        derive_with_pin_encoding(pin, salt, rounds, *enc)
            .ok()
            .map(|e| (name.to_string(), e))
    }).collect()
}

/// 将 ASCII 字符串转换为 UTF-16LE 字节序列
///
/// UTF-16LE: 每个 ASCII 字符编码为 2 字节（低字节 = ASCII 码，高字节 = 0x00）
fn to_utf16le_bytes(s: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(s.len() * 2);
    for ch in s.chars() {
        let code = ch as u16;
        buf.extend_from_slice(&code.to_le_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_utf16le_bytes() {
        let result = to_utf16le_bytes("AB");
        // 'A' = 0x41, 'B' = 0x42
        // UTF-16LE: [0x41, 0x00, 0x42, 0x00]
        assert_eq!(result, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn test_pin_hex_conversion() {
        // PIN "12" → hex "3132" → UTF-16LE
        let pin_hex: String = "12".as_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        assert_eq!(pin_hex, "3132");
        let utf16 = to_utf16le_bytes(&pin_hex);
        // '3'=0x33, '1'=0x31, '3'=0x33, '2'=0x32
        assert_eq!(utf16, vec![0x33, 0x00, 0x31, 0x00, 0x33, 0x00, 0x32, 0x00]);
    }

    #[test]
    fn test_derive_entropy_output_length() {
        let entropy = derive_entropy("123456", &[0u8; 32], 10000).unwrap();
        // 固定前缀(18 bytes) + SHA-512(64 bytes) = 82 bytes
        assert_eq!(entropy.len(), FIXED_ENTROPY_PREFIX.len() + 64);
        assert!(entropy.starts_with(FIXED_ENTROPY_PREFIX));
    }

    #[test]
    fn test_derive_entropy_deterministic() {
        let salt = [0xAAu8; 32];
        let e1 = derive_entropy("test", &salt, 1000).unwrap();
        let e2 = derive_entropy("test", &salt, 1000).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_different_pins_produce_different_entropy() {
        let salt = [0xBBu8; 32];
        let e1 = derive_entropy("111111", &salt, 10000).unwrap();
        let e2 = derive_entropy("222222", &salt, 10000).unwrap();
        assert_ne!(e1, e2);
    }
}
