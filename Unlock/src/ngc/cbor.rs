//! 轻量级 CBOR 解码器（RFC 7049）— 仅用于诊断现代 NgcIso 加密Cbor 内部结构
//!
//! 不依赖外部 cbor crate，零开销实现核心 RFC 7049 解码能力：
//! - Major types: 0/1 (int), 2 (bytes), 3 (text), 4 (array), 5 (map), 6 (tag), 7 (simple)
//! - Indefinite length (arg=31) 不支持（现代 NgcIso 都用定长）
//!
//! 仅做诊断打印，不会用其驱动实际解密逻辑。

use std::fmt;

/// CBOR 解码错误
#[derive(Debug, Clone)]
pub enum CborError {
    /// 数据提前结束
    Truncated,
    /// 字节不符合 CBOR 编码
    InvalidEncoding,
    /// 类型不匹配
    TypeMismatch,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => write!(f, "CBOR: 数据提前结束"),
            CborError::InvalidEncoding => write!(f, "CBOR: 编码非法"),
            CborError::TypeMismatch => write!(f, "CBOR: 类型不匹配"),
        }
    }
}

/// CBOR 解码后的值
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Unsigned(u64),
    Negative(i128), // 0..=-(2^64-1) 用 i128 表达
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Tag(u64, Box<CborValue>),
    Bool(bool),
    Null,
    Undefined,
    // 浮点和 simple other 不解析（无意义）
    Unknown(u8, u64),
}

/// 解析 CBOR 头部（initial byte + additional info）
fn decode_initial_byte(byte: u8) -> Result<(u8, u8), CborError> {
    Ok((byte >> 5, byte & 0x1F))
}

/// 读 CBOR 额外参数（基于 arg 值）
fn decode_arg<'a>(data: &'a [u8], pos: &mut usize, arg: u8) -> Result<u64, CborError> {
    match arg {
        0..=23 => Ok(arg as u64),
        24 => {
            if *pos >= data.len() { return Err(CborError::Truncated); }
            let v = data[*pos] as u64;
            *pos += 1;
            Ok(v)
        }
        25 => {
            if *pos + 2 > data.len() { return Err(CborError::Truncated); }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        26 => {
            if *pos + 4 > data.len() { return Err(CborError::Truncated); }
            let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as u64;
            *pos += 4;
            Ok(v)
        }
        27 => {
            if *pos + 8 > data.len() { return Err(CborError::Truncated); }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[*pos..*pos + 8]);
            let v = u64::from_be_bytes(bytes);
            *pos += 8;
            Ok(v)
        }
        _ => Err(CborError::InvalidEncoding),
    }
}

/// 解码一个 CBOR 值
pub fn decode_cbor(data: &[u8]) -> Result<(CborValue, usize), CborError> {
    let mut pos = 0;
    let v = decode_value(data, &mut pos)?;
    Ok((v, pos))
}

fn decode_value(data: &[u8], pos: &mut usize) -> Result<CborValue, CborError> {
    if *pos >= data.len() { return Err(CborError::Truncated); }
    let (major, arg) = decode_initial_byte(data[*pos])?;
    *pos += 1;

    if arg == 31 {
        // Indefinite length — 不支持
        return Err(CborError::InvalidEncoding);
    }

    match major {
        0 => {
            let v = decode_arg(data, pos, arg)?;
            Ok(CborValue::Unsigned(v))
        }
        1 => {
            let v = decode_arg(data, pos, arg)?;
            Ok(CborValue::Negative(-(v as i128) - 1))
        }
        2 => {
            let len = decode_arg(data, pos, arg)? as usize;
            if *pos + len > data.len() { return Err(CborError::Truncated); }
            let bytes = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(CborValue::Bytes(bytes))
        }
        3 => {
            let len = decode_arg(data, pos, arg)? as usize;
            if *pos + len > data.len() { return Err(CborError::Truncated); }
            let s = std::str::from_utf8(&data[*pos..*pos + len])
                .map_err(|_| CborError::InvalidEncoding)?
                .to_string();
            *pos += len;
            Ok(CborValue::Text(s))
        }
        4 => {
            let len = decode_arg(data, pos, arg)? as usize;
            let mut arr = Vec::with_capacity(len.min(256));
            for _ in 0..len {
                arr.push(decode_value(data, pos)?);
            }
            Ok(CborValue::Array(arr))
        }
        5 => {
            let len = decode_arg(data, pos, arg)? as usize;
            let mut map = Vec::with_capacity(len.min(256));
            for _ in 0..len {
                let k = decode_value(data, pos)?;
                let v = decode_value(data, pos)?;
                map.push((k, v));
            }
            Ok(CborValue::Map(map))
        }
        6 => {
            // Tag
            let tag = decode_arg(data, pos, arg)?;
            let inner = decode_value(data, pos)?;
            Ok(CborValue::Tag(tag, Box::new(inner)))
        }
        7 => {
            // Simple values and floats
            match arg {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                23 => Ok(CborValue::Undefined),
                0..=19 => Ok(CborValue::Unknown(arg, 0)),
                24 => {
                    if *pos >= data.len() { return Err(CborError::Truncated); }
                    let sv = data[*pos];
                    *pos += 1;
                    Ok(CborValue::Unknown(7, sv as u64))
                }
                25 => {
                    if *pos + 2 > data.len() { return Err(CborError::Truncated); }
                    *pos += 2;
                    Ok(CborValue::Unknown(arg, 0))
                }
                26 => {
                    if *pos + 4 > data.len() { return Err(CborError::Truncated); }
                    *pos += 4;
                    Ok(CborValue::Unknown(arg, 0))
                }
                27 => {
                    if *pos + 8 > data.len() { return Err(CborError::Truncated); }
                    *pos += 8;
                    Ok(CborValue::Unknown(arg, 0))
                }
                28..=30 => Ok(CborValue::Unknown(arg, 0)),
                31 => Err(CborError::InvalidEncoding), // Indefinite length, rejected above
                _ => Ok(CborValue::Unknown(arg, 0)),  // catch-all for completeness
            }
        }
        _ => unreachable!(),
    }
}

/// 打印 CBOR 值为可读文本
pub fn print_cbor(value: &CborValue, indent: usize) -> String {
    let pad = " ".repeat(indent);
    match value {
        CborValue::Unsigned(n) => format!("{n}"),
        CborValue::Negative(n) => format!("{n}"),
        CborValue::Bytes(b) => {
            if b.len() <= 64 {
                format!("h'{}'", hex_encode(&b[..b.len().min(64)]))
            } else {
                format!("b'({}B) {}{}'", b.len(), hex_encode(&b[..32]), "..")
            }
        }
        CborValue::Text(s) => {
            if s.len() <= 80 && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                format!("\"{s}\"")
            } else {
                let t: String = s.chars().take(80).collect();
                format!("\"{t}...\"({}B)", s.len())
            }
        }
        CborValue::Array(arr) => {
            if arr.is_empty() { return "[]".to_string(); }
            let mut s = String::from("[\n");
            for (i, v) in arr.iter().enumerate() {
                s.push_str(&format!("{pad}  [{}] {}\n", i, print_cbor(v, indent + 2)));
            }
            s.push_str(&format!("{pad}]"));
            s
        }
        CborValue::Map(entries) => {
            if entries.is_empty() { return "{}".to_string(); }
            let mut s = String::from("{\n");
            for (k, v) in entries {
                s.push_str(&format!("{pad}  {}: {}\n", print_cbor(k, 0), print_cbor(v, indent + 2)));
            }
            s.push_str(&format!("{pad}}}"));
            s
        }
        CborValue::Tag(tag, inner) => {
            format!("tag({tag})({})", print_cbor(inner, indent))
        }
        CborValue::Bool(b) => format!("bool({b})"),
        CborValue::Null => "null".to_string(),
        CborValue::Undefined => "undefined".to_string(),
        CborValue::Unknown(t, v) => format!("simple(type={t}, val={v})"),
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join("")
}

/// 深度 dump 函数：尝试解析数据为 CBOR 并打印（即使解析失败也打印 raw）
pub fn deep_dump_cbor(name: &str, data: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n=== CBOR Deep Dump: {name} ({}B) ===\n", data.len()));
    out.push_str(&format!("[head64] {}\n", hex_encode(&data[..data.len().min(64)])));
    if data.is_empty() { return out; }

    let first = data[0];
    let major = first >> 5;
    let arg = first & 0x1F;
    out.push_str(&format!("[CBOR first byte] 0x{first:02X} major={major} arg={arg}\n"));

    match decode_cbor(data) {
        Ok((v, consumed)) => {
            out.push_str(&format!("[CBOR decoded] consumed={}/{} bytes:\n", consumed, data.len()));
            out.push_str(&print_cbor(&v, 0));
            out.push_str("\n");
            if consumed < data.len() {
                out.push_str(&format!("\n[trailing {}B] {}\n",
                    data.len() - consumed,
                    hex_encode(&data[consumed..data.len().min(consumed + 64)])));
            }
        }
        Err(e) => {
            out.push_str(&format!("[CBOR decode error] {e}\n"));
            // 尝试作为 TLV 暴力解析
            out.push_str("[TLV 暴力扫描]\n");
            for &skip in &[0u32, 4, 8, 12, 16, 20, 24, 28, 32, 0x1C, 0x3C, 0x4C] {
                if (skip as usize) + 4 > data.len() { continue; }
                let len = u32::from_le_bytes([data[skip as usize], data[skip as usize + 1],
                                              data[skip as usize + 2], data[skip as usize + 3]]);
                if (64..=2048).contains(&len) {
                    out.push_str(&format!("  skip={skip}: TLV u32_le={len} ({:#X}) 候选 EncData 长度\n", len));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_unsigned() {
        // 0x05 = unsigned 5
        let (v, _) = decode_cbor(&[0x05]).unwrap();
        assert_eq!(v, CborValue::Unsigned(5));
    }

    #[test]
    fn test_decode_text() {
        // 0x63 "abc" = text of length 3
        let (v, _) = decode_cbor(&[0x63, b'a', b'b', b'c']).unwrap();
        assert_eq!(v, CborValue::Text("abc".to_string()));
    }

    #[test]
    fn test_decode_array() {
        // 0x82 0x01 0x02 = array of 2 elements [1, 2]
        let (v, _) = decode_cbor(&[0x82, 0x01, 0x02]).unwrap();
        assert_eq!(v, CborValue::Array(vec![CborValue::Unsigned(1), CborValue::Unsigned(2)]));
    }

    #[test]
    fn test_decode_map() {
        // 0xa2 0x01 0x02 0x03 0x04 = map {1: 2, 3: 4}
        let (v, _) = decode_cbor(&[0xa2, 0x01, 0x02, 0x03, 0x04]).unwrap();
        match v {
            CborValue::Map(entries) => {
                assert_eq!(entries.len(), 2);
            }
            _ => panic!("not a map"),
        }
    }
}
