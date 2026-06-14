//! 内存转储扫描器 — 搜索 NgcIso 内存 dump 中的 ECDSA_P256 私钥
//!
//! 从原始二进制内存转储（.writemem 或 .dump）中搜索
//! BCRYPT_ECCPRIVATE_BLOB magic 0x32434345 ("ECC2")，
//! 验证 cbKey=32，提取 X/Y/d，推导公钥并校验自洽性。
//!
//! 用法:
//!   key_scanner.exe <dump_file>
//!   key_scanner.exe --dir <dir>              # 批量扫描目录
//!
//! 输出: COSE public key (base64url) + 自洽校验结果

use std::fs;
use std::path::Path;
use p256::elliptic_curve::sec1::ToEncodedPoint;

const MAGIC_ECC2: u32 = 0x32434345; // bytes: 45 43 43 32 (LE)
const BLOB_SIZE: usize = 104;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("用法: key_scanner.exe <dump_file>");
        eprintln!("      key_scanner.exe --dir <directory>");
        eprintln!("");
        eprintln!("扫描二进制内存转储，搜索 BCRYPT_ECCPRIVATE_BLOB (104 bytes, magic=0x32434345)");
        eprintln!("找到后推导公钥，输出 COSE Public Key (base64url) 供与 RP 比对。");
        std::process::exit(1);
    }

    if args[1] == "--dir" && args.len() >= 3 {
        scan_dir(Path::new(&args[2]));
    } else {
        scan_file(Path::new(&args[1]));
    }
}

fn scan_dir(dir: &Path) {
    println!("扫描目录: {}", dir.display());
    let mut found = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let count = scan_file(&path);
                found += count;
            }
        }
    }
    println!("\n总计找到 {found} 个候选密钥");
    if found == 0 {
        println!("未找到 ECDSA_P256 私钥。可能是:");
        println!("  1. dump 时 passkey 签名尚未发生或已完成");
        println!("  2. 密钥在 CNG 内核态，不在用户态转储中");
        println!("  3. 密钥格式不同于 BCRYPT_ECCPRIVATE_BLOB");
    }
}

fn scan_file(path: &Path) -> usize {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("读取 {} 失败: {}", path.display(), e);
            return 0;
        }
    };

    if data.len() < BLOB_SIZE {
        return 0;
    }

    let magic_bytes = MAGIC_ECC2.to_le_bytes(); // [0x45, 0x43, 0x43, 0x32]
    let mut found = 0;

    // 4 字节对齐搜索 magic
    let mut i = 0;
    while i <= data.len() - BLOB_SIZE {
        if data[i] == magic_bytes[0]
            && data[i+1] == magic_bytes[1]
            && data[i+2] == magic_bytes[2]
            && data[i+3] == magic_bytes[3]
        {
            let cb_key = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]);
            // P256 key size = 32 bytes
            if cb_key == 32 && i + BLOB_SIZE <= data.len() {
                let candidate = &data[i..i + BLOB_SIZE];
                let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("dump");
                let out_name = format!("C:\\FaceWinUnlock\\captured_keys\\scan_{}_offset_{:08X}.bin",
                    file_stem, i);
                let _ = fs::create_dir_all("C:\\FaceWinUnlock\\captured_keys");
                let _ = fs::write(&out_name, candidate);

                print!("\n📍 偏移 0x{i:08X} — cbKey={cb_key}");
                match verify_and_output(candidate, i) {
                    Ok(_) => {
                        found += 1;
                        println!("  ✅ 有效 → {}", out_name);
                    }
                    Err(e) => {
                        println!("  ❌ {}", e);
                        // 删除无效文件
                        let _ = fs::remove_file(&out_name);
                    }
                }
            }
        }
        i += 4; // 对齐步进
    }

    found
}

fn verify_and_output(blob: &[u8], _offset: usize) -> Result<(), String> {
    if blob.len() < 104 {
        return Err("blob 不足 104 字节".into());
    }

    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);

    if magic != MAGIC_ECC2 {
        return Err(format!("magic 不匹配: 0x{magic:08X}"));
    }
    if cb_key != 32 {
        return Err(format!("cbKey != 32: {cb_key}"));
    }

    let x = &blob[8..40];
    let y = &blob[40..72];
    let d = &blob[72..104];

    // 从 d 推导公钥
    use p256::SecretKey;
    let sk = SecretKey::from_bytes(d.into())
        .map_err(|e| format!("无效 P256 私钥: {e}"))?;
    let pk = sk.public_key();
    let point = pk.to_encoded_point(false);
    let dx = point.x().ok_or("缺少 X")?;
    let dy = point.y().ok_or("缺少 Y")?;

    let x_match = dx.as_slice() == x;
    let y_match = dy.as_slice() == y;

    if !x_match || !y_match {
        return Err(format!("自洽校验失败: blob(X,Y) != 推导(X',Y')"));
    }

    // COSE Public Key
    let cose = cose_public_key(x, y);

    println!();
    println!("    X: {}...", hex::encode(&x[..8]));
    println!("    Y: {}...", hex::encode(&y[..8]));
    println!("    COSE Public Key (base64url):");
    println!("    {}", cose);

    Ok(())
}

fn cose_public_key(x: &[u8], y: &[u8]) -> String {
    let mut cbor = Vec::with_capacity(80);
    cbor.push(0xA5); // map(5)
    cbor.push(0x01); cbor.push(0x02);   // 1:2 (kty: EC2)
    cbor.push(0x03); cbor.push(0x26);   // 3:-7 (alg: ES256)
    cbor.push(0x20); cbor.push(0x01);   // -1:1 (crv: P-256)
    cbor.push(0x21); cbor.push(0x58); cbor.push(0x20);
    cbor.extend_from_slice(x);           // -2: X
    cbor.push(0x22); cbor.push(0x58); cbor.push(0x20);
    cbor.extend_from_slice(y);           // -3: Y
    base64_url(&cbor)
}

fn base64_url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
