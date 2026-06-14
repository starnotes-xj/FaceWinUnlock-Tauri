//! 公钥校验工具 — C 方案 §7 go/no-go 闸门
//!
//! 读取 key_capture 捕获的 BCRYPT_ECCPRIVATE_BLOB，
//! 从私钥 d 推导公钥 Q=d·G，输出多种编码供与 RP 存储公钥比对。
//!
//! 用法:
//!   key_verify.exe                                    # 扫描默认捕获目录
//!   key_verify.exe <dir>                              # 扫描指定目录
//!   key_verify.exe <file.bin>                         # 解析单个文件
//!   key_verify.exe --cose <file.bin>                  # 仅输出 COSE 公钥(base64url)
//!
//! 安全红线: 仅在终端输出公钥和校验信息，绝不输出私钥十六进制。

use std::fs;
use std::path::Path;
use p256::elliptic_curve::sec1::ToEncodedPoint;

const DEFAULT_CAPTURE_DIR: &str = r"C:\FaceWinUnlock\captured_keys";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.len() {
        1 => scan_dir(Path::new(DEFAULT_CAPTURE_DIR)),
        2 => {
            let arg = &args[1];
            if arg == "--help" || arg == "-h" {
                print_help();
                return;
            }
            let p = Path::new(arg);
            if p.is_dir() {
                scan_dir(p);
            } else if p.is_file() {
                let cose_only = false;
                verify_and_print(p, cose_only);
            } else {
                eprintln!("路径不存在: {arg}");
                std::process::exit(1);
            }
        }
        3 if args[1] == "--cose" => {
            let p = Path::new(&args[2]);
            if p.is_file() {
                verify_and_print(p, true);
            } else {
                eprintln!("文件不存在: {}", args[2]);
                std::process::exit(1);
            }
        }
        _ => {
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    eprintln!(
        "key_verify — FIDO2 ECDSA_P256 私钥 → 公钥 校验工具
用法:
  key_verify.exe                      扫描默认捕获目录 {}
  key_verify.exe <dir>                扫描指定目录
  key_verify.exe <file.bin>           解析单个私钥 blob
  key_verify.exe --cose <file.bin>    仅输出 COSE 公钥 (base64url, 供比对 RP)
",
        DEFAULT_CAPTURE_DIR
    );
}

// ─── 目录扫描 ────────────────────────────────────────────────────────────

fn scan_dir(dir: &Path) {
    println!("扫描目录: {}", dir.display());
    if !dir.is_dir() {
        eprintln!("目录不存在: {}", dir.display());
        eprintln!("请先执行 key_capture_injector 捕获密钥，然后重试。");
        std::process::exit(1);
    }

    let mut found = 0;
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                // 匹配捕获的输出文件
                if fname.starts_with("plaintext_")
                    && (fname.contains("BCryptImportKeyPair") || fname.contains("ECC"))
                    && fname.ends_with(".bin")
                {
                    found += 1;
                    println!("\n{}", "=".repeat(60));
                    verify_and_print(&path, false);
                }
            }
        }
        Err(e) => {
            eprintln!("读取目录失败: {e}");
            std::process::exit(1);
        }
    }

    if found == 0 {
        println!("\n未找到捕获的 ECDSA 私钥文件。");
        println!("预期文件名: plaintext_BCryptImportKeyPair_ECC_*.bin");
        println!("请确认已注入 DLL 并触发过一次 passkey 断言。");
    } else {
        println!("\n{}", "=".repeat(60));
        println!("扫描完成，共 {found} 个候选文件。");
        println!("请将上面输出的 COSE Public Key (base64url) 与 RP 存储的公钥比对。");
        println!("匹配 → C 方案成立 ✅ | 不匹配 → 假阳性，继续排查。");
    }
}

// ─── 单文件解析 + 校验 ──────────────────────────────────────────────────

fn verify_and_print(path: &Path, cose_only: bool) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("读取 {} 失败: {e}", path.display());
            return;
        }
    };

    if !cose_only {
        println!("文件: {}", path.display());
        println!("大小: {} bytes", data.len());
    }

    // 尝试多种格式
    match data.len() {
        104 => parse_ecc_private_blob(&data, path, cose_only),
        32 => parse_raw_scalar(&data, path, cose_only),
        n if n > 8 && data[0] == 0x30 => parse_pkcs8_der(&data, path, cose_only),
        _ => {
            if !cose_only {
                println!("  ⚠ 未知格式 ({} bytes)，尝试按 BCRYPT_ECCPRIVATE_BLOB 解析...", data.len());
            }
            if data.len() >= 104 {
                parse_ecc_private_blob(&data[..104], path, cose_only);
            } else {
                eprintln!("  文件太小，无法解析。");
            }
        }
    }
}

// ─── BCRYPT_ECCPRIVATE_BLOB (104 bytes) ─────────────────────────────────

fn parse_ecc_private_blob(data: &[u8], _path: &Path, cose_only: bool) {
    // 格式: dwMagic(4LE) + cbKey(4LE) + X(32) + Y(32) + d(32)
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let cb_key = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    if !cose_only {
        println!("Magic: 0x{:08X} ({})", magic, magic_str(magic));
        println!("cbKey: {}", cb_key);
    }

    if cb_key != 32 {
        if !cose_only {
            println!("  ⚠ cbKey={cb_key} (期望 32 for P256)，尝试继续...");
        }
        if data.len() < 4 + 4 + 32 + 32 + 32 {
            eprintln!("  数据不足 104 字节，中止。");
            return;
        }
    }

    let x = &data[8..40];
    let y = &data[40..72];
    let d = &data[72..104];

    // 从 d 重新推导公钥
    match derive_public_key(d) {
        Ok((derived_x, derived_y)) => {
            let x_match = derived_x.as_slice() == x;
            let y_match = derived_y.as_slice() == y;

            if !cose_only {
                println!();
                println!("┌─ 私钥 d (32B) — 仅显示前8字节，绝不输出完整私钥");
                println!("│  {:02X?}...", &d[..8]);
                println!("├─ Blob X  (32B): {:02X?}...", &x[..8]);
                println!("├─ Blob Y  (32B): {:02X?}...", &y[..8]);
                println!("├─ 推导 X' (32B): {:02X?}...", &derived_x[..8]);
                println!("├─ 推导 Y' (32B): {:02X?}...", &derived_y[..8]);
                println!("│");
                if x_match && y_match {
                    println!("│  ✅ 自洽校验通过: Blob(X,Y) == 推导(X',Y')");
                } else {
                    println!("│  ❌ 自洽校验失败: 推导公钥与 blob 不一致！");
                    println!("│     这可能不是有效的 ECDSA_P256 私钥。");
                    return;
                }
                println!("└──────────────────────────────────────────");
            }

            // 输出公钥
            let cose_b64 = cose_public_key(x, y);

            if cose_only {
                println!("{}", cose_b64);
            } else {
                println!();
                println!("╔══════════════════════════════════════════════════╗");
                println!("║  公钥 — 用于与 RP 存储的公钥比对               ║");
                println!("╠══════════════════════════════════════════════════╣");
                println!("║ X (hex): {}", hex::encode(x));
                println!("║ Y (hex): {}", hex::encode(y));
                println!("╠══════════════════════════════════════════════════╣");
                println!("║ Uncompressed (hex):");
                println!("║ 04{}{}", hex::encode(x), hex::encode(y));
                println!("╠══════════════════════════════════════════════════╣");
                println!("║ COSE Public Key (base64url):");
                println!("║ {}", cose_b64);
                println!("╠══════════════════════════════════════════════════╣");
                println!("║ X (base64url): {}", base64_url(x));
                println!("║ Y (base64url): {}", base64_url(y));
                println!("╚══════════════════════════════════════════════════╝");

                // 比对提示
                println!();
                println!("🔑 比对步骤:");
                println!("  1. 在 https://webauthn.io 注册一个 passkey");
                println!("  2. 打开浏览器 DevTools → Application → WebAuthn");
                println!("  3. 找到对应 credentialId 的 Public Key");
                println!("  4. 对比上面 COSE Public Key (base64url) 与 RP 存储的公钥");
                println!("  5. 一致 → ✅ C 方案私钥捕获成功！");
                println!("  6. 或复制上面 X/Y hex，手动与已知公钥比对");
            }
        }
        Err(e) => {
            if !cose_only {
                println!("  ❌ 从 d 推导公钥失败: {e}");
            } else {
                eprintln!("推导失败: {e}");
            }
        }
    }
}

// ─── Raw 32-byte scalar ──────────────────────────────────────────────────

fn parse_raw_scalar(data: &[u8], _path: &Path, cose_only: bool) {
    if !cose_only {
        println!("格式: Raw 32-byte private key scalar");
    }
    match derive_public_key(data) {
        Ok((x, y)) => {
            if !cose_only {
                println!("  ✅ 导出成功");
                println!("  X: {}", hex::encode(&x));
                println!("  Y: {}", hex::encode(&y));
                println!("  COSE Public Key: {}", cose_public_key(&x, &y));
            } else {
                println!("{}", cose_public_key(&x, &y));
            }
        }
        Err(e) => {
            if !cose_only {
                println!("  ❌ 推导失败: {e}");
            } else {
                eprintln!("推导失败: {e}");
            }
        }
    }
}

// ─── PKCS#8 DER ──────────────────────────────────────────────────────────

fn parse_pkcs8_der(data: &[u8], _path: &Path, cose_only: bool) {
    if !cose_only {
        println!("格式: PKCS#8 DER ({} bytes)", data.len());
    }
    use p256::SecretKey;
    match SecretKey::from_sec1_der(data) {
        Ok(sk) => {
            let pub_key = sk.public_key();
            let point = pub_key.to_encoded_point(false);
            let x = point.x().expect("no x");
            let y = point.y().expect("no y");
            if !cose_only {
                println!("  ✅ PKCS#8 解析成功");
                println!("  X: {}", hex::encode(x.as_slice()));
                println!("  Y: {}", hex::encode(y.as_slice()));
                println!("  COSE Public Key: {}", cose_public_key(x.as_slice(), y.as_slice()));
            } else {
                println!("{}", cose_public_key(x.as_slice(), y.as_slice()));
            }
        }
        Err(e) => {
            if !cose_only {
                println!("  ❌ PKCS#8 解析失败: {e}");
            } else {
                eprintln!("PKCS#8 解析失败: {e}");
            }
        }
    }
}

// ─── 公钥推导 (p256 crate) ──────────────────────────────────────────────

fn derive_public_key(d: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use p256::SecretKey;

    if d.len() != 32 {
        return Err(format!("私钥长度应为 32 字节，实际 {}", d.len()));
    }

    let sk = SecretKey::from_bytes(d.into()).map_err(|e| format!("无效的 P256 私钥: {e}"))?;
    let pub_key = sk.public_key();
    let point = pub_key.to_encoded_point(false);
    let x = point.x().ok_or("缺少 X 坐标")?;
    let y = point.y().ok_or("缺少 Y 坐标")?;
    Ok((x.as_slice().to_vec(), y.as_slice().to_vec()))
}

// ─── COSE 公钥编码 ───────────────────────────────────────────────────────

/// 构造 WebAuthn COSE_Key (EC2 P-256 ES256) 的 base64url 编码
///
/// COSE_Key 映射:
///   1 (kty): 2 (EC2)
///   3 (alg): -7 (ES256)
///  -1 (crv): 1 (P-256)
///  -2 (x):   32-byte X coordinate
///  -3 (y):   32-byte Y coordinate
///
/// CBOR 编码 (确定性，最小长度):
///   A5                       # map(5)
///     01 02                  # 1:2 (kty: EC2)
///     03 26                  # 3:-7 (alg: ES256)  → 0x26 = -7 in CBOR negative int
///     20 01                  # -1:1 (crv: P-256)  → 0x20 = -1
///     21 58 20 <x>           # -2: bytes(32) X    → 0x21 = -2, 0x58=bytes, 0x20=32
///     22 58 20 <y>           # -3: bytes(32) Y    → 0x22 = -3
fn cose_public_key(x: &[u8], y: &[u8]) -> String {
    let mut cbor = Vec::with_capacity(2 + 2 + 2 + 2 + 2 + 32 + 2 + 2 + 32);

    // A5 = map(5)
    cbor.push(0xA5);

    // 1:2 (kty: EC2)
    cbor.push(0x01);
    cbor.push(0x02);

    // 3:-7 (alg: ES256). CBOR negative int: 0x20 + (|value| - 1) → 0x20 + 6 = 0x26
    cbor.push(0x03);
    cbor.push(0x26);

    // -1:1 (crv: P-256). CBOR negative int: -1 → 0x20
    cbor.push(0x20);
    cbor.push(0x01);

    // -2: bytes(32) X. CBOR negative int: -2 → 0x21. bytes(32) → 0x58 0x20
    cbor.push(0x21);
    cbor.push(0x58);
    cbor.push(0x20);
    cbor.extend_from_slice(x);

    // -3: bytes(32) Y. CBOR negative int: -3 → 0x22
    cbor.push(0x22);
    cbor.push(0x58);
    cbor.push(0x20);
    cbor.extend_from_slice(y);

    base64_url(&cbor)
}

// ─── 辅助 ──────────────────────────────────────────────────────────────────

fn magic_str(magic: u32) -> &'static str {
    match magic {
        0x32434345 => "ECDSA_P256 (ECC2)",
        0x31434345 => "ECDSA_P384 (ECC1)",
        0x30434345 => "ECDSA_P521 (ECC0)",
        0x32534345 => "ECDSA_P256 (ECS2) — 备选 magic",
        _ => "未知",
    }
}

fn base64_url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
